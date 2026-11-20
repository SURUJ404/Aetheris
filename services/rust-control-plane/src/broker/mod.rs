//! The execution broker: the only path from a validated request to a sandbox.
//!
//! Order of operations, and why:
//! 1. **Authorize** with the same [`PolicyEngine`] the HTTP API uses. A denial
//!    happens before any row exists, so an unauthorized caller cannot create
//!    durable state or consume a sandbox slot.
//! 2. **Validate** runtime, workload and limits. Identity, tenant and runtime
//!    selection are never taken from guest input.
//! 3. **Persist** the execution (`CREATED`) with idempotency.
//! 4. **Advance** through `QUEUED -> AUTHORIZED -> STARTING -> RUNNING` using
//!    compare-and-set transitions.
//! 5. **Dispatch** to the runtime selected by configuration. The broker holds
//!    only the [`SandboxRuntime`] trait, never a concrete runtime.
//! 6. **Clean up** by moving through `CLEANING_UP` to exactly one terminal
//!    state, carrying output digest, artifacts and resource usage.
//!
//! The broker never trusts a runtime result for identity or permissions: a
//! result can only describe what happened, never what is allowed next.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use uuid::Uuid;

use crate::config::ExecutionConfig;
use crate::execution::{
    ArtifactRef, ExecutionLimits, ExecutionRecord, ExecutionStatus, ExecutionStore,
    ExecutionStoreError, LimitCeilings, LimitError, NewExecution, RuntimeKind, TransitionPatch,
};
use crate::policy::{Action, PolicyDecision, PolicyEngine, POLICY_VERSION};
use crate::principal::TenantContext;
use crate::runtime::{
    digest, RuntimeRegistry, SandboxError, SandboxLimits, SandboxResult, SandboxSpec, Termination,
    WorkloadRegistry,
};

/// A validated proposal to run one approved workload.
///
/// Deliberately has no tenant, principal, policy version or environment field:
/// those are decided by the broker from the authenticated context and its own
/// configuration. A caller cannot restate them.
#[derive(Debug, Clone)]
pub struct ExecutionRequest {
    /// Tenant-scoped task label the execution belongs to.
    pub task_id: String,
    /// Runtime the caller wants, subject to the deployment allowlist.
    pub runtime: RuntimeKind,
    /// Approved workload name.
    pub workload: String,
    /// Standard input bytes, bounded by `limits.max_stdin_bytes`.
    pub stdin: Vec<u8>,
    /// Requested limits, lowered against deployment ceilings.
    pub limits: ExecutionLimits,
    /// Optional client key making retries idempotent within a tenant.
    pub idempotency_key: Option<String>,
}

/// Broker failures. Every variant maps to a stable HTTP status in the API layer.
///
/// Runtime-internal reasons are logged, never returned: an error body must not
/// become an oracle for host paths or image contents.
#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("not authorized to invoke a tool")]
    Forbidden { reason: String },

    #[error("runtime `{0}` is not enabled on this deployment")]
    RuntimeDisabled(RuntimeKind),

    #[error("workload `{0}` is not approved")]
    UnknownWorkload(String),

    #[error("invalid execution limits: {0}")]
    InvalidLimits(#[from] LimitError),

    #[error("invalid execution request: {0}")]
    InvalidRequest(String),

    #[error("too many concurrent executions for this tenant")]
    Busy,

    #[error("execution not found")]
    NotFound,

    #[error("execution `{0}` is not cancellable in state `{1}`")]
    NotCancellable(Uuid, ExecutionStatus),

    #[error("execution state changed underneath this request")]
    Conflict,

    #[error("sandbox runtime `{0}` is unavailable")]
    RuntimeUnavailable(RuntimeKind),

    #[error("execution failed internally")]
    Internal,
}

impl From<ExecutionStoreError> for BrokerError {
    fn from(err: ExecutionStoreError) -> Self {
        match err {
            ExecutionStoreError::StateConflict { .. }
            | ExecutionStoreError::InvalidTransition { .. } => BrokerError::Conflict,
            ExecutionStoreError::Unavailable(source) => {
                tracing::error!(error = %source, "execution store unavailable");
                BrokerError::Internal
            }
            ExecutionStoreError::Corrupt => {
                tracing::error!("stored execution state is corrupt");
                BrokerError::Internal
            }
        }
    }
}

/// Output of preflight validation: only artifacts needed to dispatch.
struct ValidatedExecution {
    runtime: Arc<dyn crate::runtime::SandboxRuntime>,
    module: Arc<Vec<u8>>,
}

/// Coordinates authorization, persistence and sandbox runtimes.
pub struct Broker {
    store: Arc<dyn ExecutionStore>,
    runtimes: RuntimeRegistry,
    workloads: WorkloadRegistry,
    config: ExecutionConfig,
    /// In-flight cancellation handles, keyed by execution id.
    tokens: Mutex<BTreeMap<Uuid, CancellationToken>>,
    /// Per-tenant concurrency lanes.
    lanes: tokio::sync::Mutex<BTreeMap<String, Arc<Semaphore>>>,
}

impl Broker {
    /// Build a broker from durable state, enabled runtimes and approved
    /// workloads. No runtime is constructed here: the registry already holds
    /// exactly what configuration enabled.
    pub fn new(
        store: Arc<dyn ExecutionStore>,
        runtimes: RuntimeRegistry,
        workloads: WorkloadRegistry,
        config: ExecutionConfig,
    ) -> Self {
        Self {
            store,
            runtimes,
            workloads,
            config,
            tokens: Mutex::new(BTreeMap::new()),
            lanes: tokio::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Approved workload names, for operator diagnostics.
    pub fn workloads(&self) -> Vec<&str> {
        self.workloads.names()
    }

    /// Enabled runtime kinds.
    pub fn runtimes(&self) -> Vec<RuntimeKind> {
        self.runtimes.kinds()
    }

    /// Lambda for readiness: the broker is only useful if its store is.
    pub async fn ping(&self) -> Result<(), BrokerError> {
        // A read of a non-existent row exercises the connection without
        // pretending this is a health check of the sandbox host.
        self.store
            .get("__readiness__", Uuid::nil())
            .await
            .map(|_| ())
            .map_err(BrokerError::from)
    }

    /// Fail every row left in flight by a previous process.
    ///
    /// Must be called once at startup, before accepting requests. Nothing is
    /// running for those rows: their sandbox and cancellation token died with
    /// the old process.
    pub async fn recover(&self) -> Result<Vec<Uuid>, BrokerError> {
        let recovered = self.store.recover_interrupted().await?;
        if !recovered.is_empty() {
            tracing::warn!(
                recovered = recovered.len(),
                "failed executions left in flight by a previous process"
            );
        }
        Ok(recovered)
    }

    /// Read one execution, scoped to the caller's tenant.
    pub async fn get(
        &self,
        context: &TenantContext,
        id: Uuid,
    ) -> Result<ExecutionRecord, BrokerError> {
        let tenant = &context.identity.tenant_id;
        let record = self
            .store
            .get(tenant, id)
            .await?
            .filter(|record| record.belongs_to(tenant))
            .ok_or(BrokerError::NotFound)?;
        Ok(record)
    }

    /// Cancel an in-flight execution.
    ///
    /// The durable cancellation timestamp is written first, then the in-memory
    /// token is fired. A cancel that arrives after the guest finished is a
    /// no-op and returns the terminal record, because cancellation is a
    /// request, not a guarantee about the outcome.
    pub async fn cancel(
        &self,
        context: &TenantContext,
        id: Uuid,
    ) -> Result<ExecutionRecord, BrokerError> {
        self.authorize(context)?;
        let tenant = &context.identity.tenant_id;

        let status = self
            .store
            .request_cancel(tenant, id)
            .await?
            .ok_or(BrokerError::NotFound)?;

        if status.is_cancellable() {
            if let Some(token) = self.tokens.lock().expect("token registry").get(&id) {
                token.cancel();
            }
            tracing::info!(
                tenant_id = %tenant,
                execution_id = %id,
                status = %status,
                "execution cancellation requested"
            );
        }

        self.get(context, id).await
    }

    /// Authorize and dispatch one execution.
    pub async fn submit(
        &self,
        context: &TenantContext,
        request: ExecutionRequest,
    ) -> Result<ExecutionRecord, BrokerError> {
        let span = tracing::info_span!(
            "execution.submit",
            tenant_id = %context.identity.tenant_id,
            principal_id = %context.resolved.principal_id,
            task_id = %request.task_id,
            runtime = %request.runtime,
            workload = %request.workload,
            execution_id = tracing::field::Empty,
        );

        self.submit_inner(context, request).instrument(span).await
    }

    async fn submit_inner(
        &self,
        context: &TenantContext,
        request: ExecutionRequest,
    ) -> Result<ExecutionRecord, BrokerError> {
        // 1. Authorize and validate before any durable state is created. The
        //    same checks are exposed to the approval-bound path as a preflight.
        let validated = self.validated_request(context, &request)?;

        let tenant_id = context.identity.tenant_id.clone();
        let principal_id = context.resolved.principal_id;

        // 5. Persist CREATED, idempotently. The cancellation token is installed
        //    before the row exists, so a cancel can never race registration.
        let id = Uuid::new_v4();
        let token = CancellationToken::new();
        self.tokens
            .lock()
            .expect("token registry")
            .insert(id, token.clone());

        let new = NewExecution {
            id,
            tenant_id: tenant_id.clone(),
            principal_id,
            task_id: request.task_id.clone(),
            runtime: request.runtime,
            workload: request.workload.clone(),
            limits: request.limits,
            policy_version: POLICY_VERSION.to_owned(),
            idempotency_key: request.idempotency_key.clone(),
        };

        let (record, created) = match self.store.insert(new).await {
            Ok(result) => result,
            Err(err) => {
                self.tokens.lock().expect("token registry").remove(&id);
                return Err(err.into());
            }
        };

        if !created {
            // A duplicate is a successful retry: return the original row and do
            // not touch its cancellation token.
            self.tokens.lock().expect("token registry").remove(&id);
            tracing::info!(
                execution_id = %record.id,
                status = %record.status,
                "duplicate execution request returned the existing record"
            );
            return Ok(record);
        }

        let span = tracing::Span::current();
        span.record("execution_id", tracing::field::display(id));

        // 6. Acquire a tenant lane. A rejected execution is still a durable row:
        //    it happened, and it must be auditable.
        let permit = match self.acquire_lane(&tenant_id).await {
            Ok(permit) => permit,
            Err(error) => {
                self.fail_before_start(&tenant_id, id, "rejected", "tenant concurrency limit")
                    .await;
                self.tokens.lock().expect("token registry").remove(&id);
                return Err(error);
            }
        };

        let outcome = self
            .run_authorized(
                &tenant_id,
                id,
                validated.runtime,
                validated.module,
                &request,
                token,
            )
            .await;

        drop(permit);
        self.tokens.lock().expect("token registry").remove(&id);

        outcome
    }

    /// The authorized path: transitions, dispatch, terminal state.
    async fn run_authorized(
        &self,
        tenant_id: &str,
        id: Uuid,
        runtime: Arc<dyn crate::runtime::SandboxRuntime>,
        module: Arc<Vec<u8>>,
        request: &ExecutionRequest,
        token: CancellationToken,
    ) -> Result<ExecutionRecord, BrokerError> {
        let now = chrono::Utc::now();

        self.advance(
            tenant_id,
            id,
            ExecutionStatus::Created,
            ExecutionStatus::Queued,
            TransitionPatch::default(),
        )
        .await?;
        self.advance(
            tenant_id,
            id,
            ExecutionStatus::Queued,
            ExecutionStatus::Authorized,
            TransitionPatch::default(),
        )
        .await?;
        self.advance(
            tenant_id,
            id,
            ExecutionStatus::Authorized,
            ExecutionStatus::Starting,
            TransitionPatch {
                started_at: Some(now),
                ..Default::default()
            },
        )
        .await?;
        self.advance(
            tenant_id,
            id,
            ExecutionStatus::Starting,
            ExecutionStatus::Running,
            TransitionPatch::default(),
        )
        .await?;

        // A cancel that arrived while the row was starting wins immediately.
        if token.is_cancelled() {
            return self
                .finish(
                    tenant_id,
                    id,
                    ExecutionStatus::Cancelled,
                    TransitionPatch {
                        finished_at: Some(chrono::Utc::now()),
                        failure_kind: Some("cancelled".into()),
                        failure_message: Some("cancellation requested before dispatch".into()),
                        duration_ms: Some(0),
                        ..Default::default()
                    },
                )
                .await;
        }

        let spec = SandboxSpec {
            execution_id: id,
            workload: request.workload.clone(),
            module,
            stdin: request.stdin.clone(),
            env: self.sandbox_env(id, &request.task_id),
            limits: SandboxLimits::from(&request.limits),
            scratch_root: Some(self.config.scratch_root.clone()),
        };

        let started = std::time::Instant::now();
        let result = runtime.execute(spec, token.clone()).await;

        match result {
            Ok(result) => {
                let status = terminal_status(&result);
                let patch = terminal_patch(&result, started);
                let record = self.finish(tenant_id, id, status, patch).await?;
                tracing::info!(
                    tenant_id = %tenant_id,
                    execution_id = %id,
                    status = %record.status,
                    duration_ms = record.duration_ms.unwrap_or_default(),
                    "execution finished"
                );
                Ok(record)
            }
            Err(error) => {
                let (kind, message) = match &error {
                    SandboxError::Unavailable { reason, .. } => {
                        tracing::error!(error = %reason, "sandbox runtime unavailable");
                        ("runtime_unavailable", "sandbox runtime is unavailable")
                    }
                    SandboxError::InvalidWorkload { reason } => {
                        tracing::error!(error = %reason, "approved workload is unusable");
                        ("invalid_workload", "approved workload is unusable")
                    }
                    SandboxError::Internal { reason } => {
                        tracing::error!(error = %reason, "sandbox runtime failure");
                        ("internal", "sandbox runtime failure")
                    }
                };

                let record = self
                    .finish(
                        tenant_id,
                        id,
                        ExecutionStatus::Failed,
                        TransitionPatch {
                            finished_at: Some(chrono::Utc::now()),
                            failure_kind: Some(kind.into()),
                            failure_message: Some(message.into()),
                            duration_ms: Some(started.elapsed().as_millis() as i64),
                            ..Default::default()
                        },
                    )
                    .await?;

                if matches!(error, SandboxError::Unavailable { .. }) {
                    return Err(BrokerError::RuntimeUnavailable(request.runtime));
                }
                let _ = record;
                Err(BrokerError::Internal)
            }
        }
    }

    /// Environment handed to the sandbox.
    ///
    /// Fixed, non-secret, derived only from control-plane state. A caller has
    /// no way to add a variable, and no variable in this list is sensitive.
    fn sandbox_env(&self, id: Uuid, task_id: &str) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("AGENTIC_EXECUTION_ID".into(), id.to_string());
        env.insert("AGENTIC_TASK_ID".into(), task_id.to_owned());
        env
    }

    /// Preflight an execution proposal without persisting or dispatching it.
    ///
    /// Callers that must perform an atomic side effect between validation and
    /// dispatch (for example consuming an approval) use this to prove the
    /// broker would accept the request, then pass the same request to
    /// [`Broker::submit`]. Validation is repeated there because state may have
    /// changed in between.
    pub fn validate_request(
        &self,
        context: &TenantContext,
        request: &ExecutionRequest,
    ) -> Result<(), BrokerError> {
        self.validated_request(context, request).map(|_| ())
    }

    fn validated_request(
        &self,
        context: &TenantContext,
        request: &ExecutionRequest,
    ) -> Result<ValidatedExecution, BrokerError> {
        // Authorization. The tenant comes from validated membership, not from
        // the request.
        self.authorize(context)?;

        // Runtime against the deployment allowlist.
        let runtime = self.runtimes.get(request.runtime).ok_or_else(|| {
            tracing::warn!(runtime = %request.runtime, "requested runtime is not enabled");
            BrokerError::RuntimeDisabled(request.runtime)
        })?;

        // Workload against the approved registry. Arbitrary module bytes are
        // never accepted.
        let workload = self
            .workloads
            .get(&request.workload)
            .ok_or_else(|| BrokerError::UnknownWorkload(request.workload.clone()))?;

        // Limits are rejected, never clamped.
        request
            .limits
            .enforce(&LimitCeilings::from_config(&self.config))?;

        if request.stdin.len() as u64 > request.limits.max_stdin_bytes {
            return Err(BrokerError::InvalidRequest(
                "stdin exceeds the declared max_stdin_bytes".into(),
            ));
        }

        if !valid_task_id(&request.task_id) {
            return Err(BrokerError::InvalidRequest("task_id is not valid".into()));
        }

        if let Some(key) = &request.idempotency_key {
            if key.is_empty() || key.len() > 128 {
                return Err(BrokerError::InvalidRequest(
                    "idempotency_key must be 1..=128 bytes".into(),
                ));
            }
        }

        Ok(ValidatedExecution {
            runtime,
            module: workload.module.clone(),
        })
    }

    fn authorize(&self, context: &TenantContext) -> Result<(), BrokerError> {
        match PolicyEngine::new().evaluate(context, Action::ToolInvoke) {
            PolicyDecision::Allow { .. } => Ok(()),
            PolicyDecision::Deny { reason, .. } => {
                tracing::warn!(
                    tenant_id = %context.identity.tenant_id,
                    principal_id = %context.resolved.principal_id,
                    reason = ?reason,
                    "execution denied by policy"
                );
                Err(BrokerError::Forbidden {
                    reason: "tool:invoke is required".into(),
                })
            }
        }
    }

    async fn advance(
        &self,
        tenant_id: &str,
        id: Uuid,
        from: ExecutionStatus,
        to: ExecutionStatus,
        patch: TransitionPatch,
    ) -> Result<(), BrokerError> {
        self.store
            .transition(tenant_id, id, from, to, patch)
            .await
            .map_err(BrokerError::from)
    }

    /// Move `RUNNING -> CLEANING_UP -> terminal` and return the stored row.
    async fn finish(
        &self,
        tenant_id: &str,
        id: Uuid,
        terminal: ExecutionStatus,
        patch: TransitionPatch,
    ) -> Result<ExecutionRecord, BrokerError> {
        if !terminal.is_terminal() {
            return Err(BrokerError::Internal);
        }

        self.advance(
            tenant_id,
            id,
            ExecutionStatus::Running,
            ExecutionStatus::CleaningUp,
            TransitionPatch::default(),
        )
        .await?;
        self.advance(tenant_id, id, ExecutionStatus::CleaningUp, terminal, patch)
            .await?;

        self.store
            .get(tenant_id, id)
            .await?
            .ok_or(BrokerError::Internal)
    }

    /// Failure that happens after the row exists but before the runtime is
    /// asked to do anything.
    async fn fail_before_start(&self, tenant_id: &str, id: Uuid, kind: &str, message: &str) {
        let patch = TransitionPatch {
            finished_at: Some(chrono::Utc::now()),
            failure_kind: Some(kind.into()),
            failure_message: Some(message.into()),
            duration_ms: Some(0),
            ..Default::default()
        };

        for (from, to) in [
            (ExecutionStatus::Created, ExecutionStatus::CleaningUp),
            (ExecutionStatus::CleaningUp, ExecutionStatus::Failed),
        ] {
            if self
                .store
                .transition(tenant_id, id, from, to, patch.clone())
                .await
                .is_err()
            {
                tracing::error!(
                    tenant_id = %tenant_id,
                    execution_id = %id,
                    from = %from,
                    "could not record a pre-start failure"
                );
                return;
            }
        }
    }

    /// Acquire a per-tenant execution slot without waiting.
    async fn acquire_lane(&self, tenant_id: &str) -> Result<OwnedSemaphorePermit, BrokerError> {
        let semaphore = {
            let mut lanes = self.lanes.lock().await;
            lanes
                .entry(tenant_id.to_owned())
                .or_insert_with(|| {
                    Arc::new(Semaphore::new(self.config.max_concurrent_per_tenant.max(1)))
                })
                .clone()
        };

        semaphore.try_acquire_owned().map_err(|_| BrokerError::Busy)
    }
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Broker")
            .field("runtimes", &self.runtimes)
            .field("workloads", &self.workloads.names())
            .field(
                "max_concurrent_per_tenant",
                &self.config.max_concurrent_per_tenant,
            )
            .finish_non_exhaustive()
    }
}

/// Deterministic terminal status for a completed sandbox run.
fn terminal_status(result: &SandboxResult) -> ExecutionStatus {
    match result.termination {
        Termination::Completed => {
            if result.exit_code == Some(0) {
                ExecutionStatus::Completed
            } else {
                ExecutionStatus::Failed
            }
        }
        Termination::Failed => ExecutionStatus::Failed,
        Termination::TimedOut => ExecutionStatus::TimedOut,
        Termination::Cancelled => ExecutionStatus::Cancelled,
    }
}

/// Columns written when an execution reaches a terminal state.
fn terminal_patch(result: &SandboxResult, started: std::time::Instant) -> TransitionPatch {
    let mut combined = result.stdout.clone();
    combined.extend_from_slice(&result.stderr);

    let artifacts = result
        .artifacts
        .iter()
        .map(|artifact| ArtifactRef {
            name: artifact.name.clone(),
            size_bytes: artifact.size_bytes as i64,
            sha256: artifact.sha256.clone(),
        })
        .collect::<Vec<_>>();

    let duration_ms = result
        .duration
        .max(started.elapsed())
        .as_millis()
        .min(i64::MAX as u128) as i64;

    TransitionPatch {
        finished_at: Some(chrono::Utc::now()),
        exit_code: result.exit_code,
        failure_kind: result
            .failure
            .as_ref()
            .map(|failure| failure.kind.as_str().to_owned()),
        failure_message: result
            .failure
            .as_ref()
            .map(|failure| truncate(&failure.message, 512)),
        duration_ms: Some(duration_ms),
        fuel_consumed: result
            .fuel_consumed
            .map(|fuel| fuel.min(i64::MAX as u64) as i64),
        memory_peak_bytes: result
            .memory_peak_bytes
            .map(|bytes| bytes.min(i64::MAX as u64) as i64),
        output_digest: Some(digest(&combined)),
        stdout: Some(String::from_utf8_lossy(&result.stdout).into_owned()),
        stderr: Some(String::from_utf8_lossy(&result.stderr).into_owned()),
        artifacts: Some(artifacts),
        ..Default::default()
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

/// Task ids appear in logs and storage, so they are bounded and printable.
fn valid_task_id(task_id: &str) -> bool {
    !task_id.is_empty()
        && task_id.len() <= 128
        && task_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_ids_are_bounded_and_printable() {
        assert!(valid_task_id("task-1"));
        assert!(valid_task_id("tenant_1:task.2"));
        assert!(!valid_task_id(""));
        assert!(!valid_task_id("has space"));
        assert!(!valid_task_id(&"a".repeat(129)));
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello", 3), "hel");
        let unicode = "héllo";
        assert_eq!(truncate(unicode, 2), "h");
    }
}
