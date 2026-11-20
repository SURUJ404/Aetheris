//! Execution broker tests.
//!
//! The broker is exercised against a fake runtime and the in-memory execution
//! store, so these tests are fast and deterministic. They cover the authority
//! boundary (authorization, tenant isolation, runtime allowlist, limits) and
//! the lifecycle (duplicates, cancellation, concurrency, recovery).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rust_control_plane::auth::Principal;
use rust_control_plane::broker::{Broker, BrokerError, ExecutionRequest};
use rust_control_plane::config::ExecutionConfig;
use rust_control_plane::execution::{
    ExecutionLimits, ExecutionStatus, ExecutionStore, MemoryExecutionStore, NewExecution,
    RuntimeKind, TransitionPatch,
};
use rust_control_plane::persistence::ResolvedPrincipal;
use rust_control_plane::principal::TenantContext;
use rust_control_plane::runtime::{
    FailureKind, FilesystemAccess, NetworkAccess, RuntimeCapabilities, RuntimeHealth,
    RuntimeRegistry, SandboxError, SandboxFailure, SandboxLimits, SandboxResult, SandboxRuntime,
    SandboxSpec, Termination, Workload, WorkloadRegistry,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Runtime that either echoes stdin or blocks until cancelled. It never touches
/// the filesystem, so broker tests stay independent of Wasmtime.
struct FakeRuntime {
    calls: AtomicUsize,
    block: bool,
    timeout: bool,
    started: Arc<Notify>,
}

impl FakeRuntime {
    fn new(block: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            block,
            timeout: false,
            started: Arc::new(Notify::new()),
        })
    }

    /// Always reports a wall-clock timeout, without blocking a test.
    fn timing_out() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            block: false,
            timeout: true,
            started: Arc::new(Notify::new()),
        })
    }
}

#[async_trait]
impl SandboxRuntime for FakeRuntime {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Wasmtime
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            runtime: RuntimeKind::Wasmtime,
            available: true,
            unavailable_reason: None,
            filesystem: FilesystemAccess::None,
            network: NetworkAccess::Disabled,
            arbitrary_python: false,
            shell: false,
            package_install: false,
            supports_cancellation: true,
            max_wall_clock_ms: 60_000,
            max_memory_bytes: 512 * 1024 * 1024,
        }
    }

    async fn health(&self) -> RuntimeHealth {
        RuntimeHealth::healthy()
    }

    async fn execute(
        &self,
        spec: SandboxSpec,
        cancel: CancellationToken,
    ) -> Result<SandboxResult, SandboxError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();

        if self.block {
            cancel.cancelled().await;
            return Ok(SandboxResult {
                termination: Termination::Cancelled,
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                duration: Duration::from_millis(1),
                fuel_consumed: None,
                memory_peak_bytes: None,
                artifacts: Vec::new(),
                failure: Some(SandboxFailure {
                    kind: FailureKind::Cancelled,
                    message: "cancelled".into(),
                }),
            });
        }

        if self.timeout {
            return Ok(SandboxResult {
                termination: Termination::TimedOut,
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                duration: Duration::from_millis(1),
                fuel_consumed: None,
                memory_peak_bytes: None,
                artifacts: Vec::new(),
                failure: Some(SandboxFailure {
                    kind: FailureKind::Timeout,
                    message: "timed out".into(),
                }),
            });
        }

        Ok(SandboxResult {
            termination: Termination::Completed,
            exit_code: Some(0),
            stdout: spec.stdin,
            stderr: Vec::new(),
            duration: Duration::from_millis(1),
            fuel_consumed: Some(1),
            memory_peak_bytes: Some(1024),
            artifacts: Vec::new(),
            failure: None,
        })
    }
}

fn context(tenant: &str, with_tool_invoke: bool) -> TenantContext {
    let mut permissions = vec!["task:read".to_string(), "task:write".to_string()];
    if with_tool_invoke {
        permissions.push("tool:invoke".to_string());
    }

    TenantContext {
        identity: Principal {
            subject: "user-1".into(),
            tenant_id: tenant.into(),
            issuer: "https://issuer.test".into(),
            audiences: vec!["rust-control-plane".into()],
            scopes: vec!["openid".into()],
            token_id: None,
            expires_at: u64::MAX,
        },
        resolved: ResolvedPrincipal {
            principal_id: Uuid::nil(),
            tenant_id: tenant.into(),
            role: if with_tool_invoke { "member" } else { "viewer" }.into(),
            permissions,
        },
    }
}

fn workload() -> Workload {
    Workload {
        name: "echo".into(),
        module: Arc::new(Vec::new()),
        sha256: "test".into(),
    }
}

fn limits(config: &ExecutionConfig) -> ExecutionLimits {
    ExecutionLimits {
        wall_clock_ms: config.max_wall_clock_ms / 2,
        cpu_fuel: config.max_cpu_fuel / 2,
        memory_bytes: config.max_memory_bytes / 2,
        max_output_bytes: config.max_output_bytes / 2,
        max_stdin_bytes: config.max_stdin_bytes / 2,
        max_artifacts_bytes: config.max_artifacts_bytes / 2,
    }
}

fn request(config: &ExecutionConfig, key: Option<&str>) -> ExecutionRequest {
    ExecutionRequest {
        task_id: "task-1".into(),
        runtime: RuntimeKind::Wasmtime,
        workload: "echo".into(),
        stdin: b"hello".to_vec(),
        limits: limits(config),
        idempotency_key: key.map(str::to_owned),
    }
}

fn broker(
    runtime: Arc<FakeRuntime>,
    store: Arc<MemoryExecutionStore>,
    config: ExecutionConfig,
) -> Broker {
    let runtimes: Vec<Arc<dyn SandboxRuntime>> = vec![runtime];
    Broker::new(
        store,
        RuntimeRegistry::new(runtimes),
        WorkloadRegistry::from_workloads([workload()]),
        config,
    )
}

#[tokio::test]
async fn unauthorized_execution_is_rejected_before_any_state() {
    let runtime = FakeRuntime::new(false);
    let store = Arc::new(MemoryExecutionStore::new());
    let config = ExecutionConfig::default();
    let broker = broker(runtime.clone(), store.clone(), config.clone());

    let error = broker
        .submit(&context("tenant-a", false), request(&config, None))
        .await
        .expect_err("must be rejected");

    assert!(matches!(error, BrokerError::Forbidden { .. }));
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    assert!(store.is_empty(), "denied request must not create a row");
}

#[tokio::test]
async fn cross_tenant_reads_are_invisible() {
    let runtime = FakeRuntime::new(false);
    let store = Arc::new(MemoryExecutionStore::new());
    let config = ExecutionConfig::default();
    let broker = broker(runtime, store, config.clone());

    let record = broker
        .submit(&context("tenant-a", true), request(&config, None))
        .await
        .expect("submit");

    let error = broker
        .get(&context("tenant-b", true), record.id)
        .await
        .expect_err("cross-tenant read must fail");
    assert!(matches!(error, BrokerError::NotFound));

    // Defense in depth: the row still belongs to tenant-a.
    let own = broker
        .get(&context("tenant-a", true), record.id)
        .await
        .expect("own read");
    assert!(own.belongs_to("tenant-a"));
}

#[tokio::test]
async fn a_runtime_outside_the_allowlist_is_rejected() {
    let runtime = FakeRuntime::new(false);
    let store = Arc::new(MemoryExecutionStore::new());
    let config = ExecutionConfig::default();
    let broker = broker(runtime, store, config.clone());

    let mut proposal = request(&config, None);
    proposal.runtime = RuntimeKind::Firecracker;

    let error = broker
        .submit(&context("tenant-a", true), proposal)
        .await
        .expect_err("must be rejected");

    assert!(matches!(
        error,
        BrokerError::RuntimeDisabled(RuntimeKind::Firecracker)
    ));
}

#[tokio::test]
async fn limits_above_the_ceiling_are_rejected_not_clamped() {
    let runtime = FakeRuntime::new(false);
    let store = Arc::new(MemoryExecutionStore::new());
    let config = ExecutionConfig::default();
    let broker = broker(runtime.clone(), store.clone(), config.clone());

    let mut proposal = request(&config, None);
    proposal.limits.wall_clock_ms = config.max_wall_clock_ms + 1;

    let error = broker
        .submit(&context("tenant-a", true), proposal)
        .await
        .expect_err("must be rejected");

    assert!(matches!(error, BrokerError::InvalidLimits(_)));
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    assert!(store.is_empty());
}

#[tokio::test]
async fn an_unknown_workload_is_rejected() {
    let runtime = FakeRuntime::new(false);
    let store = Arc::new(MemoryExecutionStore::new());
    let config = ExecutionConfig::default();
    let broker = broker(runtime, store, config.clone());

    let mut proposal = request(&config, None);
    proposal.workload = "not-approved".into();

    let error = broker
        .submit(&context("tenant-a", true), proposal)
        .await
        .expect_err("must be rejected");

    assert!(matches!(error, BrokerError::UnknownWorkload(_)));
}

#[tokio::test]
async fn duplicate_submission_returns_the_original_and_runs_once() {
    let runtime = FakeRuntime::new(false);
    let store = Arc::new(MemoryExecutionStore::new());
    let config = ExecutionConfig::default();
    let broker = broker(runtime.clone(), store, config.clone());

    let ctx = context("tenant-a", true);
    let first = broker
        .submit(&ctx, request(&config, Some("key-1")))
        .await
        .expect("first submit");
    let second = broker
        .submit(&ctx, request(&config, Some("key-1")))
        .await
        .expect("retry");

    assert_eq!(first.id, second.id);
    assert_eq!(first.status, ExecutionStatus::Completed);
    assert_eq!(second.status, ExecutionStatus::Completed);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancellation_reaches_the_running_sandbox() {
    let runtime = FakeRuntime::new(true);
    let store = Arc::new(MemoryExecutionStore::new());
    let config = ExecutionConfig::default();
    let broker = Arc::new(broker(runtime.clone(), store, config.clone()));
    let ctx = context("tenant-a", true);

    let handle = {
        let broker = broker.clone();
        let ctx = ctx.clone();
        let proposal = request(&config, Some("key-cancel"));
        tokio::spawn(async move { broker.submit(&ctx, proposal).await })
    };

    runtime.started.notified().await;

    // A duplicate is the supported way to learn the id of an in-flight
    // submission without guessing it.
    let in_flight = broker
        .submit(&ctx, request(&config, Some("key-cancel")))
        .await
        .expect("duplicate returns the in-flight row");
    assert_eq!(in_flight.status, ExecutionStatus::Running);

    let cancelled = broker.cancel(&ctx, in_flight.id).await.expect("cancel");
    assert!(cancelled.cancel_requested_at.is_some());

    let finished = handle.await.expect("join").expect("submission result");
    assert_eq!(finished.status, ExecutionStatus::Cancelled);
    assert_eq!(finished.failure_kind.as_deref(), Some("cancelled"));
}

#[tokio::test]
async fn a_tenant_concurrency_limit_rejects_extra_work() {
    let runtime = FakeRuntime::new(true);
    let store = Arc::new(MemoryExecutionStore::new());
    let config = ExecutionConfig {
        max_concurrent_per_tenant: 1,
        ..ExecutionConfig::default()
    };
    let broker = Arc::new(broker(runtime.clone(), store, config.clone()));
    let ctx = context("tenant-a", true);

    let handle = {
        let broker = broker.clone();
        let ctx = ctx.clone();
        let proposal = request(&config, Some("busy-1"));
        tokio::spawn(async move { broker.submit(&ctx, proposal).await })
    };

    runtime.started.notified().await;

    let error = broker
        .submit(&ctx, request(&config, Some("busy-2")))
        .await
        .expect_err("second execution must be rejected");
    assert!(matches!(error, BrokerError::Busy));

    // Release the blocked execution.
    let in_flight = broker
        .submit(&ctx, request(&config, Some("busy-1")))
        .await
        .expect("duplicate");
    broker.cancel(&ctx, in_flight.id).await.expect("cancel");

    let finished = handle.await.expect("join").expect("submission result");
    assert_eq!(finished.status, ExecutionStatus::Cancelled);
}

#[tokio::test]
async fn recovery_fails_rows_left_in_flight() {
    let store = Arc::new(MemoryExecutionStore::new());
    let runtime = FakeRuntime::new(false);
    let config = ExecutionConfig::default();
    let broker = broker(runtime, store.clone(), config.clone());

    let id = Uuid::new_v4();
    store
        .insert(NewExecution {
            id,
            tenant_id: "tenant-a".into(),
            principal_id: Uuid::nil(),
            task_id: "task-1".into(),
            runtime: RuntimeKind::Wasmtime,
            workload: "echo".into(),
            limits: limits(&config),
            policy_version: "test".into(),
            idempotency_key: None,
        })
        .await
        .expect("insert");

    for (from, to) in [
        (ExecutionStatus::Created, ExecutionStatus::Queued),
        (ExecutionStatus::Queued, ExecutionStatus::Authorized),
        (ExecutionStatus::Authorized, ExecutionStatus::Starting),
        (ExecutionStatus::Starting, ExecutionStatus::Running),
    ] {
        store
            .transition("tenant-a", id, from, to, TransitionPatch::default())
            .await
            .expect("advance");
    }

    let recovered = broker.recover().await.expect("recover");
    assert_eq!(recovered, vec![id]);

    let record = broker
        .get(&context("tenant-a", true), id)
        .await
        .expect("get");
    assert_eq!(record.status, ExecutionStatus::Failed);
    assert_eq!(record.failure_kind.as_deref(), Some("interrupted"));
}

#[tokio::test]
async fn a_successful_run_records_resources_and_output_digest() {
    let runtime = FakeRuntime::new(false);
    let store = Arc::new(MemoryExecutionStore::new());
    let config = ExecutionConfig::default();
    let broker = broker(runtime, store, config.clone());

    let record = broker
        .submit(&context("tenant-a", true), request(&config, None))
        .await
        .expect("submit");

    assert_eq!(record.status, ExecutionStatus::Completed);
    assert_eq!(record.exit_code, Some(0));
    assert_eq!(record.stdout.as_deref(), Some("hello"));
    assert!(record.output_digest.is_some());
    assert_eq!(record.fuel_consumed, Some(1));
    assert_eq!(record.memory_peak_bytes, Some(1024));
    assert_eq!(
        record.policy_version,
        rust_control_plane::policy::POLICY_VERSION
    );
}

#[tokio::test]
async fn a_timed_out_execution_is_persisted_as_timed_out() {
    let runtime = FakeRuntime::timing_out();
    let store = Arc::new(MemoryExecutionStore::new());
    let config = ExecutionConfig::default();
    let broker = broker(runtime, store, config.clone());

    let record = broker
        .submit(&context("tenant-a", true), request(&config, None))
        .await
        .expect("submit");

    assert_eq!(record.status, ExecutionStatus::TimedOut);
    assert_eq!(record.failure_kind.as_deref(), Some("timeout"));
}

/// Compile-time reminder: limits must be accepted by the runtime contract.
#[allow(dead_code)]
fn _limits_convert(limits: &ExecutionLimits) -> SandboxLimits {
    SandboxLimits::from(limits)
}
