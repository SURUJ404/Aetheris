//! Execution lifecycle: identities, limits, durable state and the store trait.
//!
//! This module owns the *state machine*. It deliberately contains no runtime
//! code: the broker drives transitions, and every transition is checked against
//! [`ExecutionStatus::can_transition_to`] so a status can never move backwards
//! or skip authorization.
//!
//! Invariants:
//! - A record is created only by the broker, after authentication and
//!   authorization succeeded.
//! - `tenant_id` and `principal_id` always come from the validated
//!   [`crate::principal::TenantContext`], never from a request body.
//! - Terminal states are immutable. Cleanup runs before the terminal state is
//!   written, so a terminal row always describes a reclaimed sandbox.
//! - Idempotency is durable: `(tenant_id, idempotency_key)` is unique in
//!   PostgreSQL and enforced by the store, not by an in-process cache.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Policy vocabulary version recorded on every execution.
///
/// Bumped when authorization semantics change so an audit can tell which rules
/// were in force. The value mirrors [`crate::policy::POLICY_VERSION`].
pub const DEFAULT_POLICY_VERSION: &str = crate::policy::POLICY_VERSION;

/// Which sandbox implementation runs a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    /// Wasmtime with restricted WASI.
    Wasmtime,
    /// Firecracker microVM.
    Firecracker,
}

impl RuntimeKind {
    /// Every runtime the control plane knows about.
    pub const ALL: [RuntimeKind; 2] = [RuntimeKind::Wasmtime, RuntimeKind::Firecracker];

    /// Stable wire/database name.
    pub const fn as_str(self) -> &'static str {
        match self {
            RuntimeKind::Wasmtime => "wasmtime",
            RuntimeKind::Firecracker => "firecracker",
        }
    }

    /// Exact, case-sensitive parse. Unknown names are client errors.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "wasmtime" => Some(RuntimeKind::Wasmtime),
            "firecracker" => Some(RuntimeKind::Firecracker),
            _ => None,
        }
    }
}

impl fmt::Display for RuntimeKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Deterministic execution lifecycle.
///
/// ```text
/// CREATED -> QUEUED -> AUTHORIZED -> STARTING -> RUNNING -> CLEANING_UP
///    |         |           |            |           |            |
///    +---------+-----------+------------+-----------+---> COMPLETED / FAILED
///                                                          TIMED_OUT / CANCELLED
/// ```
///
/// Non-terminal states may always be cancelled; `CLEANING_UP` runs before the
/// terminal state so resource reclamation is part of the durable record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Created,
    Queued,
    Authorized,
    Starting,
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    CleaningUp,
}

impl ExecutionStatus {
    /// Stable wire/database name.
    pub const fn as_str(self) -> &'static str {
        match self {
            ExecutionStatus::Created => "CREATED",
            ExecutionStatus::Queued => "QUEUED",
            ExecutionStatus::Authorized => "AUTHORIZED",
            ExecutionStatus::Starting => "STARTING",
            ExecutionStatus::Running => "RUNNING",
            ExecutionStatus::Completed => "COMPLETED",
            ExecutionStatus::Failed => "FAILED",
            ExecutionStatus::TimedOut => "TIMED_OUT",
            ExecutionStatus::Cancelled => "CANCELLED",
            ExecutionStatus::CleaningUp => "CLEANING_UP",
        }
    }

    /// Parse the database representation.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "CREATED" => Some(ExecutionStatus::Created),
            "QUEUED" => Some(ExecutionStatus::Queued),
            "AUTHORIZED" => Some(ExecutionStatus::Authorized),
            "STARTING" => Some(ExecutionStatus::Starting),
            "RUNNING" => Some(ExecutionStatus::Running),
            "COMPLETED" => Some(ExecutionStatus::Completed),
            "FAILED" => Some(ExecutionStatus::Failed),
            "TIMED_OUT" => Some(ExecutionStatus::TimedOut),
            "CANCELLED" => Some(ExecutionStatus::Cancelled),
            "CLEANING_UP" => Some(ExecutionStatus::CleaningUp),
            _ => None,
        }
    }

    /// Whether the row may no longer change.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            ExecutionStatus::Completed
                | ExecutionStatus::Failed
                | ExecutionStatus::TimedOut
                | ExecutionStatus::Cancelled
        )
    }

    /// Whether a caller may cancel from this state.
    pub const fn is_cancellable(self) -> bool {
        !self.is_terminal() && !matches!(self, ExecutionStatus::CleaningUp)
    }

    /// The only transitions the broker is allowed to perform.
    pub const fn can_transition_to(self, next: ExecutionStatus) -> bool {
        use ExecutionStatus::*;
        matches!(
            (self, next),
            (Created, Queued)
                | (Queued, Authorized)
                | (Authorized, Starting)
                | (Starting, Running)
                | (Starting, CleaningUp)
                | (Running, CleaningUp)
                // Cancellation or admission failure before the sandbox starts.
                | (Created, CleaningUp)
                | (Queued, CleaningUp)
                | (Authorized, CleaningUp)
                // Cleanup resolves to exactly one terminal state.
                | (CleaningUp, Completed)
                | (CleaningUp, Failed)
                | (CleaningUp, TimedOut)
                | (CleaningUp, Cancelled)
        )
    }
}

impl fmt::Display for ExecutionStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Hard execution limits. Every field is enforced by the sandbox runtime and
/// re-checked by the broker before dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLimits {
    /// Wall-clock budget in milliseconds.
    pub wall_clock_ms: u64,
    /// Abstract CPU fuel units consumed by the guest.
    pub cpu_fuel: u64,
    /// Linear-memory ceiling for the guest, in bytes.
    pub memory_bytes: u64,
    /// Maximum captured stdout+stderr bytes.
    pub max_output_bytes: u64,
    /// Maximum accepted stdin bytes.
    pub max_stdin_bytes: u64,
    /// Maximum total scratch artifact bytes returned to the control plane.
    pub max_artifacts_bytes: u64,
}

/// Server-side ceilings. A request may lower them but never raise them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitCeilings {
    pub wall_clock_ms: u64,
    pub cpu_fuel: u64,
    pub memory_bytes: u64,
    pub max_output_bytes: u64,
    pub max_stdin_bytes: u64,
    pub max_artifacts_bytes: u64,
}

impl LimitCeilings {
    /// Largest limits the deployment is willing to run.
    pub fn from_config(config: &crate::config::ExecutionConfig) -> Self {
        Self {
            wall_clock_ms: config.max_wall_clock_ms,
            cpu_fuel: config.max_cpu_fuel,
            memory_bytes: config.max_memory_bytes,
            max_output_bytes: config.max_output_bytes,
            max_stdin_bytes: config.max_stdin_bytes,
            max_artifacts_bytes: config.max_artifacts_bytes,
        }
    }
}

/// A limit that is zero or above the server ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LimitError {
    #[error("limit `{field}` must be greater than zero")]
    Zero { field: &'static str },
    #[error("limit `{field}` of {requested} exceeds the server ceiling of {ceiling}")]
    Exceeds {
        field: &'static str,
        requested: u64,
        ceiling: u64,
    },
}

impl ExecutionLimits {
    /// Reject limits that are zero or above the deployment ceiling.
    ///
    /// Limits are rejected, never clamped: silently widening a caller's budget
    /// would make the persisted record disagree with what actually ran.
    pub fn enforce(&self, ceilings: &LimitCeilings) -> Result<(), LimitError> {
        let checks = [
            ("wall_clock_ms", self.wall_clock_ms, ceilings.wall_clock_ms),
            ("cpu_fuel", self.cpu_fuel, ceilings.cpu_fuel),
            ("memory_bytes", self.memory_bytes, ceilings.memory_bytes),
            (
                "max_output_bytes",
                self.max_output_bytes,
                ceilings.max_output_bytes,
            ),
            (
                "max_stdin_bytes",
                self.max_stdin_bytes,
                ceilings.max_stdin_bytes,
            ),
            (
                "max_artifacts_bytes",
                self.max_artifacts_bytes,
                ceilings.max_artifacts_bytes,
            ),
        ];

        for (field, requested, ceiling) in checks {
            if requested == 0 {
                return Err(LimitError::Zero { field });
            }
            if requested > ceiling {
                return Err(LimitError::Exceeds {
                    field,
                    requested,
                    ceiling,
                });
            }
        }

        Ok(())
    }
}

impl From<&ExecutionLimits> for crate::runtime::SandboxLimits {
    fn from(limits: &ExecutionLimits) -> Self {
        Self {
            wall_clock: std::time::Duration::from_millis(limits.wall_clock_ms),
            cpu_fuel: limits.cpu_fuel,
            memory_bytes: limits.memory_bytes,
            max_output_bytes: limits.max_output_bytes,
            max_artifacts_bytes: limits.max_artifacts_bytes,
        }
    }
}

/// Reference to a file produced in the sandbox scratch directory.
///
/// The bytes stay in the sandbox. Only name, size and digest are persisted, so
/// artifact transfer never becomes an exfiltration channel into the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub name: String,
    pub size_bytes: i64,
    pub sha256: String,
}

/// One execution as stored.
#[derive(Debug, Clone)]
pub struct ExecutionRecord {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_id: Uuid,
    pub task_id: String,
    pub runtime: RuntimeKind,
    pub workload: String,
    pub status: ExecutionStatus,
    pub policy_version: String,
    pub limits: ExecutionLimits,
    pub idempotency_key: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub failure_kind: Option<String>,
    pub failure_message: Option<String>,
    pub cancel_requested_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub fuel_consumed: Option<i64>,
    pub memory_peak_bytes: Option<i64>,
    pub output_digest: Option<String>,
    /// Captured standard output, already bounded by the execution's output
    /// limit. Lossy UTF-8 is acceptable here because this copy is for humans;
    /// `output_digest` is the exact-bytes reference.
    pub stdout: Option<String>,
    /// Captured standard error, bounded the same way as `stdout`.
    pub stderr: Option<String>,
    pub artifacts: Vec<ArtifactRef>,
}

impl ExecutionRecord {
    /// Whether the caller's tenant owns this record.
    ///
    /// The store already filters by tenant; this is defense in depth so a store
    /// defect cannot cross a tenant boundary in the API layer.
    pub fn belongs_to(&self, tenant_id: &str) -> bool {
        self.tenant_id == tenant_id
    }
}

/// Fields written when a record is first created.
#[derive(Debug, Clone)]
pub struct NewExecution {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_id: Uuid,
    pub task_id: String,
    pub runtime: RuntimeKind,
    pub workload: String,
    pub limits: ExecutionLimits,
    pub policy_version: String,
    pub idempotency_key: Option<String>,
}

/// Optional columns written by a transition.
#[derive(Debug, Clone, Default)]
pub struct TransitionPatch {
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub failure_kind: Option<String>,
    pub failure_message: Option<String>,
    pub duration_ms: Option<i64>,
    pub fuel_consumed: Option<i64>,
    pub memory_peak_bytes: Option<i64>,
    pub output_digest: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub artifacts: Option<Vec<ArtifactRef>>,
}

/// Where durable execution state lives.
///
/// The broker depends on this trait only, so tests run against an in-memory
/// implementation while production uses PostgreSQL.
#[async_trait]
pub trait ExecutionStore: Send + Sync {
    /// Insert a record unless `(tenant_id, idempotency_key)` already exists.
    ///
    /// Returns the stored record and whether this call created it. On a
    /// duplicate, the existing record is returned unchanged and the boolean is
    /// `false`, which makes submission safely retryable.
    async fn insert(
        &self,
        new: NewExecution,
    ) -> Result<(ExecutionRecord, bool), ExecutionStoreError>;

    /// Fetch one record, scoped to a tenant.
    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ExecutionRecord>, ExecutionStoreError>;

    /// Apply one state transition and optional column patch.
    ///
    /// Fails with [`ExecutionStoreError::StateConflict`] when the row is no
    /// longer in `from`, so two actors cannot both advance the same execution.
    async fn transition(
        &self,
        tenant_id: &str,
        id: Uuid,
        from: ExecutionStatus,
        to: ExecutionStatus,
        patch: TransitionPatch,
    ) -> Result<(), ExecutionStoreError>;

    /// Record a cancellation request for a non-terminal execution.
    ///
    /// Returns the current status, or `None` when the record does not exist in
    /// this tenant.
    async fn request_cancel(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ExecutionStatus>, ExecutionStoreError>;

    /// Mark every non-terminal record as failed after a process restart.
    ///
    /// Nothing is running for those rows any more: their in-memory sandbox and
    /// cancellation token died with the previous process. Returns the ids that
    /// were recovered.
    async fn recover_interrupted(&self) -> Result<Vec<Uuid>, ExecutionStoreError>;
}

/// Store failures. Messages never contain SQL, row data or connection strings.
#[derive(Debug, Error)]
pub enum ExecutionStoreError {
    #[error("execution store is unavailable")]
    Unavailable(#[source] sqlx::Error),

    #[error("execution `{id}` is not in state `{expected}`")]
    StateConflict { id: Uuid, expected: ExecutionStatus },

    #[error("invalid execution transition from `{from}` to `{to}`")]
    InvalidTransition {
        from: ExecutionStatus,
        to: ExecutionStatus,
    },

    /// A stored row contains a value this build does not understand. Treated as
    /// a defect, never as a default status.
    #[error("stored execution state is not recognised by this build")]
    Corrupt,
}

impl From<sqlx::Error> for ExecutionStoreError {
    fn from(err: sqlx::Error) -> Self {
        Self::Unavailable(err)
    }
}

/// In-memory store used by unit tests and by single-process dry runs.
///
/// It mirrors the PostgreSQL semantics, including idempotent inserts and
/// compare-and-set transitions. It is never selected by the production binary.
#[derive(Debug, Default)]
pub struct MemoryExecutionStore {
    rows: Mutex<BTreeMap<Uuid, ExecutionRecord>>,
}

impl MemoryExecutionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored records.
    pub fn len(&self) -> usize {
        self.rows.lock().expect("execution store lock").len()
    }

    /// Whether the store holds no records.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<Uuid, ExecutionRecord>> {
        self.rows.lock().expect("execution store lock")
    }
}

#[async_trait]
impl ExecutionStore for MemoryExecutionStore {
    async fn insert(
        &self,
        new: NewExecution,
    ) -> Result<(ExecutionRecord, bool), ExecutionStoreError> {
        let mut rows = self.lock();

        if let Some(key) = &new.idempotency_key {
            if let Some(existing) = rows.values().find(|row| {
                row.tenant_id == new.tenant_id && row.idempotency_key.as_ref() == Some(key)
            }) {
                return Ok((existing.clone(), false));
            }
        }

        let record = ExecutionRecord {
            id: new.id,
            tenant_id: new.tenant_id,
            principal_id: new.principal_id,
            task_id: new.task_id,
            runtime: new.runtime,
            workload: new.workload,
            status: ExecutionStatus::Created,
            policy_version: new.policy_version,
            limits: new.limits,
            idempotency_key: new.idempotency_key,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            exit_code: None,
            failure_kind: None,
            failure_message: None,
            cancel_requested_at: None,
            duration_ms: None,
            fuel_consumed: None,
            memory_peak_bytes: None,
            output_digest: None,
            stdout: None,
            stderr: None,
            artifacts: Vec::new(),
        };

        rows.insert(record.id, record.clone());
        Ok((record, true))
    }

    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ExecutionRecord>, ExecutionStoreError> {
        Ok(self
            .lock()
            .get(&id)
            .filter(|row| row.tenant_id == tenant_id)
            .cloned())
    }

    async fn transition(
        &self,
        tenant_id: &str,
        id: Uuid,
        from: ExecutionStatus,
        to: ExecutionStatus,
        patch: TransitionPatch,
    ) -> Result<(), ExecutionStoreError> {
        if !from.can_transition_to(to) {
            return Err(ExecutionStoreError::InvalidTransition { from, to });
        }

        let mut rows = self.lock();
        let row = rows
            .get_mut(&id)
            .filter(|row| row.tenant_id == tenant_id)
            .ok_or(ExecutionStoreError::StateConflict { id, expected: from })?;

        if row.status != from {
            return Err(ExecutionStoreError::StateConflict { id, expected: from });
        }

        row.status = to;
        row.started_at = patch.started_at.or(row.started_at);
        row.finished_at = patch.finished_at.or(row.finished_at);
        row.exit_code = patch.exit_code.or(row.exit_code);
        row.failure_kind = patch.failure_kind.or(row.failure_kind.take());
        row.failure_message = patch.failure_message.or(row.failure_message.take());
        row.duration_ms = patch.duration_ms.or(row.duration_ms);
        row.fuel_consumed = patch.fuel_consumed.or(row.fuel_consumed);
        row.memory_peak_bytes = patch.memory_peak_bytes.or(row.memory_peak_bytes);
        row.output_digest = patch.output_digest.or(row.output_digest.take());
        row.stdout = patch.stdout.or(row.stdout.take());
        row.stderr = patch.stderr.or(row.stderr.take());
        row.artifacts = patch.artifacts.unwrap_or_else(|| row.artifacts.clone());

        Ok(())
    }

    async fn request_cancel(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ExecutionStatus>, ExecutionStoreError> {
        let mut rows = self.lock();
        let row = rows.get_mut(&id).filter(|row| row.tenant_id == tenant_id);

        Ok(row.map(|row| {
            if row.cancel_requested_at.is_none() {
                row.cancel_requested_at = Some(Utc::now());
            }
            row.status
        }))
    }

    async fn recover_interrupted(&self) -> Result<Vec<Uuid>, ExecutionStoreError> {
        let mut rows = self.lock();
        let mut recovered = Vec::new();

        for row in rows.values_mut() {
            if row.status.is_terminal() {
                continue;
            }
            row.status = ExecutionStatus::Failed;
            row.failure_kind = Some("interrupted".into());
            row.failure_message =
                Some("control plane restarted while the execution was in flight".into());
            row.finished_at = Some(Utc::now());
            recovered.push(row.id);
        }

        Ok(recovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ExecutionLimits {
        ExecutionLimits {
            wall_clock_ms: 1_000,
            cpu_fuel: 1_000_000,
            memory_bytes: 64 * 1024 * 1024,
            max_output_bytes: 64 * 1024,
            max_stdin_bytes: 64 * 1024,
            max_artifacts_bytes: 64 * 1024,
        }
    }

    fn ceilings() -> LimitCeilings {
        LimitCeilings {
            wall_clock_ms: 5_000,
            cpu_fuel: 10_000_000,
            memory_bytes: 256 * 1024 * 1024,
            max_output_bytes: 256 * 1024,
            max_stdin_bytes: 256 * 1024,
            max_artifacts_bytes: 256 * 1024,
        }
    }

    #[test]
    fn lifecycle_only_moves_forward() {
        use ExecutionStatus::*;

        assert!(Created.can_transition_to(Queued));
        assert!(Queued.can_transition_to(Authorized));
        assert!(Authorized.can_transition_to(Starting));
        assert!(Starting.can_transition_to(Running));
        assert!(Running.can_transition_to(CleaningUp));
        assert!(CleaningUp.can_transition_to(Completed));

        // No state can be re-entered and terminal states never move.
        for status in [Created, Queued, Authorized, Starting, Running, CleaningUp] {
            assert!(
                !status.can_transition_to(status),
                "{status} self-transition"
            );
        }
        for terminal in [Completed, Failed, TimedOut, Cancelled] {
            assert!(terminal.is_terminal());
            for next in [Created, Queued, Authorized, Starting, Running, CleaningUp] {
                assert!(!terminal.can_transition_to(next));
            }
        }

        // Authorization cannot be skipped.
        assert!(!Created.can_transition_to(Running));
        assert!(!Queued.can_transition_to(Starting));
        assert!(!Created.can_transition_to(Authorized));
    }

    #[test]
    fn status_names_round_trip() {
        let all = [
            ExecutionStatus::Created,
            ExecutionStatus::Queued,
            ExecutionStatus::Authorized,
            ExecutionStatus::Starting,
            ExecutionStatus::Running,
            ExecutionStatus::Completed,
            ExecutionStatus::Failed,
            ExecutionStatus::TimedOut,
            ExecutionStatus::Cancelled,
            ExecutionStatus::CleaningUp,
        ];
        for status in all {
            assert_eq!(ExecutionStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(ExecutionStatus::parse("completed"), None);
    }

    #[test]
    fn runtime_names_round_trip_and_reject_case_variants() {
        for kind in RuntimeKind::ALL {
            assert_eq!(RuntimeKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(RuntimeKind::parse("Wasmtime"), None);
        assert_eq!(RuntimeKind::parse("docker"), None);
    }

    #[test]
    fn limits_are_rejected_not_clamped() {
        assert!(limits().enforce(&ceilings()).is_ok());

        let mut zero = limits();
        zero.cpu_fuel = 0;
        assert_eq!(
            zero.enforce(&ceilings()),
            Err(LimitError::Zero { field: "cpu_fuel" })
        );

        let mut too_large = limits();
        too_large.memory_bytes = ceilings().memory_bytes + 1;
        assert_eq!(
            too_large.enforce(&ceilings()),
            Err(LimitError::Exceeds {
                field: "memory_bytes",
                requested: ceilings().memory_bytes + 1,
                ceiling: ceilings().memory_bytes,
            })
        );
    }

    #[tokio::test]
    async fn memory_store_enforces_compare_and_set_transitions() {
        let store = MemoryExecutionStore::new();
        let id = Uuid::new_v4();
        let (record, created) = store
            .insert(NewExecution {
                id,
                tenant_id: "tenant-a".into(),
                principal_id: Uuid::nil(),
                task_id: "task-1".into(),
                runtime: RuntimeKind::Wasmtime,
                workload: "echo".into(),
                limits: limits(),
                policy_version: DEFAULT_POLICY_VERSION.into(),
                idempotency_key: Some("key-1".into()),
            })
            .await
            .expect("insert");
        assert!(created);
        assert_eq!(record.status, ExecutionStatus::Created);

        // A stale `from` must not advance the row.
        assert!(matches!(
            store
                .transition(
                    "tenant-a",
                    id,
                    ExecutionStatus::Running,
                    ExecutionStatus::CleaningUp,
                    TransitionPatch::default()
                )
                .await,
            Err(ExecutionStoreError::StateConflict { .. })
        ));

        store
            .transition(
                "tenant-a",
                id,
                ExecutionStatus::Created,
                ExecutionStatus::Queued,
                TransitionPatch::default(),
            )
            .await
            .expect("created -> queued");

        // Cross-tenant writes are invisible.
        assert!(matches!(
            store
                .transition(
                    "tenant-b",
                    id,
                    ExecutionStatus::Queued,
                    ExecutionStatus::Authorized,
                    TransitionPatch::default()
                )
                .await,
            Err(ExecutionStoreError::StateConflict { .. })
        ));
        assert!(store.get("tenant-b", id).await.expect("get").is_none());
    }

    #[tokio::test]
    async fn duplicate_idempotency_key_returns_the_original() {
        let store = MemoryExecutionStore::new();
        let new = |id| NewExecution {
            id,
            tenant_id: "tenant-a".into(),
            principal_id: Uuid::nil(),
            task_id: "task-1".into(),
            runtime: RuntimeKind::Wasmtime,
            workload: "echo".into(),
            limits: limits(),
            policy_version: DEFAULT_POLICY_VERSION.into(),
            idempotency_key: Some("same-key".into()),
        };

        let (first, created) = store.insert(new(Uuid::new_v4())).await.expect("first");
        assert!(created);

        let (second, created) = store.insert(new(Uuid::new_v4())).await.expect("second");
        assert!(!created);
        assert_eq!(first.id, second.id);
    }

    #[tokio::test]
    async fn recovery_fails_only_non_terminal_rows() {
        let store = MemoryExecutionStore::new();
        let running = Uuid::new_v4();
        let finished = Uuid::new_v4();

        async fn insert_running(store: &MemoryExecutionStore, id: Uuid) {
            store
                .insert(NewExecution {
                    id,
                    tenant_id: "tenant-a".into(),
                    principal_id: Uuid::nil(),
                    task_id: "task-1".into(),
                    runtime: RuntimeKind::Wasmtime,
                    workload: "echo".into(),
                    limits: limits(),
                    policy_version: DEFAULT_POLICY_VERSION.into(),
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
                    .expect("advance to running");
            }
        }

        insert_running(&store, running).await;

        insert_running(&store, finished).await;
        for (from, to) in [
            (ExecutionStatus::Running, ExecutionStatus::CleaningUp),
            (ExecutionStatus::CleaningUp, ExecutionStatus::Completed),
        ] {
            store
                .transition("tenant-a", finished, from, to, TransitionPatch::default())
                .await
                .expect("finish execution");
        }

        let recovered = store.recover_interrupted().await.expect("recover");
        assert_eq!(recovered, vec![running]);

        let record = store
            .get("tenant-a", running)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(record.status, ExecutionStatus::Failed);
        assert_eq!(record.failure_kind.as_deref(), Some("interrupted"));

        let record = store
            .get("tenant-a", finished)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(record.status, ExecutionStatus::Completed);
    }
}
