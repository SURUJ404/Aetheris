//! Runtime-independent sandbox contract.
//!
//! The broker knows only this trait. `wasmtime` and `firecracker` implement it,
//! and the deployment chooses which ones are enabled through configuration.
//!
//! Security rules encoded here:
//! - A request describes *what* to run; it never describes *who* may run it.
//!   Identity and authorization are decided before a [`SandboxSpec`] exists.
//! - Capabilities are declared by the implementation and are advisory to the
//!   operator; they never widen what a guest can do at run time.
//! - Every execution carries limits and a cancellation token, so no runtime can
//!   run unbounded work.
//!
//! Failure reporting is split in two:
//! - [`SandboxError`] is an infrastructure failure (runtime unavailable, guest
//!   image unusable). Nothing ran, or the result is unknown.
//! - [`SandboxResult::failure`] describes a *completed* execution that ended
//!   badly (trap, fuel exhaustion, timeout, cancellation). The result still
//!   carries captured output and artifacts so the broker can persist evidence.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::execution::RuntimeKind;

pub mod firecracker;
pub mod wasmtime;
pub mod workload;

pub use firecracker::{FirecrackerConfig, FirecrackerRuntime, GUEST_AGENT_PORT};
pub use wasmtime::{WasmtimeConfig, WasmtimeRuntime};
pub use workload::{Workload, WorkloadError, WorkloadRegistry};

/// Limits handed to a runtime. Derived from [`crate::execution::ExecutionLimits`],
/// already validated against the deployment ceilings by the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxLimits {
    pub wall_clock: Duration,
    pub cpu_fuel: u64,
    pub memory_bytes: u64,
    pub max_output_bytes: u64,
    pub max_artifacts_bytes: u64,
}

/// Everything a runtime needs to run one workload.
///
/// Constructed only by the broker. There is no tenant or principal field: the
/// sandbox must not be able to reason about identity, and therefore cannot
/// widen its own permissions.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// Execution id, used for correlation and for naming scratch directories.
    pub execution_id: Uuid,
    /// Approved workload name from the registry.
    pub workload: String,
    /// Module bytes, loaded and hash-checked by the workload registry.
    pub module: Arc<Vec<u8>>,
    /// Standard input. Size already checked against the ceiling.
    pub stdin: Vec<u8>,
    /// Environment explicitly supplied by the control plane, never by a caller.
    pub env: BTreeMap<String, String>,
    /// Effective limits.
    pub limits: SandboxLimits,
    /// Parent directory for a per-execution scratch directory. `None` disables
    /// filesystem access entirely.
    pub scratch_root: Option<PathBuf>,
}

/// How an execution ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    /// The guest exited (possibly non-zero, see `exit_code`).
    Completed,
    /// The guest trapped, or a resource limit stopped it.
    Failed,
    /// The wall-clock budget expired.
    TimedOut,
    /// The caller cancelled the execution.
    Cancelled,
}

impl Termination {
    pub const fn as_str(self) -> &'static str {
        match self {
            Termination::Completed => "completed",
            Termination::Failed => "failed",
            Termination::TimedOut => "timed_out",
            Termination::Cancelled => "cancelled",
        }
    }
}

/// Structured reason an execution did not finish normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// Guest trap and non-zero exit reported by the runtime.
    Trap,
    /// Fuel (CPU) budget consumed.
    FuelExhausted,
    /// Guest tried to grow past its memory ceiling.
    MemoryExhausted,
    /// Wall-clock budget consumed.
    Timeout,
    /// Cancelled by the caller or by shutdown.
    Cancelled,
    /// Captured output exceeded its limit.
    OutputLimit,
    /// Module rejected by validation.
    InvalidModule,
    /// Runtime-internal failure.
    Internal,
}

impl FailureKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            FailureKind::Trap => "trap",
            FailureKind::FuelExhausted => "fuel_exhausted",
            FailureKind::MemoryExhausted => "memory_exhausted",
            FailureKind::Timeout => "timeout",
            FailureKind::Cancelled => "cancelled",
            FailureKind::OutputLimit => "output_limit",
            FailureKind::InvalidModule => "invalid_module",
            FailureKind::Internal => "internal",
        }
    }
}

/// Structured failure detail. `message` is runtime-owned text: it must never
/// contain host paths, environment values or other secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxFailure {
    pub kind: FailureKind,
    pub message: String,
}

/// Reference to a file produced in the sandbox scratch directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub name: String,
    pub size_bytes: u64,
    pub sha256: String,
}

/// Outcome of one execution.
#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub termination: Termination,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration: Duration,
    pub fuel_consumed: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub artifacts: Vec<Artifact>,
    pub failure: Option<SandboxFailure>,
}

impl SandboxResult {
    /// Whether the guest finished successfully with exit code 0.
    pub fn is_success(&self) -> bool {
        self.termination == Termination::Completed && self.exit_code == Some(0)
    }
}

/// Infrastructure-level sandbox failure: nothing valid came back.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// The runtime is disabled, misconfigured, or its host support is missing.
    #[error("runtime `{runtime}` is unavailable: {reason}")]
    Unavailable {
        runtime: RuntimeKind,
        reason: String,
    },

    /// The approved workload could not be loaded (missing, hash mismatch,
    /// unparseable module). Treated as a control-plane defect, not a guest bug.
    #[error("workload is not usable: {reason}")]
    InvalidWorkload { reason: String },

    /// Internal failure. The reason is logged, never returned to a caller.
    #[error("sandbox runtime failure")]
    Internal { reason: String },
}

/// Declared capability of one runtime.
///
/// This is what an operator can inspect before enabling a runtime. It is not a
/// runtime permission check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeCapabilities {
    pub runtime: RuntimeKind,
    /// Whether this deployment can actually run the runtime.
    pub available: bool,
    /// Why it cannot run, when `available` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    /// Filesystem surface exposed to a guest.
    pub filesystem: FilesystemAccess,
    /// Network surface exposed to a guest.
    pub network: NetworkAccess,
    /// Whether arbitrary Python can run.
    pub arbitrary_python: bool,
    /// Whether a shell can run.
    pub shell: bool,
    /// Whether the guest may install packages.
    pub package_install: bool,
    /// Whether the runtime can interrupt a running execution.
    pub supports_cancellation: bool,
    /// Largest wall-clock budget honoured.
    pub max_wall_clock_ms: u64,
    /// Largest memory ceiling honoured.
    pub max_memory_bytes: u64,
}

/// Filesystem surface of a runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemAccess {
    /// No preopened descriptors at all.
    None,
    /// One per-execution scratch directory, removed after the run.
    ScratchOnly,
    /// Isolated root filesystem inside a microVM.
    IsolatedRoot,
}

/// Network surface of a runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAccess {
    /// No network API is linked into the guest.
    Disabled,
    /// Guest has a NIC with no configured route to the host or the internet.
    IsolatedNoEgress,
}

/// Health of a runtime, probed by readiness and by operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeHealth {
    pub healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl RuntimeHealth {
    pub fn healthy() -> Self {
        Self {
            healthy: true,
            detail: None,
        }
    }

    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            healthy: false,
            detail: Some(detail.into()),
        }
    }
}

/// A sandbox implementation selected by configuration.
#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    /// Which runtime this is.
    fn kind(&self) -> RuntimeKind;

    /// Declared capabilities, including availability on this host.
    fn capabilities(&self) -> RuntimeCapabilities;

    /// Cheap health probe used by readiness and diagnostics.
    async fn health(&self) -> RuntimeHealth;

    /// Run one workload under the supplied limits and cancellation token.
    ///
    /// Implementations must return within the wall-clock limit plus a small
    /// constant, must remove every resource they created, and must not panic on
    /// malformed guest input.
    async fn execute(
        &self,
        spec: SandboxSpec,
        cancel: CancellationToken,
    ) -> Result<SandboxResult, SandboxError>;
}

/// The set of runtimes a deployment enabled.
#[derive(Clone, Default)]
pub struct RuntimeRegistry {
    runtimes: BTreeMap<RuntimeKind, Arc<dyn SandboxRuntime>>,
}

impl RuntimeRegistry {
    /// Build a registry. Later duplicates of the same kind are ignored so a
    /// misconfiguration cannot shadow the first (audited) instance.
    pub fn new(runtimes: impl IntoIterator<Item = Arc<dyn SandboxRuntime>>) -> Self {
        let mut map: BTreeMap<RuntimeKind, Arc<dyn SandboxRuntime>> = BTreeMap::new();
        for runtime in runtimes {
            map.entry(runtime.kind()).or_insert(runtime);
        }
        Self { runtimes: map }
    }

    /// Fetch an enabled runtime.
    pub fn get(&self, kind: RuntimeKind) -> Option<Arc<dyn SandboxRuntime>> {
        self.runtimes.get(&kind).cloned()
    }

    /// Enabled runtime kinds.
    pub fn kinds(&self) -> Vec<RuntimeKind> {
        self.runtimes.keys().copied().collect()
    }

    /// Declared capabilities of every enabled runtime.
    pub fn capabilities(&self) -> Vec<RuntimeCapabilities> {
        self.runtimes
            .values()
            .map(|runtime| runtime.capabilities())
            .collect()
    }
}

impl std::fmt::Debug for RuntimeRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeRegistry")
            .field("runtimes", &self.kinds())
            .finish()
    }
}

/// Hash module bytes the same way the workload registry does.
pub(crate) fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
