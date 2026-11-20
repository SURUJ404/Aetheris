//! Wasmtime sandbox: restricted WASI preview1 workloads.
//!
//! What a guest gets:
//! - WASI preview1 only, with **no** network imports linked at all. A module
//!   that imports `sock_*` fails at instantiation, so egress is impossible by
//!   construction rather than by policy.
//! - No preopened directories unless the caller set a scratch root, in which
//!   case exactly one directory is exposed at `/scratch` and removed afterwards.
//! - An empty environment unless the control plane passes explicit key/value
//!   pairs (never from a request body).
//! - Fuel (CPU), linear-memory, wall-clock and output-size limits.
//!
//! What a guest cannot do:
//! - Read the host filesystem, host environment, or any fd it was not given.
//! - Spawn processes. WASI preview1 has no process API and only `_start` is
//!   invoked.
//! - Outlive its budget: epoch interruption fires every tick and the deadline
//!   callback enforces both wall-clock expiry and cancellation.

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;
use wasmtime::{Engine, Linker, Module, OptLevel, Store, StoreLimits, StoreLimitsBuilder, Trap};
use wasmtime_wasi::cli::{IsTerminal, StdinStream, StdoutStream};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{FsPerms, I32Exit, WasiCtxBuilder};

use super::{
    Artifact, FailureKind, FilesystemAccess, NetworkAccess, RuntimeCapabilities, RuntimeHealth,
    SandboxError, SandboxFailure, SandboxResult, SandboxRuntime, SandboxSpec, Termination,
};
use crate::execution::RuntimeKind;

/// How often the epoch ticker advances. Also the granularity of timeout and
/// cancellation detection.
const EPOCH_TICK: Duration = Duration::from_millis(10);

/// Guest path exposed for the per-execution scratch directory.
const SCRATCH_GUEST_PATH: &str = "/scratch";

/// Maximum depth walked when collecting artifacts.
const MAX_ARTIFACT_DEPTH: usize = 4;

/// Configuration for the Wasmtime runtime.
#[derive(Debug, Clone)]
pub struct WasmtimeConfig {
    /// Expose a per-execution scratch directory at `/scratch`.
    pub enable_scratch: bool,
    /// Maximum wasm operand stack per execution.
    pub max_stack_bytes: usize,
}

impl Default for WasmtimeConfig {
    fn default() -> Self {
        Self {
            enable_scratch: true,
            max_stack_bytes: 512 * 1024,
        }
    }
}

/// Wasmtime-backed sandbox runtime.
///
/// One engine is shared by every execution: compilation is the expensive part
/// and the engine holds no per-tenant state. Isolation comes from the store,
/// the empty linker and the WASI context, not from the engine.
pub struct WasmtimeRuntime {
    engine: Engine,
    config: WasmtimeConfig,
}

impl WasmtimeRuntime {
    /// Build the engine and start the epoch ticker.
    ///
    /// The ticker thread lives for the process lifetime and bumps the engine
    /// epoch every [`EPOCH_TICK`]. That is what makes wall-clock timeouts and
    /// cancellation able to interrupt a spinning guest.
    pub fn new(config: WasmtimeConfig) -> Result<Self, SandboxError> {
        let mut engine_config = wasmtime::Config::new();

        // Deterministic resource accounting.
        engine_config.consume_fuel(true);
        engine_config.epoch_interruption(true);

        // Keep the guest feature surface small: core modules, no threads, no
        // shared memory, no 64-bit memories, no component model.
        // Threads are compiled out entirely (the `threads` feature is not
        // enabled), so there is no shared-memory or atomic guest surface.
        engine_config.shared_memory(false);
        engine_config.wasm_memory64(false);
        engine_config.wasm_multi_memory(false);
        engine_config.wasm_custom_page_sizes(false);
        engine_config.wasm_tail_call(false);
        engine_config.wasm_wide_arithmetic(false);

        engine_config.max_wasm_stack(config.max_stack_bytes);
        engine_config.parallel_compilation(true);
        engine_config.cranelift_opt_level(OptLevel::Speed);
        engine_config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Disable);

        let engine = Engine::new(&engine_config).map_err(|err| SandboxError::Internal {
            reason: format!("wasmtime engine configuration rejected: {err}"),
        })?;

        let ticker_engine = engine.clone();
        std::thread::Builder::new()
            .name("wasmtime-epoch".into())
            .spawn(move || loop {
                std::thread::sleep(EPOCH_TICK);
                ticker_engine.increment_epoch();
            })
            .map_err(|err| SandboxError::Internal {
                reason: format!("could not start the epoch ticker: {err}"),
            })?;

        Ok(Self { engine, config })
    }

    /// Engine handle, for tests that compile modules directly.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

#[async_trait]
impl SandboxRuntime for WasmtimeRuntime {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Wasmtime
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            runtime: RuntimeKind::Wasmtime,
            available: true,
            unavailable_reason: None,
            filesystem: if self.config.enable_scratch {
                FilesystemAccess::ScratchOnly
            } else {
                FilesystemAccess::None
            },
            network: NetworkAccess::Disabled,
            arbitrary_python: false,
            shell: false,
            package_install: false,
            supports_cancellation: true,
            max_wall_clock_ms: 300_000,
            max_memory_bytes: 4 * 1024 * 1024 * 1024,
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
        let started = Instant::now();

        // Compile before touching the filesystem: a bad module must not leave a
        // scratch directory behind.
        let module = Module::new(&self.engine, spec.module.as_slice()).map_err(|err| {
            SandboxError::InvalidWorkload {
                reason: format!("module did not compile: {err}"),
            }
        })?;

        let links_network = module.imports().any(|import| {
            import.module() == "wasi_snapshot_preview1" && import.name().starts_with("sock_")
        });
        if links_network {
            // Defense in depth: the linker has no socket implementations, so
            // instantiation would fail anyway. Reject explicitly for a clear
            // error instead of a link failure.
            return Err(SandboxError::InvalidWorkload {
                reason: "workload imports a WASI socket function, which is not available".into(),
            });
        }

        let scratch = if self.config.enable_scratch {
            match spec.scratch_root.as_deref() {
                Some(root) => Some(ScratchDir::create(root, spec.execution_id)?),
                None => None,
            }
        } else {
            None
        };

        let outcome = run_blocking(
            &module,
            &spec,
            scratch.as_ref().map(ScratchDir::path),
            cancel.clone(),
        )
        .await;

        // Collect artifacts and always reclaim the directory, even when the run
        // failed or panicked.
        let artifacts = match (scratch, &outcome) {
            (Some(scratch), Ok(_)) => match scratch.collect(spec.limits.max_artifacts_bytes) {
                Ok(artifacts) => artifacts,
                Err(err) => {
                    scratch.remove();
                    return Err(err);
                }
            },
            (Some(scratch), Err(_)) => {
                scratch.remove();
                Vec::new()
            }
            (None, _) => Vec::new(),
        };

        let mut result = outcome?;
        result.artifacts = artifacts;
        result.duration = started.elapsed();
        Ok(result)
    }
}

/// Reason recorded by the epoch callback so trap classification is
/// deterministic rather than string-matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum StopReason {
    None = 0,
    Cancelled = 1,
    TimedOut = 2,
}

struct SandboxState {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

/// Run the guest on a blocking thread.
///
/// Wasmtime execution is synchronous; `spawn_blocking` keeps a spinning guest
/// off the async reactor. The epoch callback is the only interruption path.
async fn run_blocking(
    module: &Module,
    spec: &SandboxSpec,
    scratch: Option<&Path>,
    cancel: CancellationToken,
) -> Result<SandboxResult, SandboxError> {
    let limits = spec.limits;
    let stdin = StdinBytes::new(spec.stdin.clone());
    let output_budget = Arc::new(CaptureBudget::new(limits.max_output_bytes));
    let stdout = CaptureStream::with_budget(output_budget.clone());
    let stderr = CaptureStream::with_budget(output_budget);

    let mut builder = WasiCtxBuilder::new();
    builder
        .stdin(stdin)
        .stdout(stdout.clone())
        .stderr(stderr.clone())
        .args(std::slice::from_ref(&spec.workload));

    // Environment is exactly what the control plane supplied: never inherited.
    let env: Vec<(String, String)> = spec
        .env
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if !env.is_empty() {
        builder.envs(&env);
    }

    if let Some(dir) = scratch {
        builder
            .preopened_dir(dir, SCRATCH_GUEST_PATH, FsPerms::ReadWrite)
            .map_err(|err| SandboxError::Internal {
                reason: format!("could not preopen the scratch directory: {err}"),
            })?;
    }

    let wasi = builder.build_p1();

    // Rebuild the same module against this engine. `Module` is engine-bound; the
    // caller's module came from our own engine, so this is cheap (cached).
    let module = module.clone();

    let stop_reason = Arc::new(AtomicU8::new(StopReason::None as u8));
    let started = Instant::now();
    let deadline = started + limits.wall_clock;

    let state = SandboxState {
        wasi,
        limits: StoreLimitsBuilder::new()
            .memory_size(limits.memory_bytes as usize)
            .memories(1)
            .tables(4)
            .instances(1)
            .build(),
    };

    let engine = module.engine().clone();
    let stop_flag = stop_reason.clone();
    let cancel_for_guest = cancel.clone();
    let fuel = limits.cpu_fuel;

    let joined = tokio::task::spawn_blocking(move || {
        let mut store = Store::new(&engine, state);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(fuel).map_err(|err| SandboxError::Internal {
            reason: format!("could not arm the fuel budget: {err}"),
        })?;
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(move |_hook| {
            if cancel_for_guest.is_cancelled() {
                stop_flag.store(StopReason::Cancelled as u8, Ordering::SeqCst);
                return Err(wasmtime::Error::msg("sandbox cancelled"));
            }
            if Instant::now() >= deadline {
                stop_flag.store(StopReason::TimedOut as u8, Ordering::SeqCst);
                return Err(wasmtime::Error::msg("sandbox wall-clock budget exhausted"));
            }
            Ok(wasmtime::UpdateDeadline::Continue(1))
        });

        let mut linker = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |state: &mut SandboxState| &mut state.wasi).map_err(
            |err| SandboxError::Internal {
                reason: format!("could not link WASI preview1: {err}"),
            },
        )?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|err| classify_instantiation_error(&err))?;

        let entry = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|_| SandboxError::InvalidWorkload {
                reason: "module does not export a WASI `_start` function".into(),
            })?;

        let call = entry.call(&mut store, ());
        let fuel_consumed = store.get_fuel().ok().map(|left| fuel.saturating_sub(left));
        let reason = stop_reason.load(Ordering::SeqCst);

        Ok::<_, SandboxError>((call, fuel_consumed, reason))
    })
    .await
    .map_err(|err| SandboxError::Internal {
        reason: format!("sandbox worker did not complete: {err}"),
    })??;

    let (call, fuel_consumed, reason) = joined;

    let (stdout_bytes, stdout_overflowed) = stdout.take();
    let (stderr_bytes, stderr_overflowed) = stderr.take();
    let overflowed = stdout_overflowed || stderr_overflowed;

    let mut result = SandboxResult {
        termination: Termination::Completed,
        exit_code: None,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
        duration: Duration::ZERO,
        fuel_consumed,
        memory_peak_bytes: None,
        artifacts: Vec::new(),
        failure: None,
    };

    match reason {
        r if r == StopReason::Cancelled as u8 => {
            result.termination = Termination::Cancelled;
            result.failure = Some(SandboxFailure {
                kind: FailureKind::Cancelled,
                message: "execution was cancelled".into(),
            });
        }
        r if r == StopReason::TimedOut as u8 => {
            result.termination = Termination::TimedOut;
            result.failure = Some(SandboxFailure {
                kind: FailureKind::Timeout,
                message: "wall-clock budget exhausted".into(),
            });
        }
        _ => match call {
            Ok(()) => {
                if overflowed {
                    result.termination = Termination::Failed;
                    result.failure = Some(SandboxFailure {
                        kind: FailureKind::OutputLimit,
                        message: "captured output exceeded its limit".into(),
                    });
                } else {
                    result.exit_code = Some(0);
                }
            }
            Err(err) => {
                if let Some(exit) = err.downcast_ref::<I32Exit>() {
                    result.exit_code = Some(exit.0);
                    if exit.0 != 0 {
                        result.termination = Termination::Failed;
                        result.failure = Some(SandboxFailure {
                            kind: FailureKind::Trap,
                            message: format!("guest exited with status {}", exit.0),
                        });
                    }
                } else if let Some(trap) = err.downcast_ref::<Trap>() {
                    let kind = match trap {
                        Trap::OutOfFuel => FailureKind::FuelExhausted,
                        Trap::Interrupt => FailureKind::Timeout,
                        _ => FailureKind::Trap,
                    };
                    result.termination = if kind == FailureKind::Timeout {
                        Termination::TimedOut
                    } else {
                        Termination::Failed
                    };
                    result.failure = Some(SandboxFailure {
                        kind,
                        message: trap.to_string(),
                    });
                } else {
                    result.termination = Termination::Failed;
                    result.failure = Some(SandboxFailure {
                        kind: FailureKind::Trap,
                        message: "guest trapped".into(),
                    });
                }
            }
        },
    }

    if result.failure.is_none() && overflowed {
        result.termination = Termination::Failed;
        result.failure = Some(SandboxFailure {
            kind: FailureKind::OutputLimit,
            message: "captured output exceeded its limit".into(),
        });
    }

    result.duration = started.elapsed();

    Ok(result)
}

/// Map instantiation failures onto structured errors.
///
/// A module that imports something the linker does not provide (sockets,
/// unknown host functions, process APIs) is rejected here, which is why network
/// access is impossible rather than merely discouraged.
fn classify_instantiation_error(err: &wasmtime::Error) -> SandboxError {
    let message = err.to_string();
    if message.contains("memory") && message.contains("limit") {
        return SandboxError::InvalidWorkload {
            reason: "module requires more memory than its declared ceiling".into(),
        };
    }
    SandboxError::InvalidWorkload {
        reason: format!("module could not be instantiated: {message}"),
    }
}

/// Bytes plus an overflow flag.
type Captured = (Vec<u8>, bool);

#[derive(Clone)]
struct CaptureStream {
    inner: Arc<CaptureInner>,
}

struct CaptureInner {
    buffer: Mutex<Vec<u8>>,
    budget: Arc<CaptureBudget>,
    overflowed: AtomicBool,
}

impl CaptureStream {
    fn with_budget(budget: Arc<CaptureBudget>) -> Self {
        Self {
            inner: Arc::new(CaptureInner {
                buffer: Mutex::new(Vec::new()),
                budget,
                overflowed: AtomicBool::new(false),
            }),
        }
    }

    /// Take captured bytes and whether the limit was exceeded.
    ///
    /// Extra bytes are dropped rather than buffered, so a hostile guest cannot
    /// exhaust control-plane memory by writing gigabytes to stdout.
    fn take(&self) -> Captured {
        let bytes = std::mem::take(&mut *self.inner.buffer.lock().expect("capture lock"));
        (bytes, self.inner.overflowed.load(Ordering::SeqCst))
    }
}

struct CaptureBudget {
    limit: usize,
    used: std::sync::atomic::AtomicUsize,
}

impl CaptureBudget {
    fn new(limit: u64) -> Self {
        Self {
            limit: limit.min(usize::MAX as u64) as usize,
            used: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn reserve(&self, requested: usize) -> usize {
        let mut current = self.used.load(Ordering::Relaxed);
        loop {
            let remaining = self.limit.saturating_sub(current);
            let granted = requested.min(remaining);
            match self.used.compare_exchange_weak(
                current,
                current.saturating_add(granted),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return granted,
                Err(updated) => current = updated,
            }
        }
    }
}

impl IsTerminal for CaptureStream {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for CaptureStream {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(self.clone())
    }
}

impl AsyncWrite for CaptureStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let inner = &self.inner;
        let mut buffer = inner.buffer.lock().expect("capture lock");
        let granted = inner.budget.reserve(buf.len());
        if granted < buf.len() {
            inner.overflowed.store(true, Ordering::SeqCst);
            buffer.extend_from_slice(&buf[..granted]);
        } else {
            buffer.extend_from_slice(buf);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
struct StdinBytes {
    source: Arc<Mutex<Cursor<Vec<u8>>>>,
}

impl StdinBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            source: Arc::new(Mutex::new(Cursor::new(bytes))),
        }
    }
}

impl IsTerminal for StdinBytes {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdinStream for StdinBytes {
    fn async_stream(&self) -> Box<dyn AsyncRead + Send + Sync> {
        Box::new(self.clone())
    }
}

impl AsyncRead for StdinBytes {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut source = self.source.lock().expect("stdin lock");
        let destination = buf.initialize_unfilled();
        let read = source.read(destination)?;
        buf.advance(read);
        Poll::Ready(Ok(()))
    }
}

/// Per-execution scratch directory with unconditional cleanup.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn create(root: &Path, execution_id: uuid::Uuid) -> Result<Self, SandboxError> {
        let path = root.join(execution_id.to_string());
        std::fs::create_dir_all(&path).map_err(|err| SandboxError::Internal {
            reason: format!("could not create the scratch directory: {err}"),
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Collect regular files, bounded by `budget` bytes.
    ///
    /// Symlinks are skipped: a guest must not be able to make the control plane
    /// read an arbitrary host path through an artifact.
    fn collect(&self, budget: u64) -> Result<Vec<Artifact>, SandboxError> {
        let mut files = Vec::new();
        walk(&self.path, &self.path, 0, &mut files)?;
        files.sort_by(|a, b| a.0.cmp(&b.0));

        let mut artifacts = Vec::new();
        let mut consumed = 0u64;

        for (name, path) in files {
            let metadata =
                std::fs::symlink_metadata(&path).map_err(|err| SandboxError::Internal {
                    reason: format!("could not stat an artifact: {err}"),
                })?;
            if !metadata.is_file() {
                continue;
            }
            let size = metadata.len();
            if consumed.saturating_add(size) > budget {
                return Err(SandboxError::Internal {
                    reason: "artifact budget exceeded".into(),
                });
            }
            let bytes = std::fs::read(&path).map_err(|err| SandboxError::Internal {
                reason: format!("could not read an artifact: {err}"),
            })?;
            consumed += size;
            artifacts.push(Artifact {
                name,
                size_bytes: size,
                sha256: super::digest(&bytes),
            });
        }

        Ok(artifacts)
    }

    fn remove(&self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        self.remove();
    }
}

fn walk(
    root: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), SandboxError> {
    if depth > MAX_ARTIFACT_DEPTH {
        return Ok(());
    }

    let entries = std::fs::read_dir(dir).map_err(|err| SandboxError::Internal {
        reason: format!("could not enumerate the scratch directory: {err}"),
    })?;

    for entry in entries {
        let entry = entry.map_err(|err| SandboxError::Internal {
            reason: format!("could not enumerate the scratch directory: {err}"),
        })?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|err| SandboxError::Internal {
            reason: format!("could not stat a scratch entry: {err}"),
        })?;

        if metadata.is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            walk(root, &path, depth + 1, out)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((relative, path));
        }
    }

    Ok(())
}

impl std::fmt::Debug for WasmtimeRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmtimeRuntime")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Convenience for tests and the broker: empty environment map type.
pub type EnvMap = BTreeMap<String, String>;
