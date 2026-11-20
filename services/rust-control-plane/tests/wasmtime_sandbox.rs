//! Wasmtime sandbox integration tests.
//!
//! These run real WebAssembly through the real runtime. They are integration
//! tests (not KVM-dependent) and need no database.
//!
//! Covered: a valid WASI workload, invalid modules, fuel exhaustion, declared
//! memory above the ceiling, wall-clock timeout, filesystem escape denial,
//! scratch artifact collection and cleanup, network-import rejection, output
//! limits and cancellation.

use std::sync::Arc;
use std::time::Duration;

use rust_control_plane::execution::RuntimeKind;
use rust_control_plane::runtime::{
    FailureKind, SandboxError, SandboxLimits, SandboxResult, SandboxRuntime, SandboxSpec,
    Termination, WasmtimeConfig, WasmtimeRuntime, GUEST_AGENT_PORT,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const ECHO: &str = include_str!("../workloads/echo.wat");
const UPPERCASE: &str = include_str!("../workloads/uppercase.wat");

const SPIN: &str = r#"
(module
  (func (export "_start")
    (loop $forever (br $forever))))
"#;

fn runtime() -> WasmtimeRuntime {
    WasmtimeRuntime::new(WasmtimeConfig {
        enable_scratch: true,
        max_stack_bytes: 256 * 1024,
    })
    .expect("wasmtime runtime")
}

fn limits() -> SandboxLimits {
    SandboxLimits {
        wall_clock: Duration::from_secs(5),
        cpu_fuel: 10_000_000,
        memory_bytes: 16 * 1024 * 1024,
        max_output_bytes: 64 * 1024,
        max_artifacts_bytes: 64 * 1024,
    }
}

fn spec(wat: &str, stdin: &[u8]) -> SandboxSpec {
    SandboxSpec {
        execution_id: Uuid::new_v4(),
        workload: "test".into(),
        module: Arc::new(wat.as_bytes().to_vec()),
        stdin: stdin.to_vec(),
        env: Default::default(),
        limits: limits(),
        scratch_root: None,
    }
}

async fn run(wat: &str, stdin: &[u8]) -> SandboxResult {
    runtime()
        .execute(spec(wat, stdin), CancellationToken::new())
        .await
        .expect("sandbox execution")
}

#[tokio::test]
async fn executes_a_valid_wasi_workload() {
    let result = run(ECHO, b"hello sandbox").await;

    assert!(result.is_success(), "failure: {:?}", result.failure);
    assert_eq!(result.termination, Termination::Completed);
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, b"hello sandbox");
    assert!(result.stderr.is_empty());
    assert!(result.fuel_consumed.unwrap_or_default() > 0);
    assert!(!result.duration.is_zero(), "duration must be measured");
}

#[tokio::test]
async fn executes_a_data_transformation_workload() {
    let result = run(UPPERCASE, b"Mixed Case 123").await;

    assert!(result.is_success(), "failure: {:?}", result.failure);
    assert_eq!(result.stdout, b"MIXED CASE 123");
}

#[tokio::test]
async fn rejects_an_invalid_module() {
    let error = runtime()
        .execute(
            spec("this is not webassembly", b""),
            CancellationToken::new(),
        )
        .await
        .expect_err("must reject");

    assert!(
        matches!(error, SandboxError::InvalidWorkload { .. }),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn fuel_exhaustion_is_deterministic() {
    let mut sandbox = spec(SPIN, b"");
    sandbox.limits.cpu_fuel = 100_000;
    sandbox.limits.wall_clock = Duration::from_secs(30);

    let result = runtime()
        .execute(sandbox, CancellationToken::new())
        .await
        .expect("execution");

    assert_eq!(result.termination, Termination::Failed);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.kind),
        Some(FailureKind::FuelExhausted)
    );
}

#[tokio::test]
async fn declared_memory_above_the_ceiling_is_rejected() {
    // 64 pages = 4 MiB declared minimum, ceiling is 1 MiB.
    const GREEDY: &str = r#"
    (module
      (memory 64)
      (func (export "_start")))
    "#;

    let mut sandbox = spec(GREEDY, b"");
    sandbox.limits.memory_bytes = 1024 * 1024;

    let error = runtime()
        .execute(sandbox, CancellationToken::new())
        .await
        .expect_err("memory ceiling must reject the module");

    assert!(
        matches!(error, SandboxError::InvalidWorkload { .. }),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn a_guest_cannot_grow_past_the_memory_ceiling() {
    // One page initially, then ask for 64 more (4 MiB) under a 1 MiB ceiling.
    // `memory.grow` must fail and leave the guest at its original size.
    const GREEDY_GROW: &str = r#"
    (module
      (import "wasi_snapshot_preview1" "proc_exit"
        (func $proc_exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (if (i32.eq (memory.grow (i32.const 64)) (i32.const -1))
          (then (call $proc_exit (i32.const 0)))
          (else (call $proc_exit (i32.const 1))))))
    "#;

    let mut sandbox = spec(GREEDY_GROW, b"");
    sandbox.limits.memory_bytes = 1024 * 1024;

    let result = runtime()
        .execute(sandbox, CancellationToken::new())
        .await
        .expect("execution");

    assert!(result.is_success(), "failure: {:?}", result.failure);
}

#[tokio::test]
async fn a_spinning_guest_is_timed_out() {
    let mut sandbox = spec(SPIN, b"");
    sandbox.limits.cpu_fuel = u64::MAX / 4;
    sandbox.limits.wall_clock = Duration::from_millis(150);

    let result = runtime()
        .execute(sandbox, CancellationToken::new())
        .await
        .expect("execution");

    assert_eq!(result.termination, Termination::TimedOut);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.kind),
        Some(FailureKind::Timeout)
    );
}

#[tokio::test]
async fn a_guest_cannot_escape_the_scratch_directory() {
    // Ask WASI to open "../etc/passwd" relative to the only preopen (/scratch)
    // and print whether it succeeded. It must not.
    const ESCAPE: &str = r#"
    (module
      (import "wasi_snapshot_preview1" "path_open"
        (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "fd_write"
        (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit"
        (func $proc_exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 100) "../etc/passwd")
      (data (i32.const 200) "denied")
      (data (i32.const 300) "opened")
      (func (export "_start")
        (local $errno i32)
        (local $message i32)
        (i32.store (i32.const 8192) (i32.const 0))
        (i32.store (i32.const 8196) (i32.const 0))
        (local.set $errno
          (call $path_open
            (i32.const 3) (i32.const 0)
            (i32.const 100) (i32.const 13)
            (i32.const 0) (i64.const 0) (i64.const 0)
            (i32.const 0) (i32.const 8400)))
        (local.set $message
          (select (i32.const 300) (i32.const 200)
            (i32.eqz (local.get $errno))))
        (i32.store (i32.const 8192) (local.get $message))
        (i32.store (i32.const 8196) (i32.const 6))
        (drop (call $fd_write
          (i32.const 1) (i32.const 8192) (i32.const 1) (i32.const 8204)))
        (call $proc_exit (i32.const 0))))
    "#;

    let root = scratch_root();
    let mut sandbox = spec(ESCAPE, b"");
    sandbox.scratch_root = Some(root.clone());
    let execution_id = sandbox.execution_id;

    let result = runtime()
        .execute(sandbox, CancellationToken::new())
        .await
        .expect("execution");

    assert!(result.is_success(), "failure: {:?}", result.failure);
    assert_eq!(result.stdout, b"denied", "guest escaped /scratch");

    // The per-execution directory is always removed.
    assert!(!root.join(execution_id.to_string()).exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn scratch_files_are_collected_as_artifacts_and_removed() {
    // Create /scratch/out.txt, write "hi" and exit.
    const WRITE: &str = r#"
    (module
      (import "wasi_snapshot_preview1" "path_open"
        (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "fd_write"
        (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit"
        (func $proc_exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 100) "out.txt")
      (data (i32.const 200) "hi")
      (func (export "_start")
        (drop (call $path_open
          (i32.const 3) (i32.const 0)
          (i32.const 100) (i32.const 7)
          (i32.const 9) (i64.const 64) (i64.const 64)
          (i32.const 0) (i32.const 8400)))
        (i32.store (i32.const 8192) (i32.const 200))
        (i32.store (i32.const 8196) (i32.const 2))
        (drop (call $fd_write
          (i32.load (i32.const 8400))
          (i32.const 8192) (i32.const 1) (i32.const 8204)))
        (call $proc_exit (i32.const 0))))
    "#;

    let root = scratch_root();
    let mut sandbox = spec(WRITE, b"");
    sandbox.scratch_root = Some(root.clone());
    let execution_id = sandbox.execution_id;

    let result = runtime()
        .execute(sandbox, CancellationToken::new())
        .await
        .expect("execution");

    assert!(result.is_success(), "failure: {:?}", result.failure);
    assert_eq!(result.artifacts.len(), 1);
    assert_eq!(result.artifacts[0].name, "out.txt");
    assert_eq!(result.artifacts[0].size_bytes, 2);

    // Automatic cleanup: the scratch directory is gone after the run.
    assert!(!root.join(execution_id.to_string()).exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn socket_imports_are_rejected() {
    const NETWORK: &str = r#"
    (module
      (import "wasi_snapshot_preview1" "sock_open"
        (func (param i32 i32 i32 i32) (result i32)))
      (func (export "_start")))
    "#;

    let error = runtime()
        .execute(spec(NETWORK, b""), CancellationToken::new())
        .await
        .expect_err("network imports must be rejected");

    match error {
        SandboxError::InvalidWorkload { reason } => {
            assert!(reason.contains("socket"), "reason: {reason}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn output_beyond_the_limit_is_cut_off_and_reported() {
    // Fill one page and write all 64 KiB; the execution allows 1 KiB.
    const FLOOD: &str = r#"
    (module
      (import "wasi_snapshot_preview1" "fd_write"
        (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit"
        (func $proc_exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (memory.fill (i32.const 0) (i32.const 65) (i32.const 65536))
        (i32.store (i32.const 8192) (i32.const 0))
        (i32.store (i32.const 8196) (i32.const 65536))
        (drop (call $fd_write
          (i32.const 1) (i32.const 8192) (i32.const 1) (i32.const 8204)))
        (call $proc_exit (i32.const 0))))
    "#;

    let mut sandbox = spec(FLOOD, b"");
    sandbox.limits.max_output_bytes = 1024;

    let result = runtime()
        .execute(sandbox, CancellationToken::new())
        .await
        .expect("execution");

    assert_eq!(result.termination, Termination::Failed);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.kind),
        Some(FailureKind::OutputLimit)
    );
    assert_eq!(result.stdout.len(), 1024);
}

#[tokio::test]
async fn stdout_and_stderr_share_the_output_budget() {
    const FLOOD_BOTH: &str = r#"
    (module
      (import "wasi_snapshot_preview1" "fd_write"
        (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit"
        (func $proc_exit (param i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (memory.fill (i32.const 0) (i32.const 65) (i32.const 1024))
        (i32.store (i32.const 8192) (i32.const 0))
        (i32.store (i32.const 8196) (i32.const 1024))
        (drop (call $fd_write
          (i32.const 1) (i32.const 8192) (i32.const 1) (i32.const 8204)))
        (drop (call $fd_write
          (i32.const 2) (i32.const 8192) (i32.const 1) (i32.const 8204)))
        (call $proc_exit (i32.const 0))))
    "#;

    let mut sandbox = spec(FLOOD_BOTH, b"");
    sandbox.limits.max_output_bytes = 1024;
    let result = runtime()
        .execute(sandbox, CancellationToken::new())
        .await
        .expect("execution");

    assert_eq!(result.termination, Termination::Failed);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.kind),
        Some(FailureKind::OutputLimit)
    );
    assert!(result.stdout.len() + result.stderr.len() <= 1024);
}

#[tokio::test]
async fn a_running_guest_can_be_cancelled() {
    let runtime = Arc::new(runtime());
    let mut sandbox = spec(SPIN, b"");
    sandbox.limits.cpu_fuel = u64::MAX / 4;
    sandbox.limits.wall_clock = Duration::from_secs(30);

    let token = CancellationToken::new();
    let canceller = token.clone();
    let trigger = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        canceller.cancel();
    });

    let result = runtime.execute(sandbox, token).await.expect("execution");

    trigger.await.expect("canceller");

    assert_eq!(result.termination, Termination::Cancelled);
    assert_eq!(
        result.failure.as_ref().map(|failure| failure.kind),
        Some(FailureKind::Cancelled)
    );
}

#[tokio::test]
async fn capabilities_describe_the_real_surface() {
    let runtime = runtime();
    assert_eq!(runtime.kind(), RuntimeKind::Wasmtime);
    let capabilities = runtime.capabilities();
    assert!(capabilities.available);
    assert!(!capabilities.arbitrary_python);
    assert!(!capabilities.shell);
    assert!(!capabilities.package_install);
    assert!(capabilities.supports_cancellation);
    assert!(runtime.health().await.healthy);
}

/// A private scratch root for one test.
fn scratch_root() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("agentic-sandbox-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("create scratch root");
    root
}

#[tokio::test]
async fn the_approved_manifest_loads_and_runs() {
    use rust_control_plane::runtime::WorkloadRegistry;

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("workloads");
    let registry = WorkloadRegistry::load(&root).expect("approved workload manifest");

    assert_eq!(registry.names(), vec!["byte-sum", "echo", "uppercase"]);

    let workload = registry.get("uppercase").expect("uppercase workload");
    let sandbox = SandboxSpec {
        execution_id: Uuid::new_v4(),
        workload: workload.name.clone(),
        module: workload.module.clone(),
        stdin: b"manifest".to_vec(),
        env: Default::default(),
        limits: limits(),
        scratch_root: None,
    };

    let result = runtime()
        .execute(sandbox, CancellationToken::new())
        .await
        .expect("execute approved workload");

    assert!(result.is_success(), "failure: {:?}", result.failure);
    assert_eq!(result.stdout, b"MANIFEST");
}

#[test]
fn guest_agent_port_is_stable() {
    // Firecracker's guest agent contract must not drift silently.
    assert_eq!(GUEST_AGENT_PORT, 52);
}
