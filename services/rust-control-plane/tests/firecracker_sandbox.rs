//! Firecracker adapter and lifecycle tests.
//!
//! Two clearly separated groups:
//!
//! 1. **Adapter tests** (run always, no privileges): configuration validation,
//!    host probing, capability declaration and the refusal path. These prove the
//!    integration boundary never fakes execution.
//! 2. **KVM tests** (`#[ignore]`, run with `--ignored` on a real Firecracker
//!    host): an actual microVM boot and workload run.
//!
//! KVM test host requirements:
//! - Linux with `/dev/kvm` readable and writable by the test user;
//! - the `firecracker` binary (v1.x) at `FIRECRACKER_BINARY`;
//! - an uncompressed kernel at `FIRECRACKER_KERNEL_IMAGE`;
//! - a rootfs ext4 image at `FIRECRACKER_ROOTFS_IMAGE` containing the guest
//!   agent at `/usr/local/bin/agent`, listening on vsock port 52, with the
//!   workload map used below;
//! - the test process must run as root or with access to create TAP devices.
//!
//! None of this is available in the development container, which is why these
//! tests are ignored by default rather than skipped silently.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rust_control_plane::execution::RuntimeKind;
use rust_control_plane::runtime::{
    FirecrackerConfig, FirecrackerRuntime, SandboxError, SandboxLimits, SandboxRuntime, SandboxSpec,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn paths_from_env() -> Option<FirecrackerConfig> {
    let binary = std::env::var("FIRECRACKER_BINARY").ok()?;
    let kernel_image = std::env::var("FIRECRACKER_KERNEL_IMAGE").ok()?;
    let rootfs_image = std::env::var("FIRECRACKER_ROOTFS_IMAGE").ok()?;

    Some(FirecrackerConfig {
        binary: PathBuf::from(binary),
        kernel_image: PathBuf::from(kernel_image),
        rootfs_image: PathBuf::from(rootfs_image),
        scratch_root: std::env::temp_dir().join(format!("agentic-fc-test-{}", Uuid::new_v4())),
        ..FirecrackerConfig::default()
    })
}

fn limits() -> SandboxLimits {
    SandboxLimits {
        wall_clock: Duration::from_secs(30),
        cpu_fuel: 0,
        memory_bytes: 512 * 1024 * 1024,
        max_output_bytes: 64 * 1024,
        max_artifacts_bytes: 1024 * 1024,
    }
}

fn spec(execution_id: Uuid) -> SandboxSpec {
    SandboxSpec {
        execution_id,
        // The guest agent maps approved workload names to commands baked into
        // the rootfs image. Arbitrary code never crosses this boundary.
        workload: "echo".into(),
        module: Arc::new(Vec::new()),
        stdin: b"firecracker".to_vec(),
        env: Default::default(),
        limits: limits(),
        scratch_root: None,
    }
}

#[test]
fn impossible_machine_sizes_are_rejected_at_configuration_time() {
    // Each case changes exactly one field away from a valid default, so a
    // failure names the constraint rather than a combination of them.
    let base = FirecrackerConfig::default();

    assert!(FirecrackerConfig {
        vcpu_count: 0,
        ..base.clone()
    }
    .validate()
    .is_err());

    assert!(FirecrackerConfig {
        memory_mib: 64,
        ..base.clone()
    }
    .validate()
    .is_err());

    assert!(FirecrackerConfig {
        boot_args: "line one\nline two".into(),
        ..base.clone()
    }
    .validate()
    .is_err());

    assert!(FirecrackerConfig {
        guest_cid_base: 1,
        ..base.clone()
    }
    .validate()
    .is_err());

    assert!(base.validate().is_ok());
}

#[test]
fn capabilities_never_hide_the_firecracker_surface() {
    // Even when unavailable, the declared surface is honest: a microVM has a
    // shell and Python, so operators must see that before enabling it.
    let runtime = FirecrackerRuntime::new(FirecrackerConfig::default());
    let capabilities = runtime.capabilities();

    assert_eq!(capabilities.runtime, RuntimeKind::Firecracker);
    assert!(capabilities.arbitrary_python);
    assert!(capabilities.shell);
    assert!(capabilities.package_install);
    assert!(capabilities.supports_cancellation);
    assert_eq!(
        capabilities.network,
        rust_control_plane::runtime::NetworkAccess::IsolatedNoEgress
    );
}

#[tokio::test]
async fn a_host_without_firecracker_prerequisites_refuses_to_execute() {
    // Nonexistent paths guarantee the probe fails on every host, so this test
    // documents the refusal contract without depending on the machine.
    let runtime = FirecrackerRuntime::new(FirecrackerConfig {
        binary: PathBuf::from("/nonexistent/firecracker"),
        kernel_image: PathBuf::from("/nonexistent/vmlinux.bin"),
        rootfs_image: PathBuf::from("/nonexistent/rootfs.ext4"),
        scratch_root: std::env::temp_dir().join("agentic-fc-unavailable"),
        ..FirecrackerConfig::default()
    });

    assert!(!runtime.capabilities().available);
    assert!(runtime
        .capabilities()
        .unavailable_reason
        .unwrap_or_default()
        .contains("/dev/kvm"));

    let health = runtime.health().await;
    assert!(!health.healthy);

    let error = runtime
        .execute(spec(Uuid::new_v4()), CancellationToken::new())
        .await
        .expect_err("unavailable runtime must not fake a result");

    match error {
        SandboxError::Unavailable { runtime, .. } => {
            assert_eq!(runtime, RuntimeKind::Firecracker);
        }
        other => panic!("unexpected error: {other:?}"),
    }

    // Refusal must not have created a workspace.
    assert!(!runtime.config().scratch_root.exists());
}

/// Real microVM lifecycle. Ignored by default; see the host requirements at the
/// top of this file.
#[tokio::test]
#[ignore = "requires KVM, a firecracker binary, a kernel image and a guest-agent rootfs"]
async fn kvm_boots_a_microvm_and_runs_an_approved_workload() {
    let Some(config) = paths_from_env() else {
        panic!("set FIRECRACKER_BINARY, FIRECRACKER_KERNEL_IMAGE and FIRECRACKER_ROOTFS_IMAGE");
    };

    let runtime = FirecrackerRuntime::new(config.clone());
    let availability = runtime.availability();
    assert!(
        availability.ready,
        "Firecracker host is not ready: {}",
        availability.reason
    );

    let execution_id = Uuid::new_v4();
    let runtime_ref = Arc::new(runtime);
    let result = runtime_ref
        .execute(spec(execution_id), CancellationToken::new())
        .await
        .expect("microVM execution");

    assert!(result.is_success(), "failure: {:?}", result.failure);
    assert_eq!(result.stdout, b"firecracker");

    // Cleanup: the per-execution workspace is removed after the VM shuts down.
    assert!(!config.scratch_root.join(execution_id.to_string()).exists());
    let _ = std::fs::remove_dir_all(&config.scratch_root);
}
