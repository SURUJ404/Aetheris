//! Firecracker microVM runtime.
//!
//! This is the *integration boundary* for workloads that need a real Linux
//! userspace: arbitrary Python, shells, package installs. Rust still owns
//! authorization, limits and lifecycle; the guest only ever receives an
//! already-authorized workload.
//!
//! What is implemented here:
//! - Host prerequisite probing (`/dev/kvm`, the Firecracker binary, the kernel
//!   and root filesystem images). The runtime reports itself **unavailable**
//!   when any is missing; it never pretends a VM ran.
//! - A complete VM lifecycle: workspace staging, API-socket configuration
//!   (boot source, drives, machine config, vsock), instance start, readiness,
//!   wall-clock timeout, cancellation, kill and workspace reclamation.
//! - The host side of the guest-agent protocol over the Firecracker vsock
//!   device, and artifact accounting.
//!
//! What is *not* here, and is a deployment requirement rather than code:
//! - The guest agent inside the root filesystem (`/usr/local/bin/agent`,
//!   vsock port [`GUEST_AGENT_PORT`]) and the images themselves.
//! - Networking: no NIC is configured at all, so a guest has no route to the
//!   host, the LAN or the internet.
//!
//! Security notes:
//! - The Docker daemon socket is never used or mounted.
//! - The host filesystem is never shared into the VM; only a per-execution
//!   *copy* of the rootfs image and a read-only kernel image path are handed
//!   to Firecracker.
//! - The API socket lives in the per-execution workspace and is removed with
//!   it.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    FailureKind, FilesystemAccess, NetworkAccess, RuntimeCapabilities, RuntimeHealth, SandboxError,
    SandboxFailure, SandboxResult, SandboxRuntime, SandboxSpec, Termination,
};
use crate::execution::RuntimeKind;

/// vsock port the guest agent must listen on.
pub const GUEST_AGENT_PORT: u32 = 52;

/// Firecracker configuration. Every path is explicit: nothing is discovered
/// from the working directory.
#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    /// Path to the `firecracker` binary.
    pub binary: PathBuf,
    /// Uncompressed kernel image (`vmlinux`).
    pub kernel_image: PathBuf,
    /// Root filesystem image containing the guest agent and the runtime
    /// (Python, shell, package manager) the workloads need.
    pub rootfs_image: PathBuf,
    /// vCPUs per microVM.
    pub vcpu_count: u8,
    /// Guest memory in MiB.
    pub memory_mib: u32,
    /// Kernel command line.
    pub boot_args: String,
    /// Base CID for the vsock device. Each execution uses
    /// `guest_cid_base + (execution_id & 0xffff)` to avoid collisions.
    pub guest_cid_base: u32,
    /// Timeout for a single Firecracker API call.
    pub api_timeout: Duration,
    /// Timeout waiting for the API socket to appear after spawn.
    pub boot_timeout: Duration,
    /// Where per-execution workspaces are created.
    pub scratch_root: PathBuf,
    /// Ordered list of env vars forwarded to the guest agent, if present in the
    /// server environment. Values never come from a request.
    pub env_allowlist: Vec<String>,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("/usr/local/bin/firecracker"),
            kernel_image: PathBuf::from("/var/lib/agentic/vmlinux.bin"),
            rootfs_image: PathBuf::from("/var/lib/agentic/rootfs.ext4"),
            vcpu_count: 1,
            memory_mib: 512,
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off".into(),
            guest_cid_base: 16,
            api_timeout: Duration::from_secs(5),
            boot_timeout: Duration::from_secs(15),
            scratch_root: std::env::temp_dir().join("agentic-firecracker"),
            env_allowlist: Vec::new(),
        }
    }
}

impl FirecrackerConfig {
    /// Validate static configuration.
    ///
    /// Rejects limits Firecracker itself cannot honour so a bad value fails at
    /// startup rather than mid-execution.
    pub fn validate(&self) -> Result<(), String> {
        if self.vcpu_count == 0 || self.vcpu_count > 32 {
            return Err("vcpu_count must be between 1 and 32".into());
        }
        if self.memory_mib < 128 || self.memory_mib > 32_768 {
            return Err("memory_mib must be between 128 and 32768".into());
        }
        if self.boot_args.len() > 1024 {
            return Err("boot_args must not exceed 1024 bytes".into());
        }
        if self.boot_args.contains('\n') {
            return Err("boot_args must be a single line".into());
        }
        if self.guest_cid_base < 3 {
            return Err("guest_cid_base must be at least 3".into());
        }
        Ok(())
    }
}

/// Result of host prerequisite probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Availability {
    pub ready: bool,
    /// Human-readable reason when not ready. Never contains secrets.
    pub reason: String,
}

/// Firecracker-backed sandbox runtime.
pub struct FirecrackerRuntime {
    config: FirecrackerConfig,
    availability: Availability,
}

/// How the host-side run loop ended before a result was assembled.
///
/// Kept separate from [`SandboxError`] so cancellation and wall-clock
/// exhaustion are reported as outcomes (with a termination and failure kind)
/// rather than as infrastructure failures.
enum Outcome {
    Response(AgentResponse),
    Cancelled,
    TimedOut,
    Failed(SandboxError),
}

impl FirecrackerRuntime {
    /// Build the runtime and probe host prerequisites once.
    ///
    /// Probing is cheap and does not launch anything. A missing prerequisite
    /// makes the runtime unavailable instead of failing every request with an
    /// opaque error later.
    pub fn new(config: FirecrackerConfig) -> Self {
        let availability = probe(&config);
        Self {
            config,
            availability,
        }
    }

    /// Current availability, re-probed on demand.
    pub fn availability(&self) -> Availability {
        probe(&self.config)
    }

    /// Configuration in use.
    pub fn config(&self) -> &FirecrackerConfig {
        &self.config
    }

    fn require_available(&self) -> Result<(), SandboxError> {
        if self.availability.ready {
            Ok(())
        } else {
            Err(SandboxError::Unavailable {
                runtime: RuntimeKind::Firecracker,
                reason: self.availability.reason.clone(),
            })
        }
    }
}

#[async_trait]
impl SandboxRuntime for FirecrackerRuntime {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Firecracker
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            runtime: RuntimeKind::Firecracker,
            available: self.availability.ready,
            unavailable_reason: (!self.availability.ready)
                .then(|| self.availability.reason.clone()),
            filesystem: FilesystemAccess::IsolatedRoot,
            network: NetworkAccess::IsolatedNoEgress,
            arbitrary_python: true,
            shell: true,
            package_install: true,
            supports_cancellation: true,
            max_wall_clock_ms: 600_000,
            max_memory_bytes: (self.config.memory_mib as u64) * 1024 * 1024,
        }
    }

    async fn health(&self) -> RuntimeHealth {
        let availability = probe(&self.config);
        if availability.ready {
            RuntimeHealth::healthy()
        } else {
            RuntimeHealth::unavailable(availability.reason)
        }
    }

    async fn execute(
        &self,
        spec: SandboxSpec,
        cancel: CancellationToken,
    ) -> Result<SandboxResult, SandboxError> {
        self.require_available()?;

        let deadline = spec.limits.wall_clock;
        let started = std::time::Instant::now();

        let workspace = Workspace::create(&self.config.scratch_root, spec.execution_id)?;
        let cid = guest_cid(self.config.guest_cid_base, spec.execution_id);

        let mut vm = Vm::launch(&self.config, &workspace, cid).await?;

        // Boot the instance, then wait for the guest agent.
        let booted = async {
            configure(&self.config, &workspace, cid).await?;
            wait_for_agent(&workspace, deadline).await
        };

        let run = async {
            booted.await?;
            let request = AgentRequest {
                workload: spec.workload.clone(),
                stdin: String::from_utf8_lossy(&spec.stdin).into_owned(),
                env: forwarded_env(&self.config),
                max_output_bytes: spec.limits.max_output_bytes,
                max_artifacts_bytes: spec.limits.max_artifacts_bytes,
            };
            let response = call_agent(&workspace, &request, deadline).await?;
            Ok::<_, SandboxError>(response)
        };

        // Cancellation and wall-clock exhaustion are normal ends to a run, not
        // infrastructure failures: they must be reported as a result the broker
        // can persist as CANCELLED / TIMED_OUT.
        let outcome = tokio::select! {
            biased;
            _ = cancel.cancelled() => Outcome::Cancelled,
            result = tokio::time::timeout(deadline, run) => match result {
                Ok(Ok(response)) => Outcome::Response(response),
                Ok(Err(error)) => Outcome::Failed(error),
                Err(_) => Outcome::TimedOut,
            },
        };

        // Always stop the VM and reclaim the workspace, whatever happened.
        vm.shutdown().await;
        drop(workspace);

        let response = match outcome {
            Outcome::Response(response) => response,
            Outcome::Failed(error) => return Err(error),
            Outcome::Cancelled => {
                return Ok(SandboxResult {
                    termination: Termination::Cancelled,
                    exit_code: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    duration: started.elapsed(),
                    fuel_consumed: None,
                    memory_peak_bytes: None,
                    artifacts: Vec::new(),
                    failure: Some(SandboxFailure {
                        kind: FailureKind::Cancelled,
                        message: "execution was cancelled".into(),
                    }),
                });
            }
            Outcome::TimedOut => {
                return Ok(SandboxResult {
                    termination: Termination::TimedOut,
                    exit_code: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    duration: started.elapsed(),
                    fuel_consumed: None,
                    memory_peak_bytes: None,
                    artifacts: Vec::new(),
                    failure: Some(SandboxFailure {
                        kind: FailureKind::Timeout,
                        message: "guest exceeded its wall-clock budget".into(),
                    }),
                });
            }
        };

        let mut stdout = response.stdout.into_bytes();
        let mut stderr = response.stderr.into_bytes();
        let output_limit = spec.limits.max_output_bytes.min(usize::MAX as u64) as usize;
        let output_overflowed = stdout.len().saturating_add(stderr.len()) > output_limit;
        if output_overflowed {
            if stdout.len() > output_limit {
                stdout.truncate(output_limit);
                stderr.clear();
            } else {
                stderr.truncate(output_limit - stdout.len());
            }
        }

        let mut artifacts = Vec::with_capacity(response.artifacts.len());
        let mut artifact_bytes = 0u64;
        for artifact in response.artifacts {
            if artifact.name.is_empty()
                || artifact.name.len() > 256
                || Path::new(&artifact.name).is_absolute()
                || artifact
                    .name
                    .split(['/', '\\'])
                    .any(|part| part == ".." || part.is_empty())
                || artifact.size_bytes > spec.limits.max_artifacts_bytes
                || artifact_bytes.saturating_add(artifact.size_bytes)
                    > spec.limits.max_artifacts_bytes
            {
                return Err(SandboxError::Internal {
                    reason: "guest agent returned invalid artifact metadata".into(),
                });
            }
            artifact_bytes += artifact.size_bytes;
            artifacts.push(super::Artifact {
                name: artifact.name,
                size_bytes: artifact.size_bytes,
                sha256: artifact.sha256,
            });
        }

        Ok(SandboxResult {
            termination: if response.timed_out || output_overflowed {
                if response.timed_out {
                    Termination::TimedOut
                } else {
                    Termination::Failed
                }
            } else if response.exit_code == 0 {
                Termination::Completed
            } else {
                Termination::Failed
            },
            exit_code: Some(response.exit_code),
            stdout,
            stderr,
            duration: Duration::from_millis(response.duration_ms),
            fuel_consumed: None,
            memory_peak_bytes: response.memory_peak_bytes,
            artifacts,
            failure: if response.timed_out {
                Some(SandboxFailure {
                    kind: FailureKind::Timeout,
                    message: "guest exceeded its wall-clock budget".into(),
                })
            } else if output_overflowed {
                Some(SandboxFailure {
                    kind: FailureKind::OutputLimit,
                    message: "captured output exceeded its limit".into(),
                })
            } else if response.exit_code != 0 {
                Some(SandboxFailure {
                    kind: FailureKind::Trap,
                    message: format!("workload exited with status {}", response.exit_code),
                })
            } else {
                None
            },
        })
    }
}

/// Check every host prerequisite.
fn probe(config: &FirecrackerConfig) -> Availability {
    if let Err(reason) = config.validate() {
        return Availability {
            ready: false,
            reason,
        };
    }

    // KVM is mandatory: without it there is no microVM, only a slow emulator
    // that Firecracker does not support.
    let kvm = Path::new("/dev/kvm");
    if !kvm.exists() {
        return Availability {
            ready: false,
            reason: "/dev/kvm is missing; Firecracker requires KVM on the host".into(),
        };
    }
    if !is_read_write(kvm) {
        return Availability {
            ready: false,
            reason: "/dev/kvm is not readable and writable by this process".into(),
        };
    }

    for (label, path) in [
        ("firecracker binary", &config.binary),
        ("kernel image", &config.kernel_image),
        ("rootfs image", &config.rootfs_image),
    ] {
        if !path.exists() {
            return Availability {
                ready: false,
                reason: format!("{label} is missing at {}", path.display()),
            };
        }
    }

    Availability {
        ready: true,
        reason: "ready".into(),
    }
}

#[cfg(unix)]
fn is_read_write(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o600 == 0o600)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_read_write(_path: &Path) -> bool {
    false
}

/// Deterministic guest CID per execution.
fn guest_cid(base: u32, execution_id: Uuid) -> u32 {
    let bytes = execution_id.as_bytes();
    let offset = u16::from_be_bytes([bytes[0], bytes[1]]) as u32;
    base + offset
}

/// Environment forwarded to the guest: only names in the allowlist that exist in
/// the control plane's own environment. A request can never inject a value.
fn forwarded_env(config: &FirecrackerConfig) -> Vec<(String, String)> {
    config
        .env_allowlist
        .iter()
        .filter_map(|name| std::env::var(name).ok().map(|value| (name.clone(), value)))
        .collect()
}

/// Per-execution workspace holding the rootfs copy, API socket and logs.
struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn create(root: &Path, execution_id: Uuid) -> Result<Self, SandboxError> {
        let path = root.join(execution_id.to_string());
        std::fs::create_dir_all(&path).map_err(|err| SandboxError::Internal {
            reason: format!("could not create the microVM workspace: {err}"),
        })?;
        Ok(Self { path })
    }

    fn api_socket(&self) -> PathBuf {
        self.path.join("api.sock")
    }

    fn vsock_socket(&self) -> PathBuf {
        self.path.join("vsock.sock")
    }

    fn rootfs_copy(&self) -> PathBuf {
        self.path.join("rootfs.ext4")
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A running Firecracker process.
struct Vm {
    child: tokio::process::Child,
}

impl Vm {
    /// Spawn Firecracker with an API socket in the workspace.
    async fn launch(
        config: &FirecrackerConfig,
        workspace: &Workspace,
        _cid: u32,
    ) -> Result<Self, SandboxError> {
        // Never run against the pristine image: each VM gets a copy so a guest
        // cannot poison later executions.
        let source = &config.rootfs_image;
        let target = workspace.rootfs_copy();
        std::fs::copy(source, &target).map_err(|err| SandboxError::Internal {
            reason: format!("could not stage the rootfs image: {err}"),
        })?;

        let mut child = tokio::process::Command::new(&config.binary)
            .arg("--api-sock")
            .arg(workspace.api_socket())
            .arg("--id")
            .arg("agentic-execution")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| SandboxError::Internal {
                reason: format!("could not start firecracker: {err}"),
            })?;

        // Firecracker creates the socket shortly after start.
        let socket = workspace.api_socket();
        let deadline = tokio::time::Instant::now() + config.boot_timeout;
        while !socket.exists() {
            if tokio::time::Instant::now() >= deadline {
                let _ = child.kill().await;
                return Err(SandboxError::Internal {
                    reason: "firecracker API socket did not appear before the boot timeout".into(),
                });
            }
            // A process that died is not going to create one.
            if let Some(status) = child.try_wait().ok().flatten() {
                let _ = status;
                return Err(SandboxError::Internal {
                    reason: "firecracker exited before creating its API socket".into(),
                });
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        Ok(Self { child })
    }

    /// Terminate the VM. Idempotent and never fails: cleanup runs on error
    /// paths too.
    async fn shutdown(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

/// Apply the machine configuration and start the instance.
async fn configure(
    config: &FirecrackerConfig,
    workspace: &Workspace,
    cid: u32,
) -> Result<(), SandboxError> {
    let socket = workspace.api_socket();
    let timeout = config.api_timeout;

    // Order matters: boot source, drive, machine config, vsock, then start.
    api_put(
        &socket,
        timeout,
        "/boot-source",
        &serde_json::json!({
            "kernel_image_path": config.kernel_image,
            "boot_args": config.boot_args,
        }),
    )
    .await?;

    api_put(
        &socket,
        timeout,
        "/drives/rootfs",
        &serde_json::json!({
            "drive_id": "rootfs",
            "path_on_host": workspace.rootfs_copy(),
            "is_root_device": true,
            "is_read_only": false,
        }),
    )
    .await?;

    api_put(
        &socket,
        timeout,
        "/machine-config",
        &serde_json::json!({
            "vcpu_count": config.vcpu_count,
            "mem_size_mib": config.memory_mib,
            "smt": false,
        }),
    )
    .await?;

    api_put(
        &socket,
        timeout,
        "/vsock",
        &serde_json::json!({
            "guest_cid": cid,
            "uds_path": workspace.vsock_socket(),
        }),
    )
    .await?;

    api_put(
        &socket,
        timeout,
        "/actions",
        &serde_json::json!({ "action_type": "InstanceStart" }),
    )
    .await?;

    Ok(())
}

/// Wait until the guest agent accepts a vsock connection.
async fn wait_for_agent(workspace: &Workspace, budget: Duration) -> Result<(), SandboxError> {
    let deadline = tokio::time::Instant::now() + budget;
    let vsock = workspace.vsock_socket();

    while tokio::time::Instant::now() < deadline {
        if let Ok(stream) = connect_agent(&vsock).await {
            drop(stream);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(SandboxError::Internal {
        reason: "guest agent did not become reachable before the boot budget expired".into(),
    })
}

/// Connect to the guest agent through the Firecracker vsock proxy.
///
/// Firecracker multiplexes ports over one Unix socket with a text handshake:
/// `CONNECT <port>\n` and `OK <port>\n`.
async fn connect_agent(vsock: &Path) -> Result<tokio::net::UnixStream, std::io::Error> {
    let mut stream = tokio::net::UnixStream::connect(vsock).await?;
    stream
        .write_all(format!("CONNECT {GUEST_AGENT_PORT}\n").as_bytes())
        .await?;

    let mut acknowledgement = [0u8; 16];
    let read = stream.read(&mut acknowledgement).await?;
    let text = String::from_utf8_lossy(&acknowledgement[..read]);
    if !text.starts_with("OK") {
        return Err(std::io::Error::other("vsock handshake rejected"));
    }

    Ok(stream)
}

/// One execution request sent to the guest agent.
#[derive(Debug, Serialize)]
struct AgentRequest {
    workload: String,
    stdin: String,
    env: Vec<(String, String)>,
    max_output_bytes: u64,
    max_artifacts_bytes: u64,
}

/// One execution result returned by the guest agent.
#[derive(Debug, Deserialize)]
struct AgentResponse {
    exit_code: i32,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    #[serde(default)]
    timed_out: bool,
    #[serde(default)]
    duration_ms: u64,
    #[serde(default)]
    memory_peak_bytes: Option<u64>,
    #[serde(default)]
    artifacts: Vec<AgentArtifact>,
}

#[derive(Debug, Deserialize)]
struct AgentArtifact {
    name: String,
    size_bytes: u64,
    sha256: String,
}

async fn call_agent(
    workspace: &Workspace,
    request: &AgentRequest,
    budget: Duration,
) -> Result<AgentResponse, SandboxError> {
    let stream = connect_agent(&workspace.vsock_socket())
        .await
        .map_err(|err| SandboxError::Internal {
            reason: format!("could not reach the guest agent: {err}"),
        })?;

    let (mut reader, mut writer) = stream.into_split();

    let body = serde_json::to_vec(request).map_err(|err| SandboxError::Internal {
        reason: format!("could not encode the guest request: {err}"),
    })?;

    let framed = async {
        writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
        writer.write_all(&body).await?;
        writer.flush().await?;

        let mut length = [0u8; 4];
        reader.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length) as usize;
        if length > 64 * 1024 * 1024 {
            return Err(std::io::Error::other("guest response too large"));
        }
        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload).await?;
        Ok::<_, std::io::Error>(payload)
    };

    let payload = tokio::time::timeout(budget, framed)
        .await
        .map_err(|_| SandboxError::Internal {
            reason: "guest agent exceeded the wall-clock budget".into(),
        })?
        .map_err(|err| SandboxError::Internal {
            reason: format!("guest agent protocol error: {err}"),
        })?;

    serde_json::from_slice(&payload).map_err(|err| SandboxError::Internal {
        reason: format!("guest agent returned malformed JSON: {err}"),
    })
}

/// Minimal Firecracker API client: `PUT <path>` with a JSON body over the Unix
/// socket. Firecracker accepts one request per connection.
async fn api_put(
    socket: &Path,
    timeout: Duration,
    path: &str,
    body: &serde_json::Value,
) -> Result<(), SandboxError> {
    let call = async {
        let mut stream = tokio::net::UnixStream::connect(socket).await?;
        let payload = serde_json::to_vec(body).map_err(std::io::Error::other)?;

        let request = format!(
            "PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(&payload).await?;
        stream.flush().await?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let text = String::from_utf8_lossy(&response);
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);

        Ok::<_, std::io::Error>((status, text.into_owned()))
    };

    let (status, text) = tokio::time::timeout(timeout, call)
        .await
        .map_err(|_| SandboxError::Internal {
            reason: format!("firecracker API call to {path} timed out"),
        })?
        .map_err(|err| SandboxError::Internal {
            reason: format!("firecracker API call to {path} failed: {err}"),
        })?;

    if !(200..300).contains(&status) {
        // The body may contain host paths; keep only the status in the error.
        return Err(SandboxError::Internal {
            reason: format!("firecracker API call to {path} returned HTTP {status}"),
        });
    }

    let _ = text;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> FirecrackerConfig {
        FirecrackerConfig::default()
    }

    #[test]
    fn resource_validation_rejects_impossible_machines() {
        let mut bad = config();
        bad.vcpu_count = 0;
        assert!(bad.validate().is_err());

        let mut bad = config();
        bad.memory_mib = 32;
        assert!(bad.validate().is_err());

        let mut bad = config();
        bad.boot_args = "console=ttyS0\nreboot=k".into();
        assert!(bad.validate().is_err());

        assert!(config().validate().is_ok());
    }

    #[test]
    fn missing_kvm_makes_the_runtime_unavailable() {
        let runtime = FirecrackerRuntime::new(config());
        let capabilities = runtime.capabilities();

        // This development container has no /dev/kvm; the runtime must say so
        // rather than pretending to be ready.
        if !Path::new("/dev/kvm").exists() {
            assert!(!capabilities.available);
            let reason = capabilities.unavailable_reason.unwrap_or_default();
            assert!(reason.contains("/dev/kvm"), "reason: {reason}");
        }
    }

    #[tokio::test]
    async fn unavailable_runtime_refuses_to_execute() {
        let runtime = FirecrackerRuntime::new(config());
        if runtime.capabilities().available {
            return;
        }

        let spec = SandboxSpec {
            execution_id: Uuid::new_v4(),
            workload: "shell".into(),
            module: std::sync::Arc::new(Vec::new()),
            stdin: Vec::new(),
            env: Default::default(),
            limits: super::super::SandboxLimits {
                wall_clock: Duration::from_secs(1),
                cpu_fuel: 1,
                memory_bytes: 1024,
                max_output_bytes: 1024,
                max_artifacts_bytes: 1024,
            },
            scratch_root: None,
        };

        let error = runtime
            .execute(spec, CancellationToken::new())
            .await
            .expect_err("must refuse");
        assert!(matches!(
            error,
            SandboxError::Unavailable {
                runtime: RuntimeKind::Firecracker,
                ..
            }
        ));
    }

    #[test]
    fn guest_cids_are_deterministic_and_in_range() {
        let id = Uuid::new_v4();
        assert_eq!(guest_cid(16, id), guest_cid(16, id));
        assert!(guest_cid(16, id) >= 16);
        assert!(guest_cid(16, id) <= 16 + u16::MAX as u32);
    }

    #[test]
    fn env_forwarding_ignores_unknown_names() {
        let mut c = config();
        c.env_allowlist = vec!["AGENTIC_PATH_FORWARD_TEST".into()];
        assert!(forwarded_env(&c).is_empty());
    }
}
