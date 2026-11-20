# Deployment scaffold

Add pinned, reviewed Compose/Kubernetes manifests here after service boundaries are stable.
Production deployment must include secret management, network policies, non-root containers,
resource requests/limits, health checks, backup/restore procedures and image scanning.
Do not publish database/cache/admin ports publicly by default.

## Firecracker hosts

The Firecracker runtime is only usable on hosts that satisfy all of the
following. The control plane probes them at startup and on every health check;
when any is missing the runtime reports unavailable and refuses to execute
rather than faking a result.

| Requirement | Detail |
|---|---|
| Linux + KVM | `/dev/kvm` exists and is readable/writable by the control-plane user. Firecracker has no emulation fallback. |
| Nested virtualisation | If the control plane runs in a VM, the host must expose nested KVM. Most cloud "container" runtimes do not. |
| Firecracker binary | Pinned v1.x at `FIRECRACKER_BINARY`, executable. |
| Kernel image | Uncompressed `vmlinux` at `FIRECRACKER_KERNEL_IMAGE`, built with virtio and vsock support. |
| Rootfs image | ext4 at `FIRECRACKER_ROOTFS_IMAGE`, containing `/usr/local/bin/agent` (the guest agent) and the approved workload commands. |
| Guest agent | Listens on vsock port 52, accepts the control-plane request JSON over a Unix socket bridged to vsock, and reports stdout/stderr/exit status/artifacts. |
| Networking | No TAP device and no egress route are configured for guests. If egress is ever required it must be an explicit, reviewed deny-by-default policy. |
| Privileges | Root (or equivalent) to create the API socket, tap-less vsock device and mount the rootfs. This is why Firecracker must not be enabled on a developer laptop. |

Deliberately absent: no Docker socket, no host filesystem in the guest, no
shared kernel with the control plane, and no container escape surface shared
with the broker.

The `kvm_boots_a_microvm_and_runs_an_approved_workload` test is `#[ignore]` and
is the acceptance check for a new host:

```powershell
.\rust.ps1 bash -c 'cd /work/agentic-platform-structure-v1/services/rust-control-plane && FIRECRACKER_BINARY=/usr/local/bin/firecracker FIRECRACKER_KERNEL_IMAGE=/var/lib/agentic/vmlinux.bin FIRECRACKER_ROOTFS_IMAGE=/var/lib/agentic/rootfs.ext4 cargo test --test firecracker_sandbox -- --ignored'
```

