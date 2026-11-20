# Target Architecture

```text
Clients
  |
  v
Rust Control Plane (Axum / Tokio / Tonic)
  |-- AuthN / AuthZ / tenant isolation
  |-- deterministic policy + schema + budget checks
  |-- durable task state machine + approvals
  |-- tool registry / execution broker
  |-- SSE / WebSocket streaming
  |
  +---- gRPC ----> Python Cognitive Service
  |                 |-- context assembly / RAG
  |                 |-- planning / reasoning / LangGraph
  |                 |-- ingestion / evaluation
  |
  +---- broker ---> Runtime Manager
                    |-- Wasmtime (restricted WASI tools)
                    |-- Firecracker adapter (untrusted OS workloads)
                    |
                    +-- approved workload registry (hash-pinned)
                    +-- durable execution state machine
  |
  +----> PostgreSQL (durable truth)
  +----> Redis (ephemeral working state)
  +----> Qdrant (vector retrieval)
  +----> Object storage (files/artifacts)
  +----> NATS JetStream (durable async events, when needed)

Observability: OpenTelemetry -> collector -> metrics/logs/traces backends
```

## Trust boundaries
- Client -> Rust: untrusted request.
- Rust -> Python: authenticated service request; Python output remains untrusted proposal.
- Rust -> runtime: only validated, authorized, bounded execution request.
- Runtime -> Rust: untrusted output; validate size, schema and provenance.
- Memory: enforce tenant/ACL filters before returning retrieved content.

## Execution boundary (Phase 3)

```text
authenticated request
  -> tenant membership (PostgreSQL)
  -> policy: tool.invoke
  -> runtime allowlist + approved workload + limits/ceilings
  -> executions row (CREATED, idempotent)
  -> QUEUED -> AUTHORIZED -> STARTING -> RUNNING   (compare-and-set)
  -> SandboxRuntime::execute(spec, cancellation)
  -> RUNNING -> CLEANING_UP -> terminal
  -> executions + execution_events (PostgreSQL)
```

Rules that hold across both runtimes:

- The broker depends on the `SandboxRuntime` trait only; configuration selects
  the concrete runtime. A request names a runtime, but only an enabled one is
  ever looked up.
- A `SandboxSpec` has no tenant, principal, policy version or free-form
  environment. The sandbox cannot widen its own permissions because it never
  receives an identity.
- Workloads are an approved, hash-pinned registry at startup. There is no
  arbitrary module upload path.
- Limits are rejected, never clamped. Deployment ceilings come from
  `ExecutionConfig`.
- Every execution has a cancellation token. A cancellation is persisted before
  it is signalled, and the runtime must stop within the wall-clock budget.
- A result describes what happened; it never authorizes a next step.

Per runtime:

| | Wasmtime | Firecracker |
|---|---|---|
| Isolation | In-process WASI p1, no threads, no shared memory | microVM with its own kernel |
| Filesystem | No preopens, or one `/scratch` directory removed afterwards | Isolated root filesystem |
| Network | No socket imports linked | NIC with no egress route |
| CPU | Wasmtime fuel + epoch interruption | Guest wall-clock budget |
| Memory | Declared-memory ceiling + store limiter | VM memory size |
| Output | Bounded capture, overflow fails the execution | Guest agent cap |
| Host prerequisite | None beyond the binary | `/dev/kvm`, firecracker, kernel, rootfs, guest agent |

