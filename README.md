# Agentic Platform — Structural Scaffold v1

This repository is an architectural scaffold for the target system:
- Rust control plane (authority, policy, execution lifecycle, tool broker)
- Python cognitive plane (planning, RAG, reasoning, ingestion)
- Isolated execution (Wasmtime first; Firecracker adapter later)
- Persistence and observability

**This is not production-ready implementation code.** Modules are intentionally skeletal.
Use OpenCode to inspect, implement and test one phase at a time. Do not replace existing
working functionality until the audit and migration plan are approved.

## Architectural invariants
1. Rust is the authority for identity, authorization, budgets, policy and execution state.
2. Python may propose plans/actions; it cannot authorize or directly execute privileged tools.
3. All tool execution passes through the Rust broker and a constrained runtime.
4. PostgreSQL is the durable source of truth for tasks, approvals and audit records.
5. Redis is ephemeral working state/cache, never the sole store for critical state.
6. Tenant and user boundaries are enforced before memory retrieval and tool execution.
7. Every request/task carries correlation and trace identifiers.
8. Human approval is bound to the exact action, arguments, tenant, actor, expiry and nonce.

## Suggested implementation sequence
1. Audit the current repository and map existing code against `ARCHITECTURE.md`.
2. Define versioned protobuf contracts in `proto/`.
3. Implement Rust control-plane skeleton and health/readiness endpoints.
4. Implement Python gRPC cognitive worker.
5. Add durable task state and idempotency.
6. Add Wasmtime execution profile and security tests.
7. Add memory integrations and tenant isolation.
8. Add Firecracker only when host infrastructure and threat model are ready.
9. Add end-to-end tracing, evaluation, load tests, backup/restore and deployment hardening.

## Implementation status

- Versioned protobuf contracts and generated Rust/Python bindings are in place.
- The Rust authority core provides provider-agnostic OIDC configuration,
  RS256/JWKS verification, tenant extraction, Postgres-backed principal
  resolution, deterministic policy evaluation, `/v1/me`, `/v1/session`, and
  `/v1/authorize`.
- Secure sandboxed execution is available through the Wasmtime path and the
  broker. Durable execution state, cancellation, recovery and the HTTP
  execution API are implemented and tested.
- Firecracker integration is implemented but requires `/dev/kvm`, a
  firecracker binary, a kernel image and a guest-agent rootfs on the host. It
  reports unavailable and refuses to execute when those prerequisites are
  missing; it never fakes isolation.
- Durable tasks and single-use approvals are implemented as a Rust-owned
  PostgreSQL task lifecycle with a tenant-scoped `/v1/tasks` API. Orchestration
  workers and Python proposal wiring remain future work.

Architecture decisions are recorded in `ARCHITECTURE.md` and `migration/adr/`.

## Endpoints

| Route | Auth | Purpose |
|---|---|---|
| `GET /health/live` | public | Process liveness |
| `GET /health/ready` | public | Readiness; probes PostgreSQL |
| `GET /v1/me` | Bearer JWT | Validated identity (no tenant or permissions) |
| `GET /v1/session` | Bearer JWT + membership | Tenant, role and effective permissions |
| `POST /v1/authorize` | Bearer JWT + membership | Allow/deny one action against the role's permissions |
| `POST /v1/executions` | Bearer JWT + `tool:invoke` | Submit an approved workload to an enabled runtime |
| `GET /v1/executions/{id}` | Bearer JWT + membership | Read one execution in the caller's tenant |
| `POST /v1/executions/{id}/cancel` | Bearer JWT + `tool:invoke` | Request cancellation of an execution |
| `POST /v1/tasks` | Bearer JWT + `task:write` | Create a task or approval-bound proposal |
| `GET /v1/tasks/{id}` | Bearer JWT + `task:read` | Read one task in the caller's tenant |
| `POST /v1/tasks/{id}/approve` | Bearer JWT + `tool:approve` | Approve a single-use approval |
| `POST /v1/tasks/{id}/execute` | Bearer JWT + `tool:invoke` | Dispatch an approved action through the broker; workload and stdin come from the approval |
| `POST /v1/tasks/{id}/cancel` | Bearer JWT + `task:write` | Cancel a non-terminal task |

Policy is deny-by-default RBAC: an action is allowed only when the resolved
membership role grants its exact permission. Unknown actions are a 400, not a
deny. `/v1/authorize` is advisory; the broker re-evaluates in-process before
dispatch, so a 200 is not an execution token. See
`migration/adr/0003-authorization-policy.md`.

## Execution

Rust is the only authority that can move a request into a sandbox. The flow is
fixed:

1. authenticate the bearer token and resolve the tenant membership;
2. authorize `tool.invoke` against the stored role permissions;
3. reject a runtime outside `EXECUTION_RUNTIMES`, a workload outside the
   approved manifest, or limits above the deployment ceilings;
4. persist a durable `CREATED` row (idempotent on
   `tenant + idempotency_key`);
5. drive `QUEUED -> AUTHORIZED -> STARTING -> RUNNING` with compare-and-set
   transitions, then dispatch to the runtime trait;
6. finish through `CLEANING_UP` into exactly one terminal state, recording exit
   status, failure, resource use, a digest of the output and artifact metadata.

Requests never carry identity, tenant, policy version, environment or arbitrary
module bytes. Workloads come from `EXECUTION_WORKLOAD_DIR/manifest.json`, whose
SHA-256 pins are verified at startup; a tampered module is a deployment error.

```powershell
# Submit (limits are required; every value must be at or below the ceiling)
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8081/v1/executions `
  -Headers @{ Authorization = "Bearer $token" } -ContentType application/json -Body (@{
    task_id = "task-1"
    runtime = "wasmtime"
    workload = "uppercase"
    stdin = "hello"
    idempotency_key = "demo-1"
    limits = @{
      wall_clock_ms = 5000
      cpu_fuel = 10000000
      memory_bytes = 16777216
      max_output_bytes = 65536
      max_stdin_bytes = 4096
      max_artifacts_bytes = 65536
    }
  } | ConvertTo-Json)
```

Wasmtime runs WASI preview 1 in-process with fuel, epoch-based wall-clock
interruption, a declared-memory ceiling, a bounded stdout/stderr capture, no
inherited environment and no network. A guest gets exactly one preopened
directory (`/scratch`) when `EXECUTION_WASMTIME_SCRATCH=true`; anything outside
it is denied by WASI path resolution, and the directory is removed after the
run.

Firecracker is implemented as a real adapter (probe, API client, vsock guest
agent client, VM lifecycle, cleanup). It refuses to execute unless `/dev/kvm`,
the binary, the kernel and the rootfs are all present, and the rootfs must ship
the guest agent at `/usr/local/bin/agent` on vsock port 52. There is no Docker
socket and no host filesystem in the guest. Host requirements are described in
`ARCHITECTURE.md`.

Execution state is durable in PostgreSQL (`executions` and an append-only
`execution_events` log). On startup the broker fails rows left in flight by the
previous process rather than leaving them `RUNNING` forever. Redis is not used
as execution state.


`BIND_ADDR` defaults to `127.0.0.1:8081`. Opening another port requires the
Keycloak client redirect URIs to be updated by re-running
`deploy/keycloak/bootstrap.ps1`.

## Local dependencies

PostgreSQL is the durable authorization store and is required at startup.

```powershell
docker compose -f agentic-platform-structure-v1/compose.yaml up -d
```

It listens on `127.0.0.1:55432` because host `5432` is often taken. The schema
is applied automatically when `DATABASE_MIGRATE=true` (the default). Values in
`.env.example` match this instance.

### OpenTelemetry Collector

The Compose stack includes OpenTelemetry Collector Contrib `0.98.0`. Copy
`.env.example` to `.env` and set `GRAFANA_CLOUD_OTLP_ENDPOINT`,
`GRAFANA_CLOUD_INSTANCE_ID`, and `GRAFANA_CLOUD_API_KEY` before starting the
stack. The collector accepts OTLP gRPC on `127.0.0.1:4317` and HTTP on
`127.0.0.1:4318`, then forwards traces, metrics, and logs through the
Grafana Cloud exporter configured in
`deploy/observability/otel-collector-config.yaml`.

The Rust control plane exports traces when `OTEL_EXPORTER_OTLP_ENDPOINT` is set
(the example defaults to `http://localhost:4317`) and identifies itself as
`rust-control-plane`. If the collector is unavailable, structured JSON logs
continue locally and startup does not fail.

Seed a development tenant and membership after Keycloak and PostgreSQL are up:

```powershell
./scripts/seed-dev.ps1
```

The script resolves the Keycloak `sub`, upserts the tenant/principal/membership,
and requires the container name `agentic-postgres`. Its `-Issuer` must match
`OIDC_ISSUER` as the control plane sees it.


## Local identity

Keycloak runs on `127.0.0.1:8080`; the control plane defaults to
`127.0.0.1:8081` (`BIND_ADDR`). Setup, verification and caveats:
`deploy/keycloak/README.md`. Decision records:
`migration/adr/0001-identity-provider.md` (Keycloak) and
`migration/adr/0002-authorization-state.md` (roles live in PostgreSQL, never in
token claims).

## Build and test

Rust (run from the parent workspace so `rust.ps1` is available):

```powershell
.\rust.ps1 cargo test --manifest-path /work/agentic-platform-structure-v1/Cargo.toml --all-targets
.\rust.ps1 --% cargo clippy --manifest-path /work/agentic-platform-structure-v1/Cargo.toml --all-targets -- -D warnings
.\rust.ps1 cargo fmt --manifest-path /work/agentic-platform-structure-v1/Cargo.toml --all
```

PostgreSQL integration tests are gated on `TEST_DATABASE_URL` and skipped when
it is unset. From inside the `rust.ps1` container the dev database is reachable
through the Docker host gateway:

```powershell
# Replace <local-dev-password> with the POSTGRES_PASSWORD you set for compose.
.\rust.ps1 bash -c 'cd /work/agentic-platform-structure-v1 && TEST_DATABASE_URL=postgresql://agentic:<local-dev-password>@host.docker.internal:55432/agentic cargo test -p rust-control-plane --test persistence --test execution_persistence'
```

If `host.docker.internal` resolves to an IPv6 address that the container cannot
route to (the symptom is `Network is unreachable` in the DB tests), use the
gateway address reported by `docker network inspect bridge` instead of the
hostname:

```powershell
# Replace <docker-host-gateway-ip> and <local-dev-password> with your local values.
.\rust.ps1 bash -c 'cd /work/agentic-platform-structure-v1 && TEST_DATABASE_URL=postgresql://agentic:<local-dev-password>@<docker-host-gateway-ip>:55432/agentic cargo test --all-targets'
```

Last verified run of that command: 121 Rust tests passed, 1 ignored (the
KVM-only Firecracker microVM test).

Execution tests:

- `tests/wasmtime_sandbox.rs` runs real WebAssembly (valid workload, invalid
  module, fuel, memory, timeout, filesystem escape, artifact collection and
  cleanup, network imports, output limit, cancellation). No privileges needed.
- `tests/execution_broker.rs` covers the authority boundary against a fake
  runtime (unauthorized, cross-tenant, runtime allowlist, limits, unknown
  workload, duplicates, cancellation, tenant concurrency, recovery).
- `tests/firecracker_sandbox.rs` covers the adapter and refusal path always; the
  real microVM test is `#[ignore]` and needs a KVM host plus
  `FIRECRACKER_BINARY`, `FIRECRACKER_KERNEL_IMAGE` and
  `FIRECRACKER_ROOTFS_IMAGE`. Run it explicitly with `cargo test --test
  firecracker_sandbox -- --ignored`.

End-to-end auth and resolution checks run in a container attached to the same
network as Keycloak and PostgreSQL. See `deploy/keycloak/README.md`.

Python bindings and tests (Docker, pinned Python):

```powershell
docker run --rm -v "$PWD:/work" -w /work python:3.12-slim bash -c "pip install -q grpcio-tools==1.74.0 pytest==8.3.4 && cd services/python-cognitive && python scripts/gen_proto.py && python -m pytest -q tests/test_proto_contract.py"
```

Contract rules and codegen details: `proto/README.md`.

## Do not do yet
- Do not introduce Neo4j, Ray, Dagster, PyO3 or local inference until a measured need exists.
- Do not expose Docker socket or host filesystem to agents.
- Do not allow model-generated tool arguments to bypass Rust schema/policy validation.
- Do not use floating `latest` image tags in production deployments.
## Step 5: durable tasks and approvals

The Rust control plane now exposes a PostgreSQL-backed task lifecycle at
`/v1/tasks`. Tasks are tenant-scoped and use compare-and-set transitions.
Optional proposals enter `WAITING_APPROVAL`; only a distinct principal with
`tool:approve` can grant the single-use, expiring approval. Exact tool
arguments are canonicalized and SHA-256 bound before approval.
`POST /v1/tasks/{id}/execute` is the approval-bound dispatch path: the broker
preflights the request, the approval is consumed atomically, and workload plus
stdin are read only from the stored approval. The direct `/v1/executions`
route remains available for operator-approved workloads and is not bound to a
task approval. See `ARCHITECTURE.md`.

