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
1. Audit current repository and map existing code to `migration/REPOSITORY_MAP.md`.
2. Define versioned protobuf contracts in `proto/`.
3. Implement Rust control-plane skeleton and health/readiness endpoints.
4. Implement Python gRPC cognitive worker.
5. Add durable task state and idempotency.
6. Add Wasmtime execution profile and security tests.
7. Add memory integrations and tenant isolation.
8. Add Firecracker only when host infrastructure and threat model are ready.
9. Add end-to-end tracing, evaluation, load tests, backup/restore and deployment hardening.

## Do not do yet
- Do not introduce Neo4j, Ray, Dagster, PyO3 or local inference until a measured need exists.
- Do not expose Docker socket or host filesystem to agents.
- Do not allow model-generated tool arguments to bypass Rust schema/policy validation.
- Do not use floating `latest` image tags in production deployments.
