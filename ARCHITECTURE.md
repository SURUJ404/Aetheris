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
