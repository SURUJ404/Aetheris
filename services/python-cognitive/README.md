# Python Cognitive Service

Responsibilities: context assembly, retrieval, planning, reasoning and evaluation.
Non-responsibilities: user authorization, budget authority, privileged tool execution,
or durable execution-state ownership.

The service receives authenticated internal gRPC requests from Rust and returns
structured proposals conforming to versioned protobuf contracts.

## Async TaskService gRPC

The TaskService contract is defined in
[`proto/agentic/v1/task_service.proto`](../../proto/agentic/v1/task_service.proto).
Python bindings are generated into `app/gen/` with:

```bash
python scripts/gen_proto.py
```

The async client uses `grpc.aio` and sends the bearer token, tenant, actor and
idempotency key through gRPC metadata:

```python
client = TaskServiceClient("localhost:50052", token=token)
response = await client.create_task(
    title="Example",
    description="Example task",
    priority=task_service_pb2.HIGH,
    assignee_id="user-42",
    tenant_id="tenant-1",
    actor_id="actor-1",
    idempotency_key="request-1",
)
await client.close()
```

Run the local async server with:

```bash
TASK_SERVICE_INTERNAL_TOKEN="replace-with-a-long-token" \
python -m app.task_server
```

Use `TASK_SERVICE_TLS_CERT` and `TASK_SERVICE_TLS_KEY` for TLS. Insecure
transport is intended only for local development; set
`TASK_SERVICE_ALLOW_INSECURE=false` in deployments that require TLS.

The included Python server uses an in-memory repository for tests and local
development only. In production, point [`TaskServiceClient`](app/task_client.py)
at the Rust control plane's `TASK_GRPC_BIND_ADDR`; Rust validates the JWT,
membership, `task:write` permission, idempotency and persists the task in
PostgreSQL.

## Memory

`app.memory` provides a backend-independent memory service. The production
adapter is [`QdrantMemoryStore`](app/memory/qdrant.py), which can connect to a
separately deployed Qdrant microservice using `qdrant-client`. The in-memory
adapter is intended for tests and local development.

Every write stores the tenant id and ACL principals in the vector payload.
Every search requires both a tenant id and principal id; the Qdrant filter
applies both before vector ranking. Empty ACLs represent tenant-visible
content. Callers must construct `MemoryQuery` from validated Rust context, not
from model-generated fields.

Embeddings are provided through `EmbeddingProvider`. The deterministic
embedder is only for tests and wiring; production deployments should provide a
versioned embedding provider with the same configured vector dimension.

Qdrant runs separately in local Compose on `127.0.0.1:6333` (HTTP) and
`127.0.0.1:6334` (gRPC), with persistent storage in the `qdrant-data` volume.
