from __future__ import annotations

import grpc
import pytest
import pytest_asyncio

from app.gen.agentic.v1 import task_service_pb2, task_service_pb2_grpc
from app.task_client import TaskServiceClient
from app.task_service import InMemoryTaskRepository, TaskServiceServicer


@pytest_asyncio.fixture
async def task_server() -> tuple[str, str]:
    token = "internal-token-for-tests"
    server = grpc.aio.server()
    task_service_pb2_grpc.add_TaskServiceServicer_to_server(
        TaskServiceServicer(InMemoryTaskRepository(), internal_token=token),
        server,
    )
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        yield f"127.0.0.1:{port}", token
    finally:
        await server.stop(0)


@pytest.mark.asyncio
async def test_async_client_creates_task_with_metadata(task_server) -> None:
    target, token = task_server
    client = TaskServiceClient(target, token=token)
    try:
        response = await client.create_task(
            title="Migrate authentication service",
            description="Switch internal calls to gRPC.",
            priority=task_service_pb2.HIGH,
            assignee_id="user-42",
            tenant_id="tenant-1",
            actor_id="actor-1",
            idempotency_key="request-1",
        )
    finally:
        await client.close()

    assert response.task_id
    assert response.status == "OPEN"
    assert response.created_at.IsInitialized()


@pytest.mark.asyncio
async def test_invalid_metadata_is_rejected(task_server) -> None:
    target, token = task_server
    async with grpc.aio.insecure_channel(target) as channel:
        stub = task_service_pb2_grpc.TaskServiceStub(channel)
        with pytest.raises(grpc.aio.AioRpcError) as error:
            await stub.CreateTask(
                task_service_pb2.CreateTaskRequest(
                    title="Task",
                    priority=task_service_pb2.LOW,
                ),
                metadata=(("authorization", f"Bearer {token}"),),
            )

    assert error.value.code() == grpc.StatusCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_idempotency_returns_same_task(task_server) -> None:
    target, token = task_server
    client = TaskServiceClient(target, token=token)
    kwargs = {
        "title": "Repeat safely",
        "description": "Same request",
        "priority": task_service_pb2.MEDIUM,
        "assignee_id": "user-42",
        "tenant_id": "tenant-1",
        "actor_id": "actor-1",
        "idempotency_key": "same-request",
    }
    try:
        first = await client.create_task(**kwargs)
        second = await client.create_task(**kwargs)
    finally:
        await client.close()

    assert first.task_id == second.task_id
