"""Async TaskService client."""

from __future__ import annotations

from collections.abc import Mapping

import grpc

from app.gen.agentic.v1 import task_service_pb2, task_service_pb2_grpc


class TaskServiceClient:
    def __init__(self, target: str, *, token: str, secure: bool = False) -> None:
        self._token = token
        self._channel = (
            grpc.aio.secure_channel(target, grpc.ssl_channel_credentials())
            if secure
            else grpc.aio.insecure_channel(target)
        )
        self._stub = task_service_pb2_grpc.TaskServiceStub(self._channel)

    async def close(self) -> None:
        await self._channel.close()

    async def create_task(
        self,
        *,
        title: str,
        description: str,
        priority: int,
        assignee_id: str,
        tenant_id: str,
        actor_id: str,
        idempotency_key: str,
        due_date: object | None = None,
        timeout: float = 5.0,
    ) -> task_service_pb2.CreateTaskResponse:
        request = task_service_pb2.CreateTaskRequest(
            title=title,
            description=description,
            priority=priority,
            assignee_id=assignee_id,
        )
        if due_date is not None:
            request.due_date.CopyFrom(due_date)
        metadata: Mapping[str, str] = {
            "authorization": f"Bearer {self._token}",
            "x-tenant-id": tenant_id,
            "x-actor-id": actor_id,
            "x-idempotency-key": idempotency_key,
        }
        return await self._stub.CreateTask(
            request,
            timeout=timeout,
            metadata=tuple(metadata.items()),
        )
