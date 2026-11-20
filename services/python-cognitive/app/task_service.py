"""Async TaskService implementation.

The repository interface is intentionally injectable. Production deployments
should provide a Rust-backed repository; the in-memory implementation is for
local development and tests only.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import grpc
from google.protobuf.timestamp_pb2 import Timestamp

from app.gen.agentic.v1 import task_service_pb2, task_service_pb2_grpc

_TOKEN_KEY = "authorization"
_TENANT_KEY = "x-tenant-id"
_ACTOR_KEY = "x-actor-id"
_IDEMPOTENCY_KEY = "x-idempotency-key"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


@dataclass(frozen=True)
class TaskRecord:
    task_id: str
    tenant_id: str
    title: str
    description: str
    priority: int
    assignee_id: str
    created_at: datetime


class TaskRepository(Protocol):
    async def create(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
        title: str,
        description: str,
        priority: int,
        assignee_id: str,
        due_date: datetime | None,
    ) -> TaskRecord:
        """Create or return the existing task for the idempotency key."""


class InMemoryTaskRepository:
    """Non-durable repository for tests and local development."""

    def __init__(self) -> None:
        self._tasks: dict[tuple[str, str], TaskRecord] = {}
        self._lock = asyncio.Lock()

    async def create(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
        title: str,
        description: str,
        priority: int,
        assignee_id: str,
        due_date: datetime | None,
    ) -> TaskRecord:
        del due_date
        key = (tenant_id, idempotency_key)
        async with self._lock:
            existing = self._tasks.get(key)
            if existing is not None:
                return existing
            record = TaskRecord(
                task_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                title=title,
                description=description,
                priority=priority,
                assignee_id=assignee_id,
                created_at=datetime.now(UTC),
            )
            self._tasks[key] = record
            return record


def _metadata(context: grpc.aio.ServicerContext, key: str) -> str | None:
    for metadata_key, value in context.invocation_metadata():
        if metadata_key.lower() == key:
            return value
    return None


def _timestamp(value: datetime) -> Timestamp:
    result = Timestamp()
    result.FromDatetime(value)
    return result


def _parse_due_date(request: task_service_pb2.CreateTaskRequest) -> datetime | None:
    if not request.HasField("due_date"):
        return None
    return request.due_date.ToDatetime(tzinfo=UTC)


class TaskServiceServicer(task_service_pb2_grpc.TaskServiceServicer):
    def __init__(self, repository: TaskRepository, *, internal_token: str) -> None:
        if not internal_token:
            raise ValueError("internal_token is required")
        self._repository = repository
        self._internal_token = internal_token

    async def CreateTask(
        self,
        request: task_service_pb2.CreateTaskRequest,
        context: grpc.aio.ServicerContext,
    ) -> task_service_pb2.CreateTaskResponse:
        if _metadata(context, _TOKEN_KEY) != f"Bearer {self._internal_token}":
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid internal credentials")

        tenant_id = _metadata(context, _TENANT_KEY)
        actor_id = _metadata(context, _ACTOR_KEY)
        idempotency_key = _metadata(context, _IDEMPOTENCY_KEY)
        if not tenant_id or not _IDENTIFIER.fullmatch(tenant_id):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "invalid tenant metadata")
        if not actor_id or not _IDENTIFIER.fullmatch(actor_id):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "invalid actor metadata")
        if not idempotency_key or not _IDENTIFIER.fullmatch(idempotency_key):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "idempotency metadata is required")
        if not request.title.strip() or len(request.title) > 256:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "task title is required")
        if len(request.description) > 65_536:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "task description is too large")
        if request.priority == task_service_pb2.PRIORITY_UNSPECIFIED:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "priority is required")

        record = await self._repository.create(
            tenant_id=tenant_id,
            idempotency_key=idempotency_key,
            title=request.title,
            description=request.description,
            priority=request.priority,
            assignee_id=request.assignee_id,
            due_date=_parse_due_date(request),
        )
        return task_service_pb2.CreateTaskResponse(
            task_id=record.task_id,
            status="OPEN",
            created_at=_timestamp(record.created_at),
        )
