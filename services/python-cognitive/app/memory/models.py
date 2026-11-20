from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class MemoryDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: UUID = Field(default_factory=uuid4)
    tenant_id: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1, max_length=2_000_000)
    source: str = Field(min_length=1, max_length=512)
    acl_principals: frozenset[str] = frozenset()
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class MemoryQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    principal_id: str = Field(min_length=1, max_length=256)
    text: str = Field(min_length=1, max_length=32_000)
    limit: int = Field(default=5, ge=1, le=50)


class MemorySearchHit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: UUID
    tenant_id: str
    text: str
    source: str
    score: float
    metadata: dict[str, Any] = Field(default_factory=dict)
