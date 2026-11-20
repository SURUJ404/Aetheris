from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from .models import MemorySearchHit


class MemoryStore(Protocol):
    async def upsert(
        self,
        *,
        tenant_id: str,
        principal_ids: frozenset[str],
        document_id: UUID,
        source: str,
        chunks: Sequence[str],
        vectors: Sequence[Sequence[float]],
        metadata: dict,
    ) -> None:
        """Persist tenant-scoped chunks and their vectors."""

    async def search(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        vector: Sequence[float],
        limit: int,
    ) -> list[MemorySearchHit]:
        """Search only content visible to the supplied tenant and principal."""
