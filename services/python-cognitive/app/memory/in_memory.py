from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from .models import MemorySearchHit


@dataclass(frozen=True)
class _Record:
    tenant_id: str
    principal_ids: frozenset[str]
    document_id: UUID
    source: str
    text: str
    vector: tuple[float, ...]
    metadata: dict


class InMemoryMemoryStore:
    """Small deterministic store for unit tests and local development."""

    def __init__(self) -> None:
        self._records: list[_Record] = []

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
        if len(chunks) != len(vectors):
            raise ValueError("chunk and vector counts must match")
        self._records = [
            record
            for record in self._records
            if record.document_id != document_id or record.tenant_id != tenant_id
        ]
        self._records.extend(
            _Record(
                tenant_id=tenant_id,
                principal_ids=principal_ids,
                document_id=document_id,
                source=source,
                text=text,
                vector=tuple(vector),
                metadata={**metadata, "chunk_index": index},
            )
            for index, (text, vector) in enumerate(zip(chunks, vectors, strict=True))
        )

    async def search(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        vector: Sequence[float],
        limit: int,
    ) -> list[MemorySearchHit]:
        visible = (
            record
            for record in self._records
            if record.tenant_id == tenant_id
            and (not record.principal_ids or principal_id in record.principal_ids)
        )
        ranked = sorted(
            ((self._cosine(vector, record.vector), record) for record in visible),
            key=lambda item: item[0],
            reverse=True,
        )
        return [
            MemorySearchHit(
                document_id=record.document_id,
                tenant_id=record.tenant_id,
                text=record.text,
                source=record.source,
                score=score,
                metadata=record.metadata,
            )
            for score, record in ranked[:limit]
        ]

    @staticmethod
    def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
        if len(left) != len(right):
            raise ValueError("embedding dimensions must match")
        denominator = math.sqrt(sum(value * value for value in left)) * math.sqrt(
            sum(value * value for value in right)
        )
        return 0.0 if denominator == 0 else sum(a * b for a, b in zip(left, right, strict=True)) / denominator
