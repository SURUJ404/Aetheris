from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID, uuid5

from qdrant_client import AsyncQdrantClient, models

from .models import MemorySearchHit

_POINT_NAMESPACE = UUID("6f58b2a1-6e9a-4bdb-93dc-9cf29c2ec3aa")


class QdrantMemoryStore:
    """Qdrant adapter suitable for a separately deployed microservice."""

    def __init__(
        self,
        client: AsyncQdrantClient,
        *,
        collection: str,
        vector_size: int,
    ) -> None:
        if not collection or vector_size < 8:
            raise ValueError("collection and vector_size are required")
        self._client = client
        self._collection = collection
        self._vector_size = vector_size

    async def ensure_collection(self) -> None:
        exists = await self._client.collection_exists(self._collection)
        if not exists:
            await self._client.create_collection(
                collection_name=self._collection,
                vectors_config=models.VectorParams(
                    size=self._vector_size,
                    distance=models.Distance.COSINE,
                ),
            )

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
        if any(len(vector) != self._vector_size for vector in vectors):
            raise ValueError("embedding dimensions do not match the collection")

        points = [
            models.PointStruct(
                id=str(uuid5(_POINT_NAMESPACE, f"{tenant_id}:{document_id}:{index}")),
                vector=list(vector),
                payload={
                    "tenant_id": tenant_id,
                    "principal_ids": sorted(principal_ids or {"*"}),
                    "document_id": str(document_id),
                    "source": source,
                    "text": text,
                    "metadata": {**metadata, "chunk_index": index},
                },
            )
            for index, (text, vector) in enumerate(zip(chunks, vectors, strict=True))
        ]
        await self._client.upsert(
            collection_name=self._collection,
            points=points,
            wait=True,
        )

    async def search(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        vector: Sequence[float],
        limit: int,
    ) -> list[MemorySearchHit]:
        if len(vector) != self._vector_size:
            raise ValueError("embedding dimension does not match the collection")

        tenant_filter = models.FieldCondition(
            key="tenant_id",
            match=models.MatchValue(value=tenant_id),
        )
        acl_filter = models.Filter(
            must=[
                tenant_filter,
            ],
            should=[
                models.FieldCondition(
                    key="principal_ids",
                    match=models.MatchValue(value=principal_id),
                ),
                models.FieldCondition(
                    key="principal_ids",
                    match=models.MatchValue(value="*"),
                ),
            ],
        )
        # `search` was removed in qdrant-client 1.12+; `query_points` is the
        # supported dense-vector API across the pinned 1.10/1.11 client line.
        response = await self._client.query_points(
            collection_name=self._collection,
            query=list(vector),
            query_filter=acl_filter,
            limit=limit,
            with_payload=True,
        )
        results = response.points
        hits: list[MemorySearchHit] = []
        for result in results:
            payload = result.payload or {}
            # The server-side filter above is the primary boundary. Re-check
            # every returned payload as well: a misconfigured collection, a
            # stale index or a backend defect must never leak another tenant's
            # text into the context assembled by the cognitive plane.
            hit_tenant = payload.get("tenant_id")
            hit_principals = payload.get("principal_ids")
            if hit_tenant != tenant_id or not isinstance(hit_principals, list):
                continue
            if principal_id not in hit_principals and "*" not in hit_principals:
                continue
            hits.append(
                MemorySearchHit(
                    document_id=UUID(str(payload["document_id"])),
                    tenant_id=str(payload["tenant_id"]),
                    text=str(payload["text"]),
                    source=str(payload["source"]),
                    score=float(result.score),
                    metadata=dict(payload.get("metadata") or {}),
                )
            )
        return hits
