from __future__ import annotations

from .chunking import chunk_text
from .embeddings import EmbeddingProvider
from .models import MemoryDocument, MemoryQuery, MemorySearchHit
from .store import MemoryStore


class MemoryService:
    def __init__(
        self,
        store: MemoryStore,
        embedder: EmbeddingProvider,
        *,
        chunk_size: int = 1_200,
        chunk_overlap: int = 120,
    ) -> None:
        self._store = store
        self._embedder = embedder
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap

    async def ingest(self, document: MemoryDocument) -> None:
        chunks = list(
            chunk_text(
                document.text,
                size=self._chunk_size,
                overlap=self._chunk_overlap,
            )
        )
        vectors = await self._embedder.embed(chunks)
        await self._store.upsert(
            tenant_id=document.tenant_id,
            principal_ids=document.acl_principals,
            document_id=document.document_id,
            source=document.source,
            chunks=chunks,
            vectors=vectors,
            metadata=document.metadata,
        )

    async def retrieve(self, query: MemoryQuery) -> list[MemorySearchHit]:
        vectors = await self._embedder.embed([query.text])
        return await self._store.search(
            tenant_id=query.tenant_id,
            principal_id=query.principal_id,
            vector=vectors[0],
            limit=query.limit,
        )
