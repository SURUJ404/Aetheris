from uuid import uuid4

import pytest

from app.memory import DeterministicEmbedder, MemoryDocument, MemoryQuery, MemoryService
from app.memory.chunking import chunk_text
from app.memory.in_memory import InMemoryMemoryStore
from app.memory.qdrant import QdrantMemoryStore


def test_chunking_is_bounded_and_overlapping() -> None:
    chunks = list(chunk_text("abcdefghij", size=6, overlap=2))

    assert chunks == ["abcdef", "efghij"]


@pytest.mark.asyncio
async def test_retrieval_cannot_cross_tenants_or_acl_boundaries() -> None:
    service = MemoryService(InMemoryMemoryStore(), DeterministicEmbedder(32))
    allowed = MemoryDocument(
        tenant_id="tenant-a",
        source="allowed",
        text="private project alpha",
        acl_principals=frozenset({"principal-a"}),
    )
    other_principal = MemoryDocument(
        tenant_id="tenant-a",
        source="restricted",
        text="private project beta",
        acl_principals=frozenset({"principal-b"}),
    )
    other_tenant = MemoryDocument(
        tenant_id="tenant-b",
        source="cross-tenant",
        text="private project alpha",
    )
    for document in (allowed, other_principal, other_tenant):
        await service.ingest(document)

    results = await service.retrieve(
        MemoryQuery(
            tenant_id="tenant-a",
            principal_id="principal-a",
            text="private project alpha",
        )
    )

    assert results
    assert {hit.source for hit in results} == {"allowed"}


@pytest.mark.asyncio
async def test_document_upsert_replaces_existing_chunks() -> None:
    store = InMemoryMemoryStore()
    service = MemoryService(store, DeterministicEmbedder(32))
    document_id = uuid4()

    await service.ingest(
        MemoryDocument(
            document_id=document_id,
            tenant_id="tenant-a",
            source="source",
            text="old content",
        )
    )
    await service.ingest(
        MemoryDocument(
            document_id=document_id,
            tenant_id="tenant-a",
            source="source",
            text="new content",
        )
    )

    results = await service.retrieve(
        MemoryQuery(tenant_id="tenant-a", principal_id="principal-a", text="new content")
    )
    assert len(results) == 1
    assert results[0].text == "new content"


class _FakeQueryResponse:
    def __init__(self, points: list) -> None:
        self.points = points


class _FakeQdrantClient:
    def __init__(self, results: list | None = None) -> None:
        self.points = None
        self.query_filter = None
        self.results = results or []

    async def upsert(self, **kwargs):
        self.points = kwargs["points"]

    async def query_points(self, **kwargs):
        self.query_filter = kwargs["query_filter"]
        return _FakeQueryResponse(self.results)


class _FakeScoredPoint:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.score = 0.9


@pytest.mark.asyncio
async def test_qdrant_adapter_persists_acl_and_tenant_filter() -> None:
    client = _FakeQdrantClient()
    store = QdrantMemoryStore(client, collection="memory", vector_size=8)
    document_id = uuid4()

    await store.upsert(
        tenant_id="tenant-a",
        principal_ids=frozenset(),
        document_id=document_id,
        source="source",
        chunks=["public content"],
        vectors=[[1.0] + [0.0] * 7],
        metadata={},
    )
    await store.search(
        tenant_id="tenant-a",
        principal_id="principal-a",
        vector=[1.0] + [0.0] * 7,
        limit=5,
    )

    assert client.points[0].payload["tenant_id"] == "tenant-a"
    assert client.points[0].payload["principal_ids"] == ["*"]
    assert client.query_filter.must[0].match.value == "tenant-a"


@pytest.mark.asyncio
async def test_qdrant_adapter_drops_hits_that_fail_local_tenant_or_acl_check() -> None:
    def hit(tenant: str, principals: list[str], text: str) -> _FakeScoredPoint:
        return _FakeScoredPoint(
            {
                "tenant_id": tenant,
                "principal_ids": principals,
                "document_id": str(uuid4()),
                "text": text,
                "source": "source",
                "metadata": {},
            }
        )

    client = _FakeQdrantClient(
        [
            hit("tenant-a", ["principal-a"], "allowed"),
            hit("tenant-a", ["principal-b"], "other principal"),
            hit("tenant-b", ["principal-a"], "cross tenant"),
        ]
    )
    store = QdrantMemoryStore(client, collection="memory", vector_size=8)

    results = await store.search(
        tenant_id="tenant-a",
        principal_id="principal-a",
        vector=[1.0] + [0.0] * 7,
        limit=5,
    )

    assert [result.text for result in results] == ["allowed"]
