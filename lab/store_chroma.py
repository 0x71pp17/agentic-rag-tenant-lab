"""ChromaDB-backed store, implementing the same interface as `store.VectorStore`.

Why this file exists: the hand-written store in `store.py` is a real retrieval
implementation, but it is *mine*, so a reasonable reviewer will ask whether the
findings are artifacts of my own code. They are not. This adapter runs the same
attacks against a real vector database, and `tests/test_chroma_parity.py` asserts
that the results match.

One finding did NOT transfer verbatim, and saying so is more useful than a clean
parity claim:

  V2 (post-filter top-k)      transfers exactly.
  V4 (metadata mass assignment) transfers exactly.
  V1 (null-tenant fail-open)  does NOT transfer as written. Chroma fails *closed*
                              on a missing metadata key: a document with no
                              `tenant_id` is not returned by a
                              `where={"tenant_id": X}` filter.

The real-world shape of V1 in Chroma is therefore not null handling. It is the
`$or` clause developers write to get shared documents back:

    where={"$or": [{"tenant_id": tenant}, {"shared": True}]}

That clause is correct and necessary; company-wide policy documents do need to
reach every tenant. It becomes a fail-open the moment `shared` is a field a
caller can set, which is exactly what V4 provides. The two findings compose:
V4 is the write primitive and the `$or` is the read path.

This is worth internalising as a general point. The dangerous pattern is not a
missing check. It is a *deliberate, documented exception* to a check, combined
with a write path that lets an attacker qualify for the exception.

Install: `pip install chromadb` (optional; the core lab needs numpy alone).
"""

from __future__ import annotations

import uuid
from typing import Any

from .config import LabConfig
from .embeddings import Embedder, HashEmbedder
from .store import Chunk, RetrievalResult

# Chroma metadata values must be str/int/float/bool. `None` is not storable, so
# "no tenant" is represented by the key being absent, which is itself the reason
# V1 does not transfer verbatim.
SHARED_KEY = "shared"


class ChromaStore:
    """Drop-in replacement for `VectorStore`, backed by a real Chroma collection."""

    def __init__(
        self,
        embedder: Embedder | None = None,
        collection_name: str | None = None,
    ) -> None:
        import chromadb  # noqa: PLC0415 - optional dependency

        self.embedder: Embedder = embedder or HashEmbedder()
        self._client = chromadb.EphemeralClient()
        # Chroma requires 3-512 chars from [a-zA-Z0-9._-].
        name = collection_name or f"kb_{uuid.uuid4().hex[:12]}"
        self._col = self._client.create_collection(
            name=name, metadata={"hnsw:space": "cosine"}
        )
        self.chunks: list[Chunk] = []

    # ---- write path ------------------------------------------------------

    def add(self, chunk: Chunk) -> None:
        meta: dict[str, Any] = {}
        for k, v in chunk.metadata.items():
            if k == "tenant_id":
                continue
            if isinstance(v, (str, int, float, bool)):
                meta[k] = v

        tenant = chunk.tenant_id
        if tenant is not None:
            meta["tenant_id"] = tenant
        else:
            # No tenant. In a real deployment this is how a document becomes
            # "shared": it is published to everyone. The write path that lets a
            # caller reach this branch is the vulnerability (V4), not the branch.
            meta[SHARED_KEY] = True

        self._col.add(
            ids=[chunk.chunk_id],
            documents=[chunk.text],
            metadatas=[meta],
            embeddings=[self.embedder.embed(chunk.text).tolist()],
        )
        self.chunks.append(chunk)

    def add_all(self, chunks: list[Chunk]) -> None:
        for c in chunks:
            self.add(c)

    # ---- read path -------------------------------------------------------

    def _where(self, tenant_id: str, config: LabConfig) -> dict[str, Any]:
        if config.null_tenant_fail_open:
            # The clause developers actually write, so that company-wide policy
            # documents reach every tenant. Sound in isolation; a fail-open once
            # `shared` is caller-settable.
            return {"$or": [{"tenant_id": tenant_id}, {SHARED_KEY: True}]}
        return {"tenant_id": tenant_id}

    def query(
        self, query_text: str, tenant_id: str, config: LabConfig
    ) -> RetrievalResult:
        qv = self.embedder.embed(query_text).tolist()
        by_id = {c.chunk_id: c for c in self.chunks}

        if config.retrieval_filter_mode == "post":
            # V2: ask the database for the globally nearest neighbours with no
            # authorization predicate, then filter in the application. The
            # cross-tenant documents are transported to the app process before
            # being dropped, so the secret has already left the database.
            res = self._col.query(query_embeddings=[qv], n_results=config.top_k)
            ids = res["ids"][0]
            metas = res["metadatas"][0]

            kept: list[Chunk] = []
            starved = 0
            for cid, meta in zip(ids, metas):
                owner = meta.get("tenant_id")
                is_shared = bool(meta.get(SHARED_KEY, False))
                visible = owner == tenant_id or (
                    is_shared and config.null_tenant_fail_open
                )
                if visible:
                    if cid in by_id:
                        kept.append(by_id[cid])
                elif owner is not None and owner != tenant_id:
                    starved += 1

            return RetrievalResult(
                chunks=kept,
                considered=len(self.chunks),
                dropped_cross_tenant=len(ids) - len(kept),
                slots_consumed_by_other_tenants=starved,
            )

        # Correct ordering: the predicate goes to the database.
        res = self._col.query(
            query_embeddings=[qv],
            n_results=config.top_k,
            where=self._where(tenant_id, config),
        )
        ids = res["ids"][0]
        return RetrievalResult(
            chunks=[by_id[cid] for cid in ids if cid in by_id],
            considered=len(self.chunks),
            dropped_cross_tenant=0,
            slots_consumed_by_other_tenants=0,
        )
