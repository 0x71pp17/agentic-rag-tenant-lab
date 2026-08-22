"""Vector store and retrieval.

This module holds the primary findings of the lab. All of them converge on a
single sink, `_visible()`, which decides whether a chunk may be shown to a given
tenant. Three independent upstream conditions can drive that sink to fail open:

  V1  null_tenant_fail_open   -- a chunk with tenant_id=None is treated as global
  V3  chunk_metadata_loss     -- chunking drops tenant_id, producing V1's input
  V4  metadata_mass_assignment -- the caller supplies tenant_id at ingest (ingest.py)

and one attacks the ordering rather than the predicate:

  V2  post_filter_topk        -- filter applied after top-k, not before

V2 is the subtle one. Filtering after selection is functionally "correct" in the
sense that no cross-tenant text is returned, which is why it survives review.
But cross-tenant chunks still consume result slots, so the number of results a
tenant gets back is a function of other tenants' data. That is an oracle: a
caller can confirm the existence and approximate content of another tenant's
documents without ever seeing them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from .config import LabConfig
from .embeddings import Embedder, HashEmbedder, cosine


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    vector: np.ndarray | None = None

    @property
    def tenant_id(self) -> str | None:
        return self.metadata.get("tenant_id")

    @property
    def source(self) -> str:
        return self.metadata.get("source", "unknown")

    @property
    def is_attacker_writable(self) -> bool:
        """Whether this chunk came from a source that accepts untrusted writes.

        Drives the provenance-taint defense (D5). In a real system this is the
        field almost nobody carries, which is precisely why indirect injection
        works: by the time text reaches the model, its origin is gone.
        """
        return bool(self.metadata.get("attacker_writable", False))


@dataclass
class RetrievalResult:
    chunks: list[Chunk]
    # Observability for the harness: what the filter actually did.
    considered: int = 0
    dropped_cross_tenant: int = 0
    slots_consumed_by_other_tenants: int = 0


class VectorStore:
    def __init__(self, embedder: Embedder | None = None) -> None:
        self.embedder: Embedder = embedder or HashEmbedder()
        self.chunks: list[Chunk] = []

    # ---- write path ------------------------------------------------------

    def add(self, chunk: Chunk) -> None:
        if chunk.vector is None:
            chunk.vector = self.embedder.embed(chunk.text)
        self.chunks.append(chunk)

    def add_all(self, chunks: list[Chunk]) -> None:
        for c in chunks:
            self.add(c)

    # ---- the authorization sink -----------------------------------------

    def _visible(self, chunk: Chunk, tenant_id: str, config: LabConfig) -> bool:
        """Single decision point for cross-tenant visibility."""
        chunk_tenant = chunk.tenant_id

        if chunk_tenant is None:
            # V1. The intent was "documents with no tenant are shared company
            # policy, everyone should see them". The effect is that any path
            # which loses or omits tenant_id yields a globally readable document.
            return bool(config.null_tenant_fail_open)

        return chunk_tenant == tenant_id

    # ---- read path -------------------------------------------------------

    def query(
        self,
        query_text: str,
        tenant_id: str,
        config: LabConfig,
    ) -> RetrievalResult:
        qv = self.embedder.embed(query_text)
        scored = sorted(
            ((cosine(qv, c.vector), c) for c in self.chunks if c.vector is not None),
            key=lambda pair: pair[0],
            reverse=True,
        )

        if config.retrieval_filter_mode == "post":
            # V2: select first, authorize second.
            window = scored[: config.top_k]
            kept = [c for _, c in window if self._visible(c, tenant_id, config)]
            starved = sum(
                1
                for _, c in window
                if c.tenant_id is not None and c.tenant_id != tenant_id
            )
            return RetrievalResult(
                chunks=kept,
                considered=len(scored),
                dropped_cross_tenant=len(window) - len(kept),
                slots_consumed_by_other_tenants=starved,
            )

        # Correct ordering: authorize first, then select.
        allowed = [c for _, c in scored if self._visible(c, tenant_id, config)]
        return RetrievalResult(
            chunks=allowed[: config.top_k],
            considered=len(scored),
            dropped_cross_tenant=0,
            slots_consumed_by_other_tenants=0,
        )
