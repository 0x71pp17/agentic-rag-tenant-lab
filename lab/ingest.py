"""Ingestion: document -> chunks -> vector store.

Two findings live here, both upstream of the `store._visible()` sink.

V3 (chunk_metadata_loss): the chunker builds each chunk's metadata from a
field allowlist. `tenant_id` is not on it, because chunk metadata was designed
for retrieval display (title, source, section) and authorization was assumed to
happen "at the API layer". Every chunk therefore lands with tenant_id=None and
inherits V1's fail-open. This is the single most common way real multi-tenant
RAG pipelines lose their tenant boundary: the boundary is enforced on documents
and the model is fed chunks.

V4 (metadata_mass_assignment): the ingest API merges caller-supplied metadata
over server-derived metadata. A caller who can reach any ingestion path can set
`tenant_id: null` on their own document and make it globally retrievable.
OWASP API6:2023, wearing an AI costume.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from .config import LabConfig
from .store import Chunk, VectorStore

# Chunk metadata is built from this allowlist. Note what is missing.
CHUNK_METADATA_FIELDS = ("title", "source", "section", "attacker_writable")


@dataclass
class Document:
    doc_id: str
    text: str
    tenant_id: str | None
    metadata: dict[str, Any]


def chunk_text(text: str, size: int = 320, overlap: int = 48) -> list[str]:
    """Paragraph-aware splitter with character-window fallback."""
    paras = [p.strip() for p in text.split("\n\n") if p.strip()]
    out: list[str] = []
    buf = ""
    for p in paras:
        if len(buf) + len(p) + 2 <= size:
            buf = f"{buf}\n\n{p}" if buf else p
            continue
        if buf:
            out.append(buf)
        if len(p) <= size:
            buf = p
            continue
        step = max(1, size - overlap)
        for i in range(0, len(p), step):
            piece = p[i : i + size]
            if piece.strip():
                out.append(piece.strip())
        buf = ""
    if buf:
        out.append(buf)
    return out or [text.strip()]


def build_chunks(doc: Document, config: LabConfig) -> list[Chunk]:
    chunks: list[Chunk] = []
    for idx, piece in enumerate(chunk_text(doc.text)):
        meta: dict[str, Any] = {
            k: doc.metadata[k] for k in CHUNK_METADATA_FIELDS if k in doc.metadata
        }
        if config.chunk_metadata_inherit:
            # The fix: authorization metadata is propagated to every chunk,
            # because the chunk is the unit the model actually sees.
            meta["tenant_id"] = doc.tenant_id
        # else: V3. tenant_id never reaches the chunk.

        chunks.append(
            Chunk(
                chunk_id=f"{doc.doc_id}::{idx}",
                doc_id=doc.doc_id,
                text=piece,
                metadata=meta,
            )
        )
    return chunks


def ingest(
    store: VectorStore,
    text: str,
    *,
    tenant_id: str,
    config: LabConfig,
    caller_metadata: dict[str, Any] | None = None,
    doc_id: str | None = None,
    attacker_writable: bool = False,
) -> Document:
    """Ingest one document.

    `tenant_id` is the server-derived tenant (from the authenticated session).
    `caller_metadata` is whatever the client sent in the request body.
    """
    caller_metadata = dict(caller_metadata or {})
    doc_id = doc_id or f"doc-{uuid.uuid4().hex[:8]}"

    server_metadata: dict[str, Any] = {
        "source": "api",
        "attacker_writable": attacker_writable,
    }

    effective_tenant: str | None = tenant_id

    if config.ingest_trusts_caller_metadata:
        # V4. Caller metadata wins. `tenant_id` is a normal key in this dict,
        # so a client can null it out or claim someone else's.
        merged = {**server_metadata, **caller_metadata}
        if "tenant_id" in caller_metadata:
            effective_tenant = caller_metadata["tenant_id"]
    else:
        # The fix: server metadata wins, and authorization fields are stripped
        # from caller input entirely rather than merged and overridden.
        safe_caller = {
            k: v for k, v in caller_metadata.items() if k not in {"tenant_id"}
        }
        merged = {**safe_caller, **server_metadata}

    doc = Document(
        doc_id=doc_id,
        text=text,
        tenant_id=effective_tenant,
        metadata=merged,
    )
    store.add_all(build_chunks(doc, config))
    return doc


def ingest_many(
    store: VectorStore, docs: Iterable[dict[str, Any]], config: LabConfig
) -> list[Document]:
    return [
        ingest(
            store,
            d["text"],
            tenant_id=d["tenant_id"],
            config=config,
            caller_metadata=d.get("metadata"),
            doc_id=d.get("doc_id"),
            attacker_writable=d.get("attacker_writable", False),
        )
        for d in docs
    ]
