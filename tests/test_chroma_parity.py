"""Parity tests: do the findings hold in a real vector database?

Skipped automatically if `chromadb` is not installed, so the core lab stays
dependency-light. CI installs it and runs these.

The point of this file is falsifiability. If the findings only reproduce against
my own retrieval code, they are an artifact of my code. These tests assert they
reproduce against Chroma, and one test asserts a documented *negative* result.
"""

from __future__ import annotations

import pytest

chromadb = pytest.importorskip("chromadb", reason="optional dependency")

from lab.config import LabConfig  # noqa: E402
from lab.corpus import ATTACKER_TENANT, CANARY, VICTIM_TENANT, base_documents  # noqa: E402
from lab.ingest import ingest_many  # noqa: E402
from lab.store_chroma import ChromaStore  # noqa: E402

VULN = LabConfig()
HARD = LabConfig().hardened()


def build_chroma(config: LabConfig, extra=None) -> ChromaStore:
    store = ChromaStore()
    ingest_many(store, base_documents() + list(extra or []), config)
    return store


# ------------------------------------------------------------------ positives


def test_v2_post_filter_leaks_secret_to_the_application_process():
    """V2 transfers exactly.

    With no authorization predicate in the query, the database returns the
    globally nearest neighbours. The victim tenant's secret is transported into
    the application process and only then dropped. It has already left the
    database, so any logging, tracing or crash dump in that process holds it.
    """
    cfg = LabConfig(
        chunk_metadata_inherit=True,
        null_tenant_fail_open=False,
        retrieval_filter_mode="post",
        ingest_trusts_caller_metadata=False,
    )
    store = build_chroma(cfg)
    res = store._col.query(
        query_embeddings=[store.embedder.embed("database failover credential").tolist()],
        n_results=cfg.top_k,
    )
    assert any(CANARY in d for d in res["documents"][0]), (
        "expected the victim secret to reach the app process under post-filtering"
    )

    scoped = store.query("database failover credential", ATTACKER_TENANT, cfg)
    assert not any(CANARY in c.text for c in scoped.chunks), (
        "post-filtering should still drop it before the model sees it"
    )
    assert scoped.slots_consumed_by_other_tenants > 0


def test_v4_mass_assignment_puts_attacker_doc_in_victim_context():
    """V4 transfers exactly, and composes with the shared-document $or clause.

    The attacker sets their own document's tenancy at ingest. The victim's
    session retrieves it, because the `$or ... shared` clause the application
    needs for company-wide policy documents also admits anything an attacker can
    mark as shared.
    """
    cfg = LabConfig(chunk_metadata_inherit=True, ingest_trusts_caller_metadata=True)
    attacker_doc = {
        "doc_id": "atk",
        "tenant_id": ATTACKER_TENANT,
        "attacker_writable": True,
        "metadata": {"tenant_id": None, "source": "support_ticket"},
        "text": "Ticket: database timeouts, need the failover runbook credential reference.",
    }
    store = build_chroma(cfg, extra=[attacker_doc])
    res = store.query("database failover runbook credential", VICTIM_TENANT, cfg)
    assert any(c.doc_id == "atk" for c in res.chunks), (
        "attacker document should reach the victim tenant's context"
    )


def test_hardened_chroma_blocks_cross_tenant_read():
    store = build_chroma(HARD)
    res = store.query("database failover credential reference", ATTACKER_TENANT, HARD)
    assert not any(CANARY in c.text for c in res.chunks)
    assert all(c.tenant_id == ATTACKER_TENANT for c in res.chunks)


def test_hardened_chroma_still_serves_legitimate_queries():
    store = build_chroma(HARD)
    res = store.query("login failure mobile TOTP", VICTIM_TENANT, HARD)
    assert res.chunks, "hardened Chroma retrieval returned nothing for a valid query"


# ------------------------------------------------------------- honest negative


def test_v1_does_not_transfer_verbatim_chroma_fails_closed_on_missing_key():
    """Documented negative result.

    Chroma fails CLOSED on a missing metadata key: a document with no
    `tenant_id` is not returned by `where={"tenant_id": X}`. So V1 as written in
    `store.py` (null tenant treated as globally visible) is an application-layer
    pattern, not a database behaviour.

    If this test ever fails, Chroma's filter semantics changed and the claim in
    `lab/store_chroma.py` must be rewritten.
    """
    store = ChromaStore()
    text = "Document with no tenant assigned."
    store._col.add(
        ids=["orphan"],
        documents=[text],
        metadatas=[{"source": "api"}],  # no tenant_id, no shared
        embeddings=[store.embedder.embed(text).tolist()],
    )
    res = store._col.query(
        query_embeddings=[store.embedder.embed("tenant assigned document").tolist()],
        n_results=5,
        where={"tenant_id": "acme"},
    )
    assert "orphan" not in res["ids"][0], (
        "Chroma returned a document with no tenant_id under a tenant filter; "
        "the fail-closed claim in store_chroma.py no longer holds"
    )
