"""Test suite.

Structured so each test maps to a claim the README makes. If a claim in the
README is not backed by a test here, it should not be in the README.
"""

from __future__ import annotations

import pytest

from attack.attacks import A1, A2, A3, A4, A5, BY_ID
from harness.runner import run_trial
from lab.backends import ScriptedBackend
from lab.config import LabConfig
from lab.corpus import ATTACKER_TENANT, CANARY, VICTIM_TENANT, build_store
from lab.defenses import classify_injection
from lab.ingest import ingest

VULN = LabConfig()
HARD = LabConfig().hardened()
DEF_ONLY = LabConfig().defenses_only()


# ---------------------------------------------------------------- safe path


def test_hardened_agent_still_works():
    """The hardened config must not break the product. A defense that returns
    no results for everyone is not a defense, it is an outage."""
    store = build_store(HARD)
    res = store.query("login failure mobile TOTP", VICTIM_TENANT, HARD)
    assert res.chunks, "hardened retrieval returned nothing for a legitimate query"
    assert any("globex" in c.doc_id for c in res.chunks)


def test_hardened_retrieval_is_tenant_scoped():
    store = build_store(HARD)
    res = store.query("login failure mobile", ATTACKER_TENANT, HARD)
    for c in res.chunks:
        assert c.tenant_id in (ATTACKER_TENANT,), f"leaked {c.chunk_id} to {ATTACKER_TENANT}"


def test_canary_never_reaches_attacker_under_hardened_retrieval():
    store = build_store(HARD)
    res = store.query("database failover credential reference", ATTACKER_TENANT, HARD)
    assert not any(CANARY in c.text for c in res.chunks)


# ------------------------------------------------------- retrieval findings


def test_v3_chunk_metadata_loss_drops_tenant():
    store = build_store(VULN)
    assert all(c.tenant_id is None for c in store.chunks), (
        "expected every chunk to lose tenant_id under chunk_metadata_inherit=False"
    )


def test_v3_plus_v1_leaks_victim_secret_to_attacker_tenant():
    """The headline finding: an attacker-tenant session reads the victim's secret."""
    store = build_store(VULN)
    res = store.query("database failover credential reference", ATTACKER_TENANT, VULN)
    assert any(CANARY in c.text for c in res.chunks), "expected cross-tenant read"


def test_v4_metadata_mass_assignment_sets_null_tenant():
    cfg = LabConfig(chunk_metadata_inherit=True, ingest_trusts_caller_metadata=True)
    store = build_store(cfg)
    doc = ingest(
        store,
        "attacker supplied document",
        tenant_id=ATTACKER_TENANT,
        config=cfg,
        caller_metadata={"tenant_id": None},
    )
    assert doc.tenant_id is None, "caller-supplied tenant_id should have won under V4"


def test_v4_fixed_ignores_caller_tenant():
    cfg = LabConfig(chunk_metadata_inherit=True, ingest_trusts_caller_metadata=False)
    store = build_store(cfg)
    doc = ingest(
        store,
        "attacker supplied document",
        tenant_id=ATTACKER_TENANT,
        config=cfg,
        caller_metadata={"tenant_id": None},
    )
    assert doc.tenant_id == ATTACKER_TENANT


def test_v2_post_filter_starves_result_slots():
    """Post-filtering leaks the existence of other tenants' documents by
    consuming result slots, even though no cross-tenant text is returned."""
    cfg = LabConfig(
        chunk_metadata_inherit=True,
        null_tenant_fail_open=False,
        retrieval_filter_mode="post",
        ingest_trusts_caller_metadata=False,
    )
    store = build_store(cfg)
    res = store.query("login failure mobile TOTP drift", ATTACKER_TENANT, cfg)
    assert res.slots_consumed_by_other_tenants > 0, (
        "expected cross-tenant chunks to consume top-k slots under post-filtering"
    )
    for c in res.chunks:
        assert c.tenant_id == ATTACKER_TENANT


# -------------------------------------------------------- classifier claims


def test_classifier_catches_imperative_override():
    v = classify_injection(A1.documents[0]["text"])
    assert v.blocked, f"A1 should be caught, scored {v.score} on {v.matched}"


def test_classifier_misses_declarative_payload():
    """The central claim of the lab: register, not intent, is what signatures see."""
    v = classify_injection(A3.documents[0]["text"])
    assert not v.blocked, (
        f"A3 was caught (score {v.score}, {v.matched}); the declarative-register "
        "claim in the README no longer holds and the finding must be rewritten"
    )


# ------------------------------------------------------------ attack claims


@pytest.mark.parametrize("attack", [A1, A2, A3, A4, A5], ids=lambda a: a.aid)
def test_every_attack_fails_against_hardened(attack):
    tr = run_trial(attack, HARD, "hardened", ScriptedBackend(), 0)
    assert not tr.success, (
        f"{attack.aid} succeeded against the hardened config via {tr.channels}"
    )


@pytest.mark.parametrize("attack", [A1, A2, A3, A4, A5], ids=lambda a: a.aid)
def test_every_attack_succeeds_against_vulnerable(attack):
    tr = run_trial(attack, VULN, "vulnerable", ScriptedBackend(), 0)
    assert tr.success, f"{attack.aid} failed against the fully vulnerable config"


def test_a1_control_is_blocked_by_defenses_only():
    """A1 is the control. If it survives model-layer defenses, the defenses are
    misconfigured and no other result in the matrix is interpretable."""
    tr = run_trial(A1, DEF_ONLY, "defenses_only", ScriptedBackend(), 0)
    assert not tr.success, "control attack A1 defeated the model-layer defenses"


def test_a2_is_immune_to_model_layer_defenses():
    """A retrieval authz bug does not care how good your prompt is."""
    tr = run_trial(A2, DEF_ONLY, "defenses_only", ScriptedBackend(), 0)
    assert tr.success, (
        "A2 was stopped by model-layer defenses, which would contradict the "
        "claim that retrieval authz is a separate control plane"
    )


def test_a5_exfiltrates_without_touching_a_blocked_domain():
    tr = run_trial(A5, DEF_ONLY, "defenses_only", ScriptedBackend(), 0)
    assert tr.success
    assert tr.channels, "expected at least one sanctioned channel to carry the canary"
