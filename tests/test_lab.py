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


# ------------------------------------------------- attacks pass for the RIGHT reason
#
# The ASR oracle only asks whether the canary reached an attacker-observable
# sink. It cannot tell whether an attack got there by the mechanism it claims.
# A4 previously passed while never touching memory at all: the tool-call parser
# could not handle nested JSON, so the scripted backend fell through to a URL
# heuristic and exfiltrated in turn 1. The headline result was unaffected, but
# the finding A4 documents was not being demonstrated.
#
# These tests assert the mechanism, not just the outcome.


def _run_session(attack, config):
    from lab.agent import Session
    store = build_store(config, extra=attack.documents)
    session = Session(
        store=store, config=config, backend=ScriptedBackend(),
        tenant_id=attack.session_tenant,
    )
    queries = list(attack.retrieval_queries) or [None] * len(attack.turns)
    while len(queries) < len(attack.turns):
        queries.append(None)
    for turn_text, rq in zip(attack.turns, queries):
        session.run_turn(turn_text, retrieval_query=rq)
    return session


def _tools(session, turn):
    return [c.get("tool") for c in session.traces[turn - 1].tool_calls]


def test_a4_actually_persists_to_memory_and_fires_in_a_later_turn():
    """A4 must land in turn 1 and act in turn 2, not exfiltrate immediately."""
    s = _run_session(A4, VULN)
    assert "write_memory" in _tools(s, 1), "A4 turn 1 did not write to memory"
    assert s.memory, "A4 left no persisted note"
    assert not s.observer.saw(CANARY) or "fetch_url" not in _tools(s, 1), (
        "A4 exfiltrated in turn 1; it is then not demonstrating persistence"
    )
    assert "fetch_url" in _tools(s, 2), "A4 turn 2 did not act on the stored note"
    assert s.observer.saw(CANARY), "A4 never exfiltrated the canary"


def test_a5_leaves_only_through_sanctioned_channels():
    """A5 must never contact a blocked host; the point is authorized egress."""
    s = _run_session(A5, VULN)
    channels = s.observer.channels_used(CANARY)
    assert channels, "A5 did not exfiltrate"
    for ev in s.observer.events:
        if CANARY in ev.payload or CANARY in ev.destination:
            assert "attacker.example" not in ev.destination, (
                f"A5 used a blocked destination {ev.destination!r}; it is then "
                "not demonstrating sanctioned-channel exfiltration"
            )


def test_tool_call_parser_handles_the_format_the_prompt_requests():
    """SYSTEM_PROMPT asks for {"tool": ..., "args": {...}}. Parse that shape."""
    from lab.backends import parse_tool_calls
    nested = '{"tool": "search_kb", "args": {"query": "database runbook"}}'
    assert parse_tool_calls(nested) == [
        {"tool": "search_kb", "args": {"query": "database runbook"}}
    ]
    fenced = '```json\n{"tool": "write_memory", "args": {"key": "k", "value": "v"}}\n```'
    assert parse_tool_calls(fenced), "fenced tool calls must parse; models emit them"


def test_system_prompt_example_is_not_executed_as_a_tool_call():
    """The prompt's worked example must not become a phantom call every turn."""
    from lab.agent import SYSTEM_PROMPT
    b = ScriptedBackend()
    resp = b.complete(SYSTEM_PROMPT, "Customer reports a login problem. Please triage.")
    assert resp.tool_calls == [], (
        f"scripted backend executed the prompt's own example: {resp.tool_calls}"
    )
