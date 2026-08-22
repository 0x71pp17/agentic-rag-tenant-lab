# Detection

Offensive AI research usually ships without this half. It is the half an
enterprise security team actually needs, because none of these attacks will be
prevented outright in a system that is already deployed.

Every signal below is derived from `TurnTrace` (`lab/agent.py`), which is the
telemetry a production agent should be emitting. If your agent does not log
these fields, none of this is detectable, and *that* is the first finding to
raise in a review.

## Required telemetry

| Field | Why |
|---|---|
| `retrieved_chunk_ids` + each chunk's `tenant_id` | The only way to catch cross-tenant retrieval |
| `blocked_chunk_ids` + classifier score | Blocks are the training signal for what is being attempted |
| `tainted` + taint sources | Distinguishes "agent acted" from "agent acted on attacker-writable input" |
| `tool_calls` with arguments | The action is the impact |
| Chunk `source` and `attacker_writable` | Provenance; almost never carried in practice |
| Memory reads and writes, with the turn that wrote them | A4 is invisible without write attribution |

## D1: cross-tenant retrieval

**Signal:** any retrieved chunk whose `tenant_id` differs from the session tenant,
or is null while the session tenant is not.

```
retrieved_chunk.tenant_id NOT IN (session.tenant_id)
```

Zero tolerance. There is no benign case in a correctly configured system, which
makes this the highest-quality rule here: it alerts on the bug itself rather than
on attacker behaviour. Alert on the first occurrence, not on a threshold.

**Catches:** A2, and the delivery step of A3/A4/A5 in the cross-tenant case.

## D2: secret egress through a sanctioned channel

**Signal:** a value matching a secret pattern (credential reference, key, canary)
appearing in a tool argument, where that value originated in retrieved content
rather than in the user turn.

```
tool_call.args CONTAINS secret_pattern
  AND secret_pattern IN retrieved_context
  AND secret_pattern NOT IN user_input
```

The provenance clause is what makes this work. Matching secret patterns in
outbound arguments alone is noisy; matching them *only when the agent introduced
them from retrieval* is not.

**Catches:** A5, and the terminal step of A1/A3.
**Note:** allowlisted destinations must not be excluded. A5 exists precisely
because the destination was authorized.

## D3: action on tainted context

**Signal:** a side-effecting tool call in a turn where `tainted == true`.

```
trace.tainted == true AND tool_call.name IN (post_comment, fetch_url, write_memory)
```

In a system running D5 this is already gated, so an occurrence means the gate
failed or was disabled. In a system not running D5, this is the highest-volume
rule here and should be tuned to alert on the tool set rather than every call.

**Catches:** A3, A5, and the write step of A4.

## D4: memory write attributable to retrieved content

**Signal:** a `write_memory` call in a turn where the retrieved context contained
attacker-writable chunks, especially where the stored value contains a URL or an
imperative.

```
tool_call.name == "write_memory"
  AND any(chunk.attacker_writable for chunk in retrieved)
```

**Catches:** A4 at plant time, the only point at which it is cheap to catch.
By the time it fires, the triggering turn looks like ordinary work.

## D5: delayed-trigger correlation

**Signal:** a memory value read in turn N whose content overlaps the retrieved
content of turn M < N, where turn M contained attacker-writable chunks.

This is the expensive rule and it requires retaining per-turn provenance across
the session. It is the only rule that catches A4 at fire time. Treat it as a
hunt query rather than a real-time alert.

## What is not detectable

Honest limits, since a detection section that claims full coverage is not useful:

- **A3 at plant time.** A declarative payload is textually indistinguishable from
  a legitimate runbook. There is no content signature; that is the whole finding.
  It is detectable only at the action stage (D2, D3).
- **Rank manipulation.** A payload engineered to out-rank legitimate documents
  produces no anomalous field. It would need retrieval-distribution baselining,
  which is out of scope here.
- **In-tenant attacker at retrieval.** D1 is silent by construction, because no
  boundary was crossed. Detection falls entirely to D2/D3.

## Sigma-style rule

See `detection/sigma/` for a drafted rule covering D1, the highest-fidelity
signal. The others are written as hunt queries rather than rules because their
false-positive profile depends on the deployment.
