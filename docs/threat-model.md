# Threat model

## System

A support-triage agent for a multi-tenant SaaS platform. Tenants `globex` and
`acme` share one vector store and one agent deployment. Tenant separation is a
property of metadata, not of infrastructure, which is the deployment shape
almost every RAG product ships, because per-tenant indexes are expensive.

## Actors

| Actor | Capability | Notes |
|---|---|---|
| Support engineer | Drives agent sessions scoped to one tenant | The confused deputy |
| Customer | Files tickets | **Untrusted write into the ingestion path** |
| Attacker (cross-tenant) | Legitimate user of `acme`, targets `globex` | Defeated by fixing retrieval authz |
| Attacker (in-tenant) | Legitimate user of `globex` | **Not** defeated by fixing retrieval authz |
| Agent | Retrieval, comment, fetch, memory read/write | Holds authority the customer does not |

The in-tenant attacker is the actor most threat models omit, and the reason the
results table carries in-tenant columns. Tenant isolation is a boundary between
customers; it is not a boundary between a customer and the agent serving them.

## Trust boundaries

```
   customer ticket ──┐
                     │  B1: untrusted write reaches the index
   confluence docs ──┼──► ingestion ──► chunks ──► vector store
                     │                     │
                     │                     │  B2: authz enforced on documents,
                     │                     │      model consumes chunks
                     │                     ▼
   engineer turn ────┴──────────────► retrieval ──► context ──► model
                                          │                       │
                                          │  B3: retrieved text   │  B4: model
                                          │      loses provenance │      output
                                          │                       │      drives
                                          ▼                       ▼      tools
                                     tool results ◄────────── tool calls
                                          │
                                          │  B5: tool output re-enters context
                                          │      without re-inspection
```

**B1** is the initial access. Anyone who can file a ticket can write into the
corpus the agent trusts. This is the precondition for every indirect-injection
finding here, and it is satisfied by design in any product with a support inbox,
a shared wiki, a public issue tracker, or a scraped source.

**B2** is V3. Authorization is enforced on the unit that has the metadata; the
model is fed the unit that does not.

**B3** is why D5 is the only control that works. Every other defense reasons
about what the text *says*. By the time text reaches the model, where it came
from has been discarded, so the only defenses left are ones that inspect
content, and content inspection is a losing game against an attacker who
controls the register.

**B4** is the agent's authority. Rate the finding by what the agent can *do*,
not by what it can be made to *say*.

**B5** is the seam A4 generalizes. Defenses run per turn on retrieved chunks.
Tool results and persisted memory are two additional ingress paths into the same
context that the per-turn classifier never inspects.

## Assets

| Asset | Impact if lost |
|---|---|
| Cross-tenant document contents | Confidentiality breach between customers; contractual and regulatory exposure |
| Credential references in runbooks | Lateral movement into the production cluster |
| Agent tool authority | Attacker-directed action under the engineer's identity |
| Agent memory | Persistence across sessions; survives the triage of the ticket that planted it |

## STRIDE, restricted to what is novel

Classic STRIDE over-generates here. The rows worth keeping are the ones where the
AI layer changes the analysis:

| | Where it lands | Finding |
|---|---|---|
| **Spoofing** | Caller-supplied `tenant_id` at ingest | V4 |
| **Tampering** | Poisoned document steers every future retrieval | A3 |
| **Repudiation** | Agent acts under the engineer's identity; the trace shows a normal triage | see `detection/` |
| **Information disclosure** | Cross-tenant read; canary via sanctioned channels | A2, A5 |
| **Denial of service** | Post-filter top-k starves a tenant's own results | V2 |
| **Elevation of privilege** | Customer-authored text acquires the agent's tool authority | A1, A3, A4 |

The last row is the one that matters. The elevation is not from user to admin.
It is from *text* to *authority*: a sentence written by a customer becomes an
action taken with the agent's privileges. Every AI-native finding in this lab is
a variation on it.

## Control planes

The findings sort into three planes, and a control in one plane cannot fix a
finding in another. This is the organizing claim of the lab and the results
table is the evidence for it.

| Plane | Controls | Fixes |
|---|---|---|
| Retrieval authorization | pre-filtering, metadata inheritance, server-owned authz fields | A2 |
| Content inspection | instruction hierarchy, injection classifier | A1 only |
| Provenance and capability | taint tracking, tool gating, human approval | A3, A4, A5 |

Content inspection is where most budget goes and it buys the least. It stops the
payload class that is already easy to stop.
