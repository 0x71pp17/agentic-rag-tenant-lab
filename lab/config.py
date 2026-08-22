"""Lab configuration.

Every vulnerability and every defense is an independently togglable flag. That is
the whole point: the measurement harness sweeps this config space and reports
attack success rate per cell, so we can say which mitigation actually holds
rather than asserting it.

`LabConfig.hardened()` is the configuration a competent team would ship. The
attacks in `attack/` are expected to be *defeated* by it in the baseline case;
the interesting results are the cells where they are not.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Literal

RetrievalFilterMode = Literal["pre", "post"]


@dataclass(frozen=True)
class LabConfig:
    # ---- Vulnerability toggles (retrieval / data layer) -------------------
    # V1: chunks whose tenant_id is None are treated as globally visible.
    # This is the "shared knowledge base" convenience that becomes a fail-open.
    null_tenant_fail_open: bool = True

    # V2: apply the tenant filter AFTER top-k selection instead of before.
    # Cross-tenant chunks consume result slots even when they are dropped,
    # which leaks their existence and starves the caller's own results.
    retrieval_filter_mode: RetrievalFilterMode = "post"

    # V3: chunk metadata is not inherited from the parent document, so every
    # chunk lands with tenant_id=None and flows into V1.
    chunk_metadata_inherit: bool = False

    # V4: the ingestion API merges caller-supplied metadata over server-derived
    # metadata, letting a caller set their own tenant_id (mass assignment).
    ingest_trusts_caller_metadata: bool = True

    # ---- Defense toggles (model / agent layer) ---------------------------
    # D1: retrieved content is delimited and explicitly framed as data.
    instruction_hierarchy: bool = False

    # D2: heuristic prompt-injection classifier over ingested chunk text.
    injection_classifier: bool = False

    # D3: egress domain allowlist on outbound tools.
    egress_allowlist: bool = False

    # D4: strict tool-argument schema/type/length validation.
    tool_arg_validation: bool = False

    # D5: provenance tainting. Chunks carry a taint flag; if any tainted chunk
    # reaches the context, side-effecting tools are withheld or gated.
    provenance_taint: bool = False

    # ---- Retrieval parameters -------------------------------------------
    top_k: int = 4

    allowed_egress_domains: tuple[str, ...] = (
        "corp.internal",
        "wiki.corp.internal",
        "status.corp.internal",
    )

    def hardened(self) -> "LabConfig":
        """The configuration a competent team would actually ship."""
        return replace(
            self,
            null_tenant_fail_open=False,
            retrieval_filter_mode="pre",
            chunk_metadata_inherit=True,
            ingest_trusts_caller_metadata=False,
            instruction_hierarchy=True,
            injection_classifier=True,
            egress_allowlist=True,
            tool_arg_validation=True,
            provenance_taint=True,
        )

    def defenses_only(self) -> "LabConfig":
        """Model-layer defenses on, data-layer bugs left in place.

        This is the most instructive cell in the matrix: it is what happens when
        a team hardens the prompt and the tools but never audits retrieval authz.
        """
        return replace(
            self,
            instruction_hierarchy=True,
            injection_classifier=True,
            egress_allowlist=True,
            tool_arg_validation=True,
            provenance_taint=False,
        )

    @property
    def enabled_defenses(self) -> tuple[str, ...]:
        names = (
            "instruction_hierarchy",
            "injection_classifier",
            "egress_allowlist",
            "tool_arg_validation",
            "provenance_taint",
        )
        return tuple(n for n in names if getattr(self, n))

    @property
    def enabled_vulns(self) -> tuple[str, ...]:
        out = []
        if self.null_tenant_fail_open:
            out.append("null_tenant_fail_open")
        if self.retrieval_filter_mode == "post":
            out.append("post_filter_topk")
        if not self.chunk_metadata_inherit:
            out.append("chunk_metadata_loss")
        if self.ingest_trusts_caller_metadata:
            out.append("metadata_mass_assignment")
        return tuple(out)


VULNERABLE = LabConfig()
HARDENED = LabConfig().hardened()
DEFENSES_ONLY = LabConfig().defenses_only()
