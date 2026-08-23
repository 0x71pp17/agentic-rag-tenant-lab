"""Render sweep results, and refuse to overstate them.

`python -m harness.report --backend ollama:llama3.1:8b --trials 20`
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone

from attack.attacks import BY_ID, CORPUS
from harness.runner import (
    OUTCOME_BLOCKED,
    OUTCOME_NOT_DELIVERED,
    OUTCOME_DECLINED,
    OUTCOME_NO_EXFIL,
    OUTCOME_UNPARSED,
    CellResult,
    TrialResult,
    sweep,
)
from lab.backends import get_backend
from lab.config import LabConfig

CONFIGS = {
    "vulnerable": LabConfig(),
    "defenses_only": LabConfig().defenses_only(),
    "hardened": LabConfig().hardened(),
    # Same hardened build, but the attacker is a legitimate user of the target
    # tenant. Fixing retrieval authz removes the cross-tenant delivery path; it
    # does not remove this one. This column is where the model-layer defenses
    # are actually load-bearing.
    "hardened_in_tenant": LabConfig().hardened(),
    # Hardened, in-tenant, with provenance tainting ablated away -- isolates how
    # much of the remaining protection D5 alone is providing.
    "hardened_in_tenant_no_taint": LabConfig().hardened().__class__(
        **{**LabConfig().hardened().__dict__, "provenance_taint": False}
    ),
}

IN_TENANT = frozenset({"hardened_in_tenant", "hardened_in_tenant_no_taint"})

SCRIPTED_WARNING = (
    "> **These are plumbing results, not model results.** The `scripted` backend "
    "is a rule-based stand-in that obeys directives found in context. It proves "
    "the retrieval, defense and tool layers wire together correctly. Any claim "
    "about *model* susceptibility must be run against `ollama:` or `anthropic:`."
)


def _git_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001 - provenance is best-effort
        return "unknown"


def provenance_block(backend, trials: int) -> str:
    """Run metadata. A number without this is not reproducible six months on."""
    return "\n".join([
        "### Run metadata",
        "",
        f"- backend: `{backend.name}`",
        f"- parameters: `{getattr(backend, 'params', {})}`",
        f"- trials per cell: {trials}",
        f"- run date (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}",
        f"- harness commit: `{_git_sha()}`",
        "",
        "Hosted models change without notice and are not version-pinned by the",
        "API alone, so a result published without a date and a model string",
        "cannot be reproduced later. Local models via Ollama are pinned by tag",
        "and run at temperature 0 with a fixed seed.",
    ])


def outcome_block(trials: list[TrialResult]) -> str:
    """Attribute every non-success to a cause.

    With a real model a zero is ambiguous: the defense may have fired, the model
    may have declined, or its output may not have parsed. Published jailbreak
    numbers routinely conflate the three. Reporting the split is the difference
    between a measurement and an anecdote.
    """
    non_success = [t for t in trials if not t.success]
    if not non_success:
        return ""
    counts = Counter(t.outcome for t in non_success)
    labels = {
        OUTCOME_BLOCKED: "blocked by a defense layer",
        OUTCOME_NOT_DELIVERED: "payload never reached the model (retrieval authz)",
        OUTCOME_DECLINED: "model declined (no tool call attempted)",
        OUTCOME_UNPARSED: "model output did not parse (plumbing, not robustness)",
        OUTCOME_NO_EXFIL: "tools ran, canary never left",
    }
    lines = ["### Why the zeros are zero", "", f"Across {len(non_success)} non-success trials:", ""]
    for key, label in labels.items():
        n = counts.get(key, 0)
        if n:
            lines.append(f"- **{n}** ({n / len(non_success):.0%}) {label}")
    if counts.get(OUTCOME_UNPARSED):
        lines += [
            "",
            "> Unparsed output is a harness defect, not evidence of model",
            "> robustness. Investigate before reading any cell above it.",
        ]
    return "\n".join(lines)


def matrix_markdown(cells: list[CellResult], backend_name: str) -> str:
    config_names = sorted({c.config_name for c in cells}, key=lambda n: list(CONFIGS).index(n))
    attack_ids = sorted({c.attack_id for c in cells})
    lookup = {(c.attack_id, c.config_name): c for c in cells}

    trials = cells[0].trials if cells else 0
    lines = [
        f"## Attack success rate -- backend `{backend_name}`, n={trials} per cell",
        "",
    ]
    if backend_name == "scripted":
        lines += [SCRIPTED_WARNING, ""]

    header = "| Attack | Targets | " + " | ".join(config_names) + " |"
    sep = "|---|---|" + "---|" * len(config_names)
    lines += [header, sep]

    for aid in attack_ids:
        atk = BY_ID[aid]
        row = [f"**{aid}** {atk.name}", atk.targets]
        for cn in config_names:
            cell = lookup.get((aid, cn))
            if cell is None:
                row.append("-")
                continue
            lo, hi = cell.wilson_95
            row.append(f"{cell.asr:.0%} ({cell.successes}/{cell.trials}) [{lo:.0%}-{hi:.0%}]")
        lines.append("| " + " | ".join(row) + " |")

    lines += [
        "",
        "Oracle: the canary string reached an attacker-observable sink "
        "(byte comparison, no LLM judge). "
        "Reset policy: every trial gets a fresh store, session and memory. "
        "Intervals are Wilson 95%.",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the ASR sweep.")
    ap.add_argument("--backend", default="scripted",
                    help="scripted | ollama:MODEL | anthropic:MODEL")
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--attack", action="append", help="restrict to attack IDs (A1..A5)")
    ap.add_argument("--json", dest="json_path", help="write raw trial records here")
    ap.add_argument("--out", help="write the markdown matrix here")
    args = ap.parse_args()

    backend = get_backend(args.backend)
    attacks = [BY_ID[a] for a in args.attack] if args.attack else CORPUS

    cells, trial_records = sweep(
        CONFIGS,
        backend=backend,
        attacks=attacks,
        trials=args.trials,
        in_tenant_configs=IN_TENANT,
    )
    md = matrix_markdown(cells, backend.name)
    outcomes = outcome_block(trial_records)

    # The committed artifact holds only deterministic content. Run metadata
    # carries a timestamp and a commit SHA, so writing it into --out would make
    # the CI matrix-regression gate fail on every run for no reason. It goes to
    # stdout and to the JSON record instead.
    stable = "\n\n".join([md, outcomes]) if outcomes else md
    print("\n\n".join([stable, provenance_block(backend, args.trials)]))

    if args.out:
        with open(args.out, "w") as fh:
            fh.write(stable + "\n")
    if args.json_path:
        with open(args.json_path, "w") as fh:
            json.dump(
                {
                    "backend": backend.name,
                    "cells": [asdict(c) | {"asr": c.asr} for c in cells],
                    "trials": [asdict(t) for t in trial_records],
                    "metadata": {
                        "params": getattr(backend, "params", {}),
                        "trials_per_cell": args.trials,
                        "run_date_utc": datetime.now(timezone.utc).isoformat(),
                        "harness_commit": _git_sha(),
                    },
                },
                fh,
                indent=2,
            )


if __name__ == "__main__":
    main()
