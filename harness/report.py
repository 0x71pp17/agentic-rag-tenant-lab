"""Render sweep results, and refuse to overstate them.

`python -m harness.report --backend ollama:llama3.1:8b --trials 20`
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from attack.attacks import BY_ID, CORPUS
from harness.runner import CellResult, TrialResult, sweep
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

    cells, trials = sweep(
        CONFIGS,
        backend=backend,
        attacks=attacks,
        trials=args.trials,
        in_tenant_configs=IN_TENANT,
    )
    md = matrix_markdown(cells, backend.name)
    print(md)

    if args.out:
        with open(args.out, "w") as fh:
            fh.write(md + "\n")
    if args.json_path:
        with open(args.json_path, "w") as fh:
            json.dump(
                {
                    "backend": backend.name,
                    "cells": [asdict(c) | {"asr": c.asr} for c in cells],
                    "trials": [asdict(t) for t in trials],
                },
                fh,
                indent=2,
            )


if __name__ == "__main__":
    main()
