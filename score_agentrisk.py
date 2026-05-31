#!/usr/bin/env python3
"""Severity composition of the AgentRisk scenario corpus.

Reproduces the "AgentRisk (ours)" row of the cross-corpus composition table
(Table tab:composition) directly from the released scenario files. This is a
corpus-composition analysis (what severity tier each author-assigned secret
sits at), NOT a model leakage-rate measurement.

Usage:
    python3 score_agentrisk.py
"""
import json
import os
from collections import Counter

WEIGHTS = {1: 1, 2: 2, 3: 3, 4: 4}
HERE = os.path.dirname(os.path.abspath(__file__))
FILES = [
    os.path.join(HERE, "data", "privacy_scenarios.json"),           # 29 low-tension
    os.path.join(HERE, "data", "privacy_scenarios_hightension.json"),  # 12 high-tension
]


def load_secrets(path):
    with open(path) as f:
        data = json.load(f)
    scenarios = data["scenarios"] if isinstance(data, dict) else data
    for sc in scenarios:
        for sec in sc.get("secrets", []):
            lvl = sec.get("severity", sec.get("level"))
            if lvl is not None:
                yield int(lvl)


def main():
    counts = Counter()
    n_scen = 0
    for path in FILES:
        with open(path) as f:
            data = json.load(f)
        scenarios = data["scenarios"] if isinstance(data, dict) else data
        n_scen += len(scenarios)
        for lvl in load_secrets(path):
            counts[lvl] += 1

    total = sum(counts.values())
    rho = sum(WEIGHTS[l] * counts[l] for l in counts)
    l12 = counts[1] + counts[2]
    l3 = counts[3]
    l4 = counts[4]

    print("AgentRisk Corpus Composition Analysis")
    print(f"  Scenarios: {n_scen}")
    print(f"  Secrets:   {total}")
    print(f"  L1: {counts[1]}  L2: {counts[2]}  L3: {l3}  L4: {l4}")
    print(f"  Grand WSL (rho_S): {rho}")
    print("  --- table row ---")
    print(
        f"  Secrets={total}  L1/L2%={100*l12/total:.1f}  "
        f"L3%={100*l3/total:.1f}  L4%={100*l4/total:.1f}  "
        f"Avg.Sev={rho/total:.2f}"
    )


if __name__ == "__main__":
    main()
