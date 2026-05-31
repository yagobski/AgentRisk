#!/usr/bin/env python3
"""
analyze_decoupled.py — Decoupling analysis for the matched-pair experiment.

Each scenario pair shares one target secret presented under two task framings:
'peripheral' (the deliverable does not need it) and 'entangled' (a good
deliverable is tempted to weave it in). Holding the literal fact and its
severity fixed, the within-pair difference isolates the effect of
task-centrality. The script reports, per model:

  * the target-leak rate under each framing,
  * the paired 2x2 table (concordant / discordant pairs),
  * an exact two-sided McNemar test on the discordant pairs,
  * the peripheral-only leak rate broken down by severity tier
    (centrality held constant, so any residual trend reflects severity alone).

Stdlib only. Reads results/decoupled_results.json and the scenario file.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCEN = HERE / "data" / "privacy_scenarios_decoupled.json"
RES = HERE / "results" / "decoupled_results.json"


def mcnemar_exact_p(b: int, c: int) -> float:
    """Exact two-sided McNemar p-value from the two discordant counts."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) * (0.5 ** n)
    return min(1.0, 2.0 * tail)


def main() -> int:
    scen = {s["id"]: s for s in json.loads(SCEN.read_text())["scenarios"]}
    run = json.loads(RES.read_text())

    # Map each scenario to (pair, role, target_secret_id, severity).
    meta = {}
    for sid, s in scen.items():
        target = next(sec for sec in s["secrets"] if sec.get("target"))
        meta[sid] = (s["pair"], s["role"], target["id"], target["severity"])

    for model, blob in run["models"].items():
        leaks = {r["scenario_id"]: r["leaks"] for r in blob["rows"]}

        pairs: dict[str, dict[str, int]] = {}
        periph_by_sev: dict[int, list[int]] = {1: [], 2: [], 3: [], 4: []}
        for sid, (pair, role, tid, sev) in meta.items():
            hit = int(bool(leaks.get(sid, {}).get(tid)))
            pairs.setdefault(pair, {})[role] = hit
            if role == "peripheral":
                periph_by_sev[sev].append(hit)

        n_pairs = len(pairs)
        periph_rate = sum(p["peripheral"] for p in pairs.values()) / n_pairs
        entang_rate = sum(p["entangled"] for p in pairs.values()) / n_pairs

        # Paired 2x2: rows = peripheral 0/1, cols = entangled 0/1.
        a = sum(1 for p in pairs.values() if p["peripheral"] == 0 and p["entangled"] == 0)
        b = sum(1 for p in pairs.values() if p["peripheral"] == 0 and p["entangled"] == 1)
        c = sum(1 for p in pairs.values() if p["peripheral"] == 1 and p["entangled"] == 0)
        d = sum(1 for p in pairs.values() if p["peripheral"] == 1 and p["entangled"] == 1)
        p_val = mcnemar_exact_p(b, c)

        print(f"\n=== {model} ===")
        print(f"  pairs                     : {n_pairs}")
        print(f"  peripheral target-leak    : {sum(p['peripheral'] for p in pairs.values())}/{n_pairs} = {periph_rate:.3f}")
        print(f"  entangled  target-leak    : {sum(p['entangled'] for p in pairs.values())}/{n_pairs} = {entang_rate:.3f}")
        print(f"  paired table [a b / c d]  : [{a} {b} / {c} {d}]  (b=periph0->entangled1, c=periph1->entangled0)")
        print(f"  McNemar exact two-sided p : {p_val:.4f}")
        print(f"  peripheral leak by tier   :", {
            sev: f"{sum(v)}/{len(v)}" for sev, v in periph_by_sev.items() if v
        })

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
