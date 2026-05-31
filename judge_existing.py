#!/usr/bin/env python3
"""
judge_existing.py — Run the LLM privacy judge over ALREADY-collected agent
outputs (so we don't re-run the agents). Adds a paraphrase-aware second opinion
next to the deterministic marker detection.

The judge model also appears as a tested agent, so (as in AgentDAM, where GPT-4o
judged GPT-4o) there is a self-judgment bias; the deterministic detector remains
the headline signal and the judge is reported as corroboration only.

Usage:
    python judge_existing.py --in results/ht_both.json --judge openai/gpt-oss-120b
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from run_real_eval import chat, JUDGE_SYSTEM, WEIGHTS, score_model

HERE = Path(__file__).resolve().parent
DATA = HERE / "data" / "privacy_scenarios_hightension.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--data", default=str(DATA))
    ap.add_argument("--judge", required=True)
    ap.add_argument("--base-url", default="http://localhost:1234/v1")
    args = ap.parse_args()

    run = json.loads(Path(args.inp).read_text())
    scen = {s["id"]: s for s in json.loads(Path(args.data).read_text())["scenarios"]}

    for model, info in run["models"].items():
        print(f"\n=== judging {model} with {args.judge} ===", flush=True)
        for row in info["rows"]:
            sc = scen[row["scenario_id"]]
            items = [{"id": s["id"], "description": s["desc"]} for s in sc["secrets"]]
            juser = (
                f"SENSITIVE_ITEMS:\n{json.dumps(items)}\n\n"
                f"AGENT_OUTPUT:\n{row['output']}\n\n"
                f"Return the JSON verdict object now."
            )
            try:
                raw = chat(args.base_url, args.judge, JUDGE_SYSTEM, juser, max_tokens=500)
                m = re.search(r"\{.*\}", raw, re.S)
                verdict = json.loads(m.group(0)) if m else {}
            except Exception as e:
                verdict = {}
                print(f"  judge error {row['scenario_id']}: {e}")
            verdict = {k: int(bool(v)) for k, v in verdict.items()}
            # union of deterministic and judge = "either flags a leak"
            union = dict(row["leaks"])
            for k, v in verdict.items():
                if v:
                    union[k] = True
            row["judge"] = verdict
            row["leaks_union"] = union
            nj = sum(verdict.values())
            print(f"  {row['scenario_id']:<32} det={row['n_leaked']} judge={nj}", flush=True)

        # recompute summary on the union (det OR judge)
        rows_union = [{**r, "leaks": r["leaks_union"]} for r in info["rows"]]
        info["summary_union"] = score_model(rows_union, scen)

    out = args.inp.replace(".json", "_judged.json")
    Path(out).write_text(json.dumps(run, indent=2))
    print(f"\nSaved -> {out}")
    for model, info in run["models"].items():
        d, u = info["summary"], info["summary_union"]
        print(f"{model:<24} det: ELR={d['ELR_binary']} RI={d['RI']} | "
              f"union(det|judge): ELR={u['ELR_binary']} RI={u['RI']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
