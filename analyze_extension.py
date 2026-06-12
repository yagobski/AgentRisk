#!/usr/bin/env python3
"""Pooled analysis for the severity-balanced extension of the high-tension set.

Combines the original 12 high-tension scenarios (rho_S = 209) with the 24
severity-balanced extension scenarios (rho_S = 332) into a pooled 36-scenario
evaluation (rho_S = 541) and recomputes, per model:

  1. Extension-only and pooled summaries (ELR, WSL, RI, per-severity counts).
  2. Wilson 95% CIs per severity level (now including Level-1 and a usable
     Level-2 pool).
  3. Cochran-Armitage trend test across severity levels 1-4 (pooled).
  4. Pairwise Monte-Carlo sign-flip permutation tests on per-scenario WSL
     differences over the 36 pooled scenarios (fixed seed -> reproducible;
     the 2^36 sign assignments are too many to enumerate exactly).
  5. Bootstrap 95% percentile CIs for pooled RI (fixed seed).
  6. Stability summary across repeated sampled runs (temperature 0.7) if the
     stability result files are present.

Everything is recomputed from saved result JSONs; no numbers are invented.

Usage:
    python3 analyze_extension.py
Reads:  results/ht_both.json, results/ht_llama.json   (original, temp 0)
        results/hx_qwen.json, results/hx_gpt.json, results/hx_llama.json
        results/stab_run{1,2,3}_*.json                (optional, temp 0.7)
        data/privacy_scenarios_hightension.json
        data/privacy_scenarios_hightension_ext.json
"""

import json
import math
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
WEIGHTS = {1: 1, 2: 2, 3: 3, 4: 4}

MODELS = {
    "qwen": "qwen/qwen3-32b",
    "gpt": "openai/gpt-oss-120b",
    "llama": "meta-llama-3.1-8b-instruct",
}


def load_sev(*files):
    sev = {}
    for f in files:
        data = json.load(open(HERE / "data" / f))
        for sc in data["scenarios"]:
            for s in sc["secrets"]:
                sev[(sc["id"], s["id"])] = s["severity"]
    return sev


SEV = load_sev("privacy_scenarios_hightension.json",
               "privacy_scenarios_hightension_ext.json")


def rows_for(path, model_key):
    blob = json.load(open(RES / path))
    for mid, d in blob["models"].items():
        if mid == MODELS[model_key] or mid.replace("meta-llama-3.1-8b-instruct",
                                                   "llama-3.1-8b") == MODELS[model_key] \
           or MODELS[model_key].endswith(mid) or mid in MODELS[model_key]:
            return d["rows"]
    # fall back: single-model file
    vals = list(blob["models"].values())
    if len(vals) == 1:
        return vals[0]["rows"]
    raise KeyError(f"{MODELS[model_key]} not in {path}: {list(blob['models'])}")


def summarize(rows):
    tot = {1: 0, 2: 0, 3: 0, 4: 0}
    leak = {1: 0, 2: 0, 3: 0, 4: 0}
    wsl = rho = n = k = 0
    for r in rows:
        for sid_sec, leaked in r["leaks"].items():
            sv = SEV[(r["scenario_id"], sid_sec)]
            w = WEIGHTS[sv]
            tot[sv] += 1
            rho += w
            n += 1
            if leaked:
                leak[sv] += 1
                wsl += w
                k += 1
    return {
        "n_secrets": n, "n_leaked": k,
        "ELR": k / n if n else 0.0,
        "WSL": wsl, "rho": rho,
        "RI": wsl / rho if rho else 0.0,
        "per_sev": {sv: (leak[sv], tot[sv]) for sv in (1, 2, 3, 4)},
    }


def wilson(k, n, z=1.959963984540054):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (p, max(0.0, centre - half), min(1.0, centre + half))


def cochran_armitage(per_sev):
    """Trend test across severity levels with scores 1..4."""
    scores, ks, ns = [], [], []
    for sv in (1, 2, 3, 4):
        k, n = per_sev[sv]
        if n > 0:
            scores.append(sv)
            ks.append(k)
            ns.append(n)
    N = sum(ns)
    K = sum(ks)
    if N == 0 or K == 0 or K == N:
        return (0.0, 1.0)
    pbar = K / N
    sbar = sum(s * n for s, n in zip(scores, ns)) / N
    num = sum(s * k for s, k in zip(scores, ks)) - K * sbar
    var = pbar * (1 - pbar) * sum(n * (s - sbar) ** 2 for s, n in zip(scores, ns))
    z = num / math.sqrt(var)
    p = 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))
    return (z, p)


def per_scenario_wsl(rows):
    out = {}
    for r in rows:
        sid = r["scenario_id"]
        wsl = sum(WEIGHTS[SEV[(sid, k)]] for k, lk in r["leaks"].items() if lk)
        rho = sum(WEIGHTS[SEV[(sid, k)]] for k in r["leaks"])
        out[sid] = (wsl, rho)
    return out


def mc_permutation(diffs, n_iter=200000, seed=42):
    """Monte-Carlo two-sided sign-flip permutation test on paired diffs."""
    rng = random.Random(seed)
    obs = sum(diffs)
    n = len(diffs)
    count = 0
    for _ in range(n_iter):
        stat = sum(d if rng.random() < 0.5 else -d for d in diffs)
        if abs(stat) >= abs(obs) - 1e-12:
            count += 1
    return obs, (count + 1) / (n_iter + 1)  # add-one for validity


def bootstrap_ri(wsl_rho, n_boot=10000, seed=42):
    rng = random.Random(seed)
    items = list(wsl_rho.values())
    n = len(items)
    point = sum(w for w, _ in items) / sum(r for _, r in items)
    stats = []
    for _ in range(n_boot):
        sample = [items[rng.randrange(n)] for _ in range(n)]
        denom = sum(r for _, r in sample)
        stats.append(sum(w for w, _ in sample) / denom if denom else 0.0)
    stats.sort()
    return point, stats[int(0.025 * n_boot)], stats[int(0.975 * n_boot) - 1]


def fmt_sev(per_sev):
    return "  ".join(f"L{sv}:{k}/{n}" for sv, (k, n) in per_sev.items())


def main():
    orig = {
        "qwen": rows_for("ht_both.json", "qwen"),
        "gpt": rows_for("ht_both.json", "gpt"),
        "llama": rows_for("ht_llama.json", "llama"),
    }
    ext = {
        "qwen": rows_for("hx_qwen.json", "qwen"),
        "gpt": rows_for("hx_gpt.json", "gpt"),
        "llama": rows_for("hx_llama.json", "llama"),
    }

    pooled_rows = {m: orig[m] + ext[m] for m in MODELS}

    report = {}
    print("=" * 72)
    print("EXTENSION-ONLY (24 severity-balanced scenarios, temp 0)")
    print("=" * 72)
    for m in MODELS:
        s = summarize(ext[m])
        report[f"ext_{m}"] = s
        print(f"{MODELS[m]:<28} ELR={s['ELR']:.3f} RI={s['RI']:.3f} "
              f"WSL={s['WSL']}/{s['rho']}  {fmt_sev(s['per_sev'])}")

    print()
    print("=" * 72)
    print("POOLED (36 scenarios = 12 original + 24 extension, temp 0)")
    print("=" * 72)
    for m in MODELS:
        s = summarize(pooled_rows[m])
        report[f"pooled_{m}"] = s
        print(f"{MODELS[m]:<28} ELR={s['ELR']:.3f} RI={s['RI']:.3f} "
              f"WSL={s['WSL']}/{s['rho']}  {fmt_sev(s['per_sev'])}")
        for sv in (1, 2, 3, 4):
            k, n = s["per_sev"][sv]
            p, lo, hi = wilson(k, n)
            print(f"    L{sv}: {k}/{n} = {100*p:.1f}%  Wilson95 [{100*lo:.1f}, {100*hi:.1f}]")
        z, p = cochran_armitage(s["per_sev"])
        report[f"trend_{m}"] = {"z": z, "p": p}
        print(f"    Cochran-Armitage trend (L1-L4): z={z:.2f}  p={p:.4f}")

    print()
    print("=" * 72)
    print("PAIRWISE MC PERMUTATION (per-scenario WSL diffs, 36 pairs, seed 42)")
    print("=" * 72)
    ws = {m: per_scenario_wsl(pooled_rows[m]) for m in MODELS}
    sids = sorted(ws["qwen"])
    for a, b in (("qwen", "gpt"), ("qwen", "llama"), ("gpt", "llama")):
        diffs = [ws[a][s][0] - ws[b][s][0] for s in sids]
        obs, p = mc_permutation(diffs)
        report[f"perm_{a}_{b}"] = {"obs_diff_WSL": obs, "p": p}
        print(f"{MODELS[a]} vs {MODELS[b]}: sum dWSL={obs:+d}  p~{p:.4f}")

    print()
    print("=" * 72)
    print("BOOTSTRAP 95% CI for pooled RI (10k resamples, seed 42)")
    print("=" * 72)
    for m in MODELS:
        pt, lo, hi = bootstrap_ri(ws[m])
        report[f"boot_{m}"] = {"RI": pt, "lo": lo, "hi": hi}
        print(f"{MODELS[m]:<28} RI={pt:.3f}  [{lo:.3f}, {hi:.3f}]")

    # ---- optional stability runs --------------------------------------- #
    stab_files = sorted(RES.glob("stab_run*_*.json"))
    if stab_files:
        print()
        print("=" * 72)
        print("STABILITY (repeated sampled runs, temperature 0.7, pooled 36)")
        print("=" * 72)
        by_model = {m: [] for m in MODELS}
        for f in stab_files:
            blob = json.load(open(f))
            for mid, d in blob["models"].items():
                for m, full in MODELS.items():
                    if mid == full or mid in full or full.endswith(mid):
                        s = summarize(d["rows"])
                        by_model[m].append((f.name, s["RI"], s["per_sev"]))
        for m in MODELS:
            runs = by_model[m]
            if not runs:
                continue
            ris = [ri for _, ri, _ in runs]
            mean = sum(ris) / len(ris)
            print(f"{MODELS[m]:<28} runs={len(ris)} "
                  f"RI mean={mean:.3f} min={min(ris):.3f} max={max(ris):.3f}")
            for name, ri, ps in runs:
                print(f"    {name:<28} RI={ri:.3f}  {fmt_sev(ps)}")
            report[f"stab_{m}"] = {"runs": [(n, r) for n, r, _ in runs],
                                   "mean": mean, "min": min(ris), "max": max(ris)}

    out = RES / "extension_analysis.json"
    out.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nSaved -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
