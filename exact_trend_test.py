#!/usr/bin/env python3
"""Exact (conditional permutation) Cochran--Armitage trend test for the
per-severity-level leak counts of the 12 high-tension scenarios.

Motivation: at these small per-level counts (Level-2 has only 3 secrets) the
asymptotic normal approximation behind the standard Cochran--Armitage z is
fragile. This script reports the exact conditional p-value obtained by
enumerating the permutation distribution of the linear-by-linear trend
statistic T = sum_i x_i * r_i, conditioning on both margins (the per-level
secret totals n_i and the total number of leaks m). No model runs; the
per-level leak counts are read straight from the saved result JSONs
(summary.per_severity_counts).

Usage:
    python3 exact_trend_test.py
"""
import json
from math import comb
from pathlib import Path

HERE = Path(__file__).resolve().parent
LEVELS = [2, 3, 4]           # low-severity end has only 3 L2 secrets
SCORES = {2: 2, 3: 3, 4: 4}  # linear scores = severity level


def per_level_counts(result_path, model_key):
    d = json.load(open(HERE / result_path))
    psc = d["models"][model_key]["summary"]["per_severity_counts"]
    leaks = {i: psc[str(i)][0] for i in LEVELS}
    totals = {i: psc[str(i)][1] for i in LEVELS}
    return leaks, totals


def exact_trend_p(leaks, totals):
    """One-sided exact conditional p-value for an increasing trend.

    Conditioning on per-level totals N_i and total leaks m, each allocation
    (r_2, r_3, r_4) with sum r_i = m gets null weight prod_i C(N_i, r_i)
    (multivariate hypergeometric). T = sum_i score_i * r_i; the p-value sums
    the null weight of allocations with T >= T_obs.
    """
    N = totals
    m = sum(leaks.values())
    T_obs = sum(SCORES[i] * leaks[i] for i in LEVELS)
    total_w = tail_w = 0
    for r2 in range(N[2] + 1):
        for r3 in range(N[3] + 1):
            r4 = m - r2 - r3
            if r4 < 0 or r4 > N[4]:
                continue
            w = comb(N[2], r2) * comb(N[3], r3) * comb(N[4], r4)
            total_w += w
            if SCORES[2] * r2 + SCORES[3] * r3 + SCORES[4] * r4 >= T_obs:
                tail_w += w
    return T_obs, tail_w / total_w, m


MODELS = [
    ("results/ht_both.json", "qwen/qwen3-32b", "Qwen3-32B"),
    ("results/ht_both.json", "openai/gpt-oss-120b", "gpt-oss-120B"),
    ("results/ht_llama.json", "llama-3.1-8b", "Llama-3.1-8B"),
]

if __name__ == "__main__":
    print("Exact conditional Cochran--Armitage trend test "
          "(scores 2,3,4; Levels 2--4; one-sided increasing):")
    for path, key, name in MODELS:
        leaks, totals = per_level_counts(path, key)
        T_obs, p, m = exact_trend_p(leaks, totals)
        rate = "  ".join(f"L{i} {leaks[i]}/{totals[i]}" for i in LEVELS)
        print(f"  {name}: {rate}  | leaks={m}  T={T_obs}  exact p={p:.4f}")
