#!/usr/bin/env python3
"""
trend_stats.py — Wilson 95% intervals and a Cochran-Armitage trend test across
severity levels, matching the statistics reported in the paper. Reads a results
JSON (run_real_eval.py format) and prints, per model, the per-level leak rate
with Wilson CI and the Cochran-Armitage z/p for the linear trend over the levels
that actually have samples.

Usage:
    python trend_stats.py results/ht_llama.json
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return p, max(0.0, centre - half), min(1.0, centre + half)


def cochran_armitage(levels: list[int], k: list[int], n: list[int]) -> tuple[float, float]:
    """Linear-by-linear trend test with scores = level index. Returns (z, p)."""
    N = sum(n)
    R = sum(k)
    if N == 0 or R == 0 or R == N:
        return 0.0, 1.0
    pbar = R / N
    # use the severity level value as the dose score
    t = levels
    num = sum(k[i] * t[i] for i in range(len(t))) - pbar * sum(n[i] * t[i] for i in range(len(t)))
    tbar = sum(n[i] * t[i] for i in range(len(t))) / N
    var = pbar * (1 - pbar) * sum(n[i] * (t[i] - tbar) ** 2 for i in range(len(t)))
    if var <= 0:
        return 0.0, 1.0
    z = num / math.sqrt(var)
    # two-sided normal p-value
    p = math.erfc(abs(z) / math.sqrt(2))
    return z, p


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "results/ht_llama.json")
    blob = json.loads(path.read_text())
    for model, info in blob["models"].items():
        s = info["summary"]
        counts = s["per_severity_counts"]  # {"1":[k,n],...}
        print(f"\n=== {model} ===  RI={s['RI']}  ELR={s['ELR_binary']}  WSL={s['WSL']}/{s['rho']}")
        levels, kk, nn = [], [], []
        for lvl in (1, 2, 3, 4):
            k, n = counts[str(lvl)]
            if n == 0:
                continue
            p, lo, hi = wilson(k, n)
            print(f"  L{lvl}: {k}/{n} = {100*p:5.1f}%  Wilson95 [{100*lo:.1f}, {100*hi:.1f}]")
            levels.append(lvl); kk.append(k); nn.append(n)
        z, pv = cochran_armitage(levels, kk, nn)
        print(f"  Cochran-Armitage trend (levels {levels}): z={z:.2f}, p={pv:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
