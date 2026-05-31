# AgentRisk — Reproduction Code

Reproducible code for the AgentRisk paper. AgentRisk scores privacy failures in
multi-agent LLM systems with a **severity-weighted, density-normalized Risk
Index** $\mathrm{RI} = \mathrm{WSL}/\rho_S \in [0,1]$, where each disclosed
secret contributes a weight by its sensitivity level (1–4) and $\rho_S$ is the
total weighted risk mass available in the scenario.

Everything here runs on the Python standard library (Python 3.9+); there are no
third-party Python dependencies. The end-to-end agent experiments query an
OpenAI-compatible chat endpoint — we used a local
[LM Studio](https://lmstudio.ai/) server serving `qwen/qwen3-32b` and
`openai/gpt-oss-120b`, but any compatible endpoint works.

## Layout

| File | What it does |
|------|--------------|
| `verify_properties.py` | Machine-checkable proof of the five RI properties and reproduction of every numeric claim in the paper. Stdlib only; no server needed. |
| `run_real_eval.py` | Runs the agents under a data-minimization system prompt over a scenario set, applies deterministic marker detection, and scores ELR / WSL / RI with per-severity leak rates. |
| `judge_existing.py` | Adds a paraphrase-aware LLM-judge second opinion over already-collected outputs (corroboration only; the deterministic detector stays the headline signal). |
| `run_mitigation_eval.py` | Re-runs the high-tension scenarios under two defenses (instructional GUARD, architectural SCOPED) to show RI responds to mitigation. |
| `analyze_results.py` | Turns raw real-eval output into the headline numbers and the binary-vs-RI re-ranking; emits a LaTeX fragment. |
| `analyze_decoupled.py` | Matched-pair decoupling analysis (severity held fixed, task-centrality varied) with an exact McNemar test. |
| `detector_triangulation.py` | Recomputes RI on saved outputs under four distinct detector sources (lexical-strict, lexical-fuzzy, two LLM judges) to test detector robustness. |
| `trend_stats.py` | Standalone Wilson CI and Cochran–Armitage trend test reproducing the paper's statistical claims. Stdlib only. |
| `final_table.py` | Builds the headline results table from the judged run. |
| `meta_analysis.py` | Transcribes *published, cited* leakage rates from prior benchmarks (nothing fabricated) to show the field reports binary rates only. |
| `score_agentrisk.py` | Severity-composition analysis of the AgentRisk scenario corpus (tab:composition). |
| `score_privacylens.py` | Keyword-based severity mapper for the PrivacyLens secret set (tab:composition, ~62% coverage). |
| `score_trustllm.py` | Keyword-based severity mapper for the TrustLLM secret set (tab:composition, full coverage). |
| `data/` | Scenario sets used by the experiments. |
| `results/` | Saved run outputs and generated LaTeX fragments. |

### Scenario sets

- `data/privacy_scenarios.json` — 29 base scenarios.
- `data/privacy_scenarios_hightension.json` — 12 high-tension scenarios (the headline deterministic baseline and the mitigation study).
- `data/privacy_scenarios_decoupled.json` — 20 matched-pair scenarios (10 pairs); each pair shares one target secret under a *peripheral* and an *entangled* framing to separate severity from task-centrality.

## Reproduce the formal claims (no server required)

```bash
python verify_properties.py
```

This checks the four RI properties and re-derives the numeric claims in the
paper (padding-invariance ratio, composite-scale orderings, Wilson intervals,
Cochran–Armitage trend tests, and the decoupling counts).

## Reproduce the experiments

Point the scripts at any OpenAI-compatible endpoint. With LM Studio running
locally:

```bash
# Headline run: two larger models on high-tension scenarios
python run_real_eval.py \
  --models qwen/qwen3-32b openai/gpt-oss-120b \
  --data data/privacy_scenarios_hightension.json \
  --out ht_both.json

# Third model (Llama-3.1-8B, high-tension only)
python run_real_eval.py \
  --models meta-llama/meta-llama-3.1-8b-instruct \
  --data data/privacy_scenarios_hightension.json \
  --out ht_llama.json

# Optional paraphrase-aware corroboration from an LLM judge
python judge_existing.py --in results/ht_both.json --judge openai/gpt-oss-120b

# Headline table and per-severity breakdown
python final_table.py
python analyze_results.py

# Detector robustness check (four detector sources, same stored outputs)
python detector_triangulation.py --both results/ht_both.json \
  --judged results/ht_both_judged.json \
  --qcache results/ht_qwen_judge.json

# Trend statistics (Wilson CIs and Cochran–Armitage test)
python trend_stats.py results/ht_both_judged.json

# Mitigation study (GUARD vs SCOPED)
python run_mitigation_eval.py --models qwen/qwen3-32b openai/gpt-oss-120b

# Decoupling experiment: severity fixed, task-centrality varied
python run_real_eval.py \
  --models qwen/qwen3-32b openai/gpt-oss-120b \
  --data data/privacy_scenarios_decoupled.json \
  --out decoupled_results.json --max-tokens 1200
python analyze_decoupled.py

# Cross-corpus taxonomy portability (tab:composition — no server needed)
python score_agentrisk.py
python score_privacylens.py
python score_trustllm.py
```

Useful flags shared by the runners: `--base-url` (default
`http://localhost:1234/v1`), `--limit N` (first N scenarios), `--max-tokens`.

## Notes on integrity

- The deterministic detector is the headline signal; the LLM judge is reported
  only as paraphrase-aware corroboration, since the judge model also appears as
  a tested agent (a self-judgment bias also present in prior work).
- Severity-weighted results are measured directly on the open-model experiments,
  where each secret's level is known. They are never retro-fitted onto external
  corpora that publish only binary labels.
