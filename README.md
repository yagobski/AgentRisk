# AgentLeak / AgentRisk — Reproduction Code

> **Paper accepted in IEEE Access** — DOI: [10.1109/ACCESS.2026.3704541](https://doi.org/10.1109/ACCESS.2026.3704541)  
> Accepted author version (CC BY 4.0): [`paper/agentleak/main.pdf`](paper/agentleak/main.pdf)

Reproducible code for the **AgentLeak** benchmark and **AgentRisk** scoring
framework. AgentLeak evaluates internal-channel privacy leakage in multi-agent
LLM systems across seven instrumented channels (C1–C7). AgentRisk scores
failures with a **severity-weighted, density-normalized Risk Index**
$\mathrm{RI} = \mathrm{WSL}/\rho_S \in [0,1]$, where each disclosed secret
contributes a weight by its sensitivity level (1–4) and $\rho_S$ is the total
weighted risk mass available in the scenario.

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
| `run_case_study.py` | End-to-end audit case study (paper §"End-to-End Audit Case Study"): six realistic coordinator→worker workflows scored across four configurations (Baseline, GUARD, DLP-regex, SCOPED) on channels C1/C2/C5, emitting per-model results and a DPO-style audit report for the flagship workflow. |
| `analyze_results.py` | Turns raw real-eval output into the headline numbers and the binary-vs-RI re-ranking; emits a LaTeX fragment. |
| `analyze_decoupled.py` | Matched-pair decoupling analysis (severity held fixed, task-centrality varied) with an exact McNemar test. |
| `analyze_extension.py` | Pooled analysis of the severity-balanced extension and repeated sampled runs: per-level summaries, Wilson CIs, Cochran–Armitage trend tests, Monte-Carlo permutation tests (n=36), bootstrap CIs, and the sampling-stability table. |
| `inference_stats.py` | Exact paired sign-flip permutation tests and bootstrap CIs over the saved high-tension results (deterministic, no new model runs). |
| `detector_triangulation.py` | Recomputes RI on saved outputs under four distinct detector sources (lexical-strict, lexical-fuzzy, two LLM judges) to test detector robustness. |
| `trend_stats.py` | Standalone Wilson CI and Cochran–Armitage trend test reproducing the paper's statistical claims. Stdlib only. |
| `exact_trend_test.py` | Exact conditional (permutation) Cochran–Armitage trend test for the small per-level counts, where the asymptotic normal approximation is fragile. Reads the per-level counts straight from the saved result JSONs; no model runs. Stdlib only. |
| `final_table.py` | Builds the headline results table from the judged run. |
| `meta_analysis.py` | Transcribes *published, cited* leakage rates from prior benchmarks (nothing fabricated) to show the field reports binary rates only. |
| `score_agentrisk.py` | Severity-composition analysis of the AgentRisk scenario corpus (tab:composition). |
| `score_privacylens.py` | Keyword-based severity mapper for the PrivacyLens secret set (tab:composition, ~62% coverage). Takes `--data` pointing at a local PrivacyLens dump (not redistributed here). |
| `score_trustllm.py` | Keyword-based severity mapper for the TrustLLM secret set (tab:composition, full coverage). Takes `--data-dir` pointing at a local TrustLLM `privacy_data` directory (not redistributed here). |
| `data/` | Scenario sets used by the experiments. |
| `results/` | Saved run outputs and generated LaTeX fragments. |
| `paper/agentleak/` | Accepted author version of the IEEE Access paper (LaTeX source + compiled PDF, CC BY 4.0). |

### Scenario sets

- `data/privacy_scenarios.json` — 29 base scenarios.
- `data/privacy_scenarios_hightension.json` — 12 high-tension scenarios (the headline deterministic baseline and the mitigation study).
- `data/privacy_scenarios_decoupled.json` — 20 matched-pair scenarios (10 pairs); each pair shares one target secret under a *peripheral* and an *entangled* framing to separate severity from task-centrality.
- `data/privacy_scenarios_hightension_ext.json` — 24 severity-balanced extension scenarios with full Level 1–4 coverage (ρ_S = 332).
- `data/privacy_scenarios_hightension_pooled.json` — the pooled 36-scenario set (12 original + 24 extension, ρ_S = 541) used by the repeated sampled runs.
- `data/case_study_workflows.json` — 6 realistic coordinator→worker workflows (healthcare, finance, HR, insurance, legal, government) for the end-to-end audit case study; each carries a full record (Private Vault, 5 labelled secrets) plus a scoped task-relevant subset. 30 secrets total (ρ_S = 84).

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

# Cross-corpus taxonomy portability (tab:composition — no server needed).
# PrivacyLens and TrustLLM raw data are third-party corpora and are not
# redistributed here; point the scripts at your own local checkout.
python score_agentrisk.py
python score_privacylens.py --data /path/to/privacylens_dump.json
python score_trustllm.py --data-dir /path/to/trustllm/privacy_data

# Severity-balanced extension (24 scenarios, L1-L4 balanced) + pooled stats
python run_real_eval.py --models qwen/qwen3-32b \
  --data data/privacy_scenarios_hightension_ext.json --out hx_qwen.json
python run_real_eval.py --models openai/gpt-oss-120b \
  --data data/privacy_scenarios_hightension_ext.json --out hx_gpt.json
python run_real_eval.py --models meta-llama-3.1-8b-instruct \
  --data data/privacy_scenarios_hightension_ext.json --out hx_llama.json

# Repeated sampled runs (sampling-stability check, temperature 0.7, pooled 36)
for run in 1 2 3; do
  python run_real_eval.py --models <model> --temperature 0.7 \
    --data data/privacy_scenarios_hightension_pooled.json \
    --out stab_run${run}_<tag>.json
done

# Pooled analysis: extension + pooled summaries, Wilson CIs, trend tests,
# MC permutation (n=36), bootstrap CIs, and stability table (tab:ext, §6.2)
python analyze_extension.py

# Exact permutation tests + bootstrap CIs on the original 12-scenario set (§7.4)
python inference_stats.py

# End-to-end audit case study (§"End-to-End Audit Case Study"):
# six workflows × four configurations (BASELINE / GUARD / DLP / SCOPED),
# channels C1/C2/C5, plus a DPO-style audit report per model
python run_case_study.py \
  --models qwen/qwen3-32b openai/gpt-oss-120b meta-llama-3.1-8b-instruct
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

## Citation

If you use this code or the AgentLeak benchmark, please cite:

```bibtex
@article{elyagoubi2026agentleak,
  author  = {El Yagoubi, Faouzi and Badu-Marfo, Godwin and Al Mallah, Ranwa},
  title   = {{AgentLeak}: A Benchmark for Internal-Channel Privacy Leakage in
             Multi-Agent {LLM} Systems},
  journal = {IEEE Access},
  year    = {2026},
  volume  = {14},
  doi     = {10.1109/ACCESS.2026.3704541}
}
```
