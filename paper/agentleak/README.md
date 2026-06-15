# AgentLeak — Accepted Author Version

**AgentLeak: A Benchmark for Internal-Channel Privacy Leakage in Multi-Agent LLM Systems**

Faouzi El Yagoubi, Godwin Badu-Marfo, Ranwa Al Mallah  
Department of Computer and Software Engineering, Polytechnique Montréal

---

**Published in IEEE Access**  
DOI: [10.1109/ACCESS.2026.3704541](https://doi.org/10.1109/ACCESS.2026.3704541)  
Manuscript ID: Access-2026-23002  
License: CC BY 4.0

---

## Files

| File | Description |
|------|-------------|
| `main.pdf` | Final accepted author version (CC BY 4.0) |
| `main_clean.tex` | LaTeX source (arXiv submission) |
| `main.bbl` | Pre-compiled bibliography |
| `ieeeaccess.cls` | IEEE Access class file |
| `figures/` | All figures (PDF) |

## Abstract

Multi-agent Large Language Model (LLM) systems create privacy risks that
current output-only benchmarks cannot measure. When agents coordinate on tasks,
sensitive data may pass through inter-agent messages, shared memory, and tool
arguments — all pathways that final-output audits typically do not inspect.

We introduce **AgentLeak**, a benchmark for evaluating internal-channel privacy
leakage in multi-agent LLM systems. AgentLeak instruments seven
privacy-relevant communication pathways and provides a large-scale empirical
evaluation focused on final outputs (C1), inter-agent messages (C2), and shared
memory (C5).

Across **1,000 scenarios** spanning healthcare, finance, legal, and corporate
domains, **five production LLMs** (GPT-4o, GPT-4o-mini, Claude 3.5 Sonnet,
Mistral Large, and Llama 3.3 70B), and **4,979 validated execution traces**:

- Multi-agent configurations **reduce** final-output leakage (C1: 27.2% vs
  43.2% single-agent), but introduce internal channels that raise **total system
  exposure to 68.9%** (aggregated across C1, C2, C5).
- Inter-agent messages (C2) leak at **68.8%**, vs 27.2% for final outputs (C1):
  output-only audits miss **41.7% of violations**.
- The pattern **C2 ≥ C1 holds consistently** across all five models and four
  domains.

## Citation

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
