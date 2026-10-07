# AgentRisk reproducibility artifact

This artifact contains the frozen synthetic executions, final annotation forms,
analysis code and offline checks supporting the manuscript. It contains
one reproduction guide: this README.

## Run the offline verification

From the artifact root, use Python 3.12:

```sh
python3 verification/verify_release.py
python3 -m venv .venv
.venv/bin/python -m pip install -r verification/requirements-offline.txt
.venv/bin/python verification/verify_release.py --full
```

The basic verifier checks every file hash, eight audit-contract assertions,
184 native WLS bounds, the canonical export of 1,440 detector observations,
and the task-rating reconciliation. The AgentLeak WLS
function is not redistributed: `verification/upstream/agentleak/SOURCE.json`
records its commit and SHA-256. Placing that public file at
`verification/upstream/agentleak/core.py` makes `verify_native_wls.py` compare
the replay with the upstream function itself (after checking the hash);
otherwise it compares with the WLS definition and says so in its output. Full replay adds
61 unit tests and recomputes the released numerical analyses in a temporary
copy, with relative and absolute float tolerances of 1e-12. Neither mode calls
model providers or requires credentials. A successful status means these
technical checks passed. Optional live execution requires separate provider
configuration and may incur charges; it is unnecessary for reproducing the
reported results. See `requirements.txt` and `experiments/requirements_p2p.txt`
for live-run dependencies, and `LICENSE` for the MIT license.

## Claims and evidence

Paths below are relative to this directory. `SHA256SUMS.json` fixes the delivered
file set and content. Run commands from the artifact root.

| Manuscript result | Evidence | Offline replay |
| --- | --- | --- |
| Audit validity and scope | `verification/evidence/contract_replay.json`; `experiments/analysis.py`; `experiments/scope.py` | `python3 verification/reproduce_contract.py --check` |
| 216 frontier generations | `experiments/generated/campaign_v2/frontier_summary.json` | `python3 verification/verify_release.py --full` |
| 68 primary multi-hop, 24 peer and 10 Guard workflows completed | `experiments/generated/campaign_v2/multihop_rows.json`; `audit_results/frontier_blind_spots.json`; `experiments/generated/audit_summary/results.json` | `python3 verification/verify_release.py --full` |
| Native WLS and RI on the same 92 primary and peer workflows | `experiments/generated/audit_summary/native_per_workflow.json`; `verification/evidence/native_field_mapping.csv`; `verification/upstream/agentleak/SOURCE.json` | `python3 verification/verify_native_wls.py` |
| 316 edge observations and retention after revocation | `measurement/evidence/all_edge_comparisons.csv`; `measurement/evidence/edge_summary.json` | `python3 measurement/scripts/strengthening_analysis.py` |
| Final disclosure labels on 360 opportunities from 72 outputs | `expert_evaluation/input/`; `expert_evaluation/results.json` | `python3 expert_evaluation/analyze_expert_evaluation.py` |
| Task-rating denominators | `verification/evidence/task_evaluation.json`; `expert_evaluation/workflow_results.json` | `python3 verification/reconcile_task_evaluation.py --check` |
| Paired control, inventory sensitivity and review volume | `experiments/generated/campaign_v2/paired_control.json`; `experiments/generated/audit_summary/results.json`; `measurement/evidence/capture_overhead.json` | `python3 verification/verify_release.py --full` |

The top-level `data/` and `results/` directories retain the historical synthetic
scenario inventories and benchmark outputs. The revision analyses are in
`experiments/`, `measurement/`, `expert_evaluation/`, `audit_results/` and
`verification/`. Legacy `verify_properties.py` checks randomized mathematical
examples and selected transcribed calculations; it does not prove all paper
claims or replace the source-backed release verifier.

## Canonical observation export

The files `experiments/generated/campaign_v2/canonical_records.json` (1,080
observations) and `measurement/evidence/presidio_canonical.json` (360) retain
the adapters' internal encoding. The manuscript's Table 5 describes the
resolved interface exported to `verification/evidence/canonical_observations.json`.
`experiments/canonical_schema.py` validates the following mapping:

| Internal field/value | Canonical field/value |
| --- | --- |
| `channel` | `channel_id` |
| `detector` | `detector_source` |
| `severity` | `severity_level` |
| `task_required: null` with unavailable-adjudication status | `task_required: "unsure"`, with that status in `task_required_provenance` |

All 1,440 archived observations lack independent contextual adjudication;
this is an unresolved policy label, not evidence that disclosure was required
or unnecessary. The separate finalized expert labels are analyzed as described
below. `OUT` is the single-output surface in this panel; it is not relabeled as
a multi-hop C1 event. Disclosure values, evidence, identities, source hashes,
severity tiers and scope IDs are preserved, including inventory hashes where
present. A null `disclosed` value remains unresolved.

Run `python3 verification/export_canonical.py --check` to validate every exported
record, reproduce the mapping and compare scores for all 288 trace/adapter
groups. This check is included in both release-verification modes. The exporter
rejects missing fields, conflicting aliases, invalid values and positives
without evidence. `--write` rebuilds the export from the frozen internal files;
no detector or model is rerun.

## Task judgments and their denominators

| Reference and population | Complete or accomplished | Other observations |
| --- | --- | --- |
| Auxiliary opposite-family model, primary multi-hop only | 22/67 valid judgments meet the full rubric | 11/67 contain unresolved item decisions; one of 68 completed workflows has no valid judgment |
| Final expert global rating, primary multi-hop | 66/68 accomplished | 2 partial; FULL 33/34 and SCOPED 33/34 accomplished |
| Final expert global rating, additional Guard workflows | 9/10 accomplished | 1 partial |
| Final expert detailed forms, same 78 workflows | 78/78 have all applicable items positive and no material invention | A form consistency diagnostic, not a task-success rate |

These are distinct assessments with different criteria, reported descriptively.
W015, W033 and W047 received a partial global rating without an identified
missing item; they are counted conservatively as partial. The automated rubric
is stricter because it requires literal evidence for every essential item
(W001 is an example). Exact archived outputs and both final forms for these four
workflows are in `verification/evidence/contract_replay.json`. The 24 peer
workflows have no expert task rating.

## Annotation provenance and detector coverage

Two risk-assessment experts labeled the same synthetic outputs, blind to model
identities, configuration labels and detector scores. A coordination record
finalized by the authors reconciles their forms. The released `a` and `b`
values (also stored as `A` and `B`) come from final forms after coordination,
not the initial independent responses. Their 360/360 disclosure agreement
describes consistency of the final forms; it does not estimate initial
inter-rater reliability. Across all 2,489 decisions, 2,472 final-form pairs
agree and 17 differ on contextual necessity or authorization; these 17
decisions retain Unknown. Comparison labels and reasons refer to these final
forms. Stable source IDs and hashes are in
`expert_evaluation/input/source_manifest.json`.

The annotation materials in `expert_evaluation/annotation_data.json` use
opaque trace, workflow and context IDs alongside the tasks, source records
and outputs to assess. They omit model identities, configuration labels and
detector scores. In contrast, `input/opportunities.json` and
`input/workflows.json` are consolidated analysis files: model, condition
and detector metadata were joined to the returned annotations during
analysis. They are not the forms shown to the experts.

The 360 final disclosure labels contain 11 Yes, 348 No and one Unknown.
Precision and recall use jointly resolved opportunities for each detector:
marker 359, regex DLP 50, Presidio 80 and cross-model judge 357. Adapter-specific
abstentions and uncovered fields are not negatives. Unknown labels contribute
lower and upper exposure bounds, which are not confidence intervals. Reported
precision and recall are descriptive comparisons against these finalized labels.

## Experimental scope and interpretation

The primary multi-hop campaign planned 72 workflows and completed 68; peer
execution completed 24/24; Guard completed 10/12. There are six synthetic tasks
per model, topology and condition, with one execution per cell. Refusals and
transport failures are retained in the records and excluded from exposure
denominators without being scored as zero. Dynamic cells were rerun uniformly
after a resume/instrumentation audit found cached timestamp replay; primary
dynamic results use the fresh round, with both rounds archived.

C1 is the user-facing reply; it precedes or follows internal processing
depending on topology. It is not a universal terminal record. Internal exposure occurs in 24/34 completed
FULL primary workflows and 8/12 FULL peer workflows despite clean user-facing
replies. The deterministic SCOPED selector acts outside the model and excludes
registered irrelevant secrets before generation. Zero detected SCOPED exposure
is conditional on that selector, the registered inventory and detector coverage;
it is not a general privacy guarantee or evidence of protection against an
upstream model that sees the full record.

Native WLS counts field/channel occurrences, whereas RI counts distinct
weighted secrets relative to a declared inventory. Native WLS and RI have
Kendall tau-b approximately 0.32 across the 32 exposed workflows in these identical records. A
separate tier-weighted occurrence surrogate gives approximately 0.40; it uses
a different weighting convention. Repeated propagation can increase WLS
without increasing distinct exposure. The comparison also changes native
field/channel weights, so the rank disagreement does not isolate deduplication.
This illustrates complementary measurements and does not establish RI as a
universally better score. The native default grid maps 19 of the 30 registered
fields; unmapped types remain explicit. Neither score estimates actual harm.

The experiments are controlled synthetic tasks, with small samples, detector
coverage limits and no real deployment. Review queues measure text volume, not
auditor time. Human audit decisions are not evaluated.

The readable mortgage report lists C2 and C5 as tied at RI 0.500. The
historical JSON stores C2, the first maximum selected by the original generator.
