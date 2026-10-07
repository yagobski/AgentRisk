"""Logged blind spots on synthetic model workflows."""
from pathlib import Path
import argparse,json
ap=argparse.ArgumentParser();ap.add_argument("--artifact-root",type=Path,default=Path("."));args=ap.parse_args()
E=args.artifact_root/"experiments"
O=args.artifact_root/"audit_results"
O.mkdir(parents=True,exist_ok=True)
work=json.loads((E/'generated/campaign_v2/multihop_rows.json').read_text());detail=[]
for d in work:
 scores=d['channel_scores'];internal=[v['binary_any'] for k,v in scores.items() if k!='C1']
 prior=[v['binary_any'] for k,v in scores.items() if k not in ['C1','archivist_to_storage']]
 detail.append({k:d[k] for k in ['workflow_id','model','scenario_id','condition','topology']} | {
 'c1_clean':scores['C1']['binary_any']==0,'any_internal_exposure':any(internal),
 'c1_clean_internal_exposed':scores['C1']['binary_any']==0 and any(internal),
 'terminal_clean':scores['archivist_to_storage']['binary_any']==0,
 'terminal_clean_prior_internal_exposed':scores['archivist_to_storage']['binary_any']==0 and any(prior)})
out=[]
for model in sorted({x['model'] for x in detail}):
 for co in ['FULL','SCOPED']:
  ds=[x for x in detail if x['model']==model and x['condition']==co]
  out.append(dict(model=model,condition=co,completed=len(ds),planned=18,**{k:sum(x[k] for x in ds) for k in list(detail[0])[5:]}))
blind={'definition':'C1 is the coordinator user-facing reply before downstream processing; terminal is the archivist storage record. Do not call C1 the terminal output.',
 'detector':'frozen deterministic registered markers; not human-adjudicated leakage', 'groups':out,'rows':detail,
 'no_cross_experiment_causal_claim':True}
(O/'frontier_blind_spots.json').write_text(json.dumps(blind,indent=2))
print(json.dumps({'blind_spots':out},indent=2))
