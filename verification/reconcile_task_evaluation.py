#!/usr/bin/env python3
"""Reconcile task-rating denominators from frozen judgments and final forms."""
import argparse, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def build():
    rows=json.loads((ROOT/'experiments/generated/campaign_v2/multihop_rows.json').read_text())
    valid=[r for r in rows if r.get('utility') and r['utility']['status']=='valid_structure']
    forms=json.loads((ROOT/'expert_evaluation/input/workflows.json').read_text())
    decisions=json.loads((ROOT/'expert_evaluation/input/decisions.json').read_text())
    labels={(d['id'],d['field']):d['final'] for d in decisions if d['sheet']=='Utility'}
    assert len(forms)==len({f['id'] for f in forms})==78
    def complete(f):
        items=[v for (i,k),v in labels.items() if i==f['id'] and k.startswith('criterion')]
        assert items
        return all(v=='Yes' for v in items) and labels[f['id'],'invention']=='No'
    def counts(fs):
        return {'rated':len(fs),'accomplished':sum(labels[f['id'],'global_result']=='Accomplished' for f in fs),
                'partial':sum(labels[f['id'],'global_result']=='Partial' for f in fs),
                'positive_detailed_grids':sum(complete(f) for f in fs)}
    conflict=[f['id'] for f in forms if complete(f) and labels[f['id'],'global_result']=='Partial']
    primary=[f for f in forms if f['primary']]
    guard=[f for f in forms if not f['primary']]
    result={'auxiliary_model':{'completed_workflows':len(rows),'valid_judgments':len(valid),
        'full_rubric_complete':sum(r['utility']['verdict']['complete'] is True for r in valid),
        'with_unresolved_item_decisions':sum(r['utility']['verdict']['unresolved'] is True for r in valid),
        'without_valid_judgment':len(rows)-len(valid)},
        'final_expert_global':counts(forms),'final_expert_primary':counts(primary),'final_expert_guard':counts(guard),
        'partial_global_without_identified_missing_item':conflict,
        'interpretation':'Global ratings are the expert task outcome; detailed grids are a form consistency diagnostic. Three workflows with a partial global rating and no identified missing item are counted conservatively as partial. Auxiliary judgments and expert forms use different criteria. No peer-to-peer expert ratings are supplied.'}
    assert result['auxiliary_model']=={'completed_workflows':68,'valid_judgments':67,'full_rubric_complete':22,'with_unresolved_item_decisions':11,'without_valid_judgment':1}
    assert result['final_expert_global']=={'rated':78,'accomplished':75,'partial':3,'positive_detailed_grids':78}
    assert result['final_expert_primary']['accomplished']==66 and result['final_expert_guard']['accomplished']==9
    assert conflict==['W015','W033','W047']
    return result
if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--check',action='store_true');ap.add_argument('--out',type=Path);args=ap.parse_args();result=build()
    if args.check:assert result==json.loads((ROOT/'verification/evidence/task_evaluation.json').read_text())
    if args.out:args.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
