"""Independent exact reanalysis of archived outputs; no model calls."""
import itertools,json
from collections import defaultdict
import runner as r
from analysis import historical_rows,score

def exact(d):
 d=[x for x in d if x];obs=abs(sum(d));return sum(abs(sum(s*x for s,x in zip(sign,d)))>=obs for sign in itertools.product([-1,1],repeat=len(d)))/(2**len(d))
scs=json.loads((r.ROOT/'data/privacy_scenarios_decoupled.json').read_text())['scenarios'];by={s['id']:s for s in scs};out=json.loads((r.ROOT/'results/decoupled_results.json').read_text());effects={};mismatch=0
for model,g in out['models'].items():
 pairs=defaultdict(dict)
 for row in g['rows']:
  sc=by[row['scenario_id']];target=next(s for s in sc['secrets'] if s.get('target'));output=row['output'];assert output and not output.startswith('[ERROR')
  verdict=r.legacy.detect_leaks(output,sc['secrets']);mismatch+=verdict!=row['leaks'];pairs[sc['pair']][sc['role']]=int(verdict[target['id']])
 effects[model]={k:v['entangled']-v['peripheral'] for k,v in pairs.items()}
keys=sorted(next(iter(effects.values())))
result={'target_label_mismatches':mismatch,'per_model':{k:{'effects':v,'exact_signflip_p':exact(v.values())} for k,v in effects.items()},'shared_fact_block_p':exact([sum(v[k] for v in effects.values()) for k in keys]),'unit':'shared fact pair; both model outcomes retained in same sign-flip block'}
r.save(r.HERE/'generated/campaign_v2/paired_control.json',result)
# Original 12-output comparison, with a consistent table grouping.
groups=defaultdict(list)
for row in historical_rows():
 if row['source'] not in ['ht_both.json','ht_llama.json']:continue
 verdict=r.legacy.detect_leaks(row['output'],row['scenario']['secrets']);groups[row['model']].append((row,verdict,score(row['scenario']['secrets'],verdict)))
metric={}
for model,g in groups.items():
 metric[model]={'outputs':len(g),'binary_any':sum(s['binary_any'] for _,_,s in g),'disclosed':sum(sum(v.values()) for _,v,_ in g),'secrets':sum(len(v) for _,v,_ in g),'WSL':sum(s['weighted_amount'] for _,_,s in g),'mass':sum(s['inventory_mass'] for _,_,s in g)}
 for k in ['RI','WLS_aligned']: metric[model][k]=metric[model]['WSL']/(metric[model]['mass'] if k=='RI' else 4)
r.save(r.HERE/'generated/campaign_v2/original_metric_table.json',metric);print(json.dumps(result,indent=2));print(json.dumps(metric,indent=2))
