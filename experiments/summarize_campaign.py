#!/usr/bin/env python3
import json,statistics,random
from collections import defaultdict
from pathlib import Path
import runner as r
import campaign as c
import analysis as a
from multihop_campaign import active_workflows
OUT=r.HERE/'generated'/'campaign_v2'

def main():
 OUT.mkdir(parents=True,exist_ok=True)
 by={s['id']:s for s in r.scenarios()};rows=[]
 for p in sorted((r.STATE/'responses').glob('*.json')):
  d=json.loads(p.read_text());m=d['meta']
  if m.get('experiment')!='frontier' or m.get('campaign')!=c.CAMPAIGN:continue
  if d['response_sha256']!=r.digest(d['response']):raise ValueError('Hash mismatch')
  rows.append({'trace_id':d['request_id'],'source':'new_openrouter','scenario':by[m['scenario_id']],'model':d['request']['model'],'repeat':m['repeat'],'output':r.content(d),'status':'ok','usage':d['response']['usage'],'wall_seconds':d['wall_seconds']})
 rows=list(a.analyzed_rows(rows));r.save(OUT/'frontier_rows.json',rows)
 groups=defaultdict(list)
 for row in rows:groups[row['model']].append(row)
 summary={}
 for model,g in groups.items():
  cases=defaultdict(list)
  for x in g:cases[x['scenario']['id']].append(x)
  pairs=[(statistics.mean(x['lexical_scores']['weighted_amount'] for x in v),v[0]['lexical_scores']['inventory_mass']) for k,v in sorted(cases.items())]
  rng=random.Random(20260924);boots=[]
  for _ in range(10000):
   sample=rng.choices(pairs,k=len(pairs));boots.append(sum(x for x,y in sample)/sum(y for x,y in sample))
  num=sum(x['lexical_scores']['weighted_amount'] for x in g);den=sum(x['lexical_scores']['inventory_mass'] for x in g)
  summary[model]={'n':len(g),'cases':len(cases),'repeats':sorted({x['repeat'] for x in g}),'RI':num/den,'RI_case_bootstrap95':[a.percentile(boots,.025),a.percentile(boots,.975)],
 'WSL':num,'mass':den,'binary_any':sum(x['lexical_scores']['binary_any'] for x in g),'exposed_secrets':sum(sum(x['lexical'].values()) for x in g),'secret_opportunities':sum(len(x['lexical']) for x in g),
 'cost':sum(x['usage']['cost'] for x in g),'prompt_tokens':sum(x['usage']['prompt_tokens'] for x in g),'completion_tokens':sum(x['usage']['completion_tokens'] for x in g),'median_request_seconds':statistics.median(x['wall_seconds'] for x in g)}
 r.save(OUT/'frontier_summary.json',summary)
 # Same-output aligned metric comparison on existing output bytes.
 old=list(a.analyzed_rows(a.historical_rows()));r.save(OUT/'historical_summary.json',a.summarize(old));r.save(OUT/'overhead.json',a.overhead(rows,1000))
 # Fixed first generation, all 36 cases, both models.
 subset=[x for x in rows if x['repeat']==0];a.templates(subset,OUT/'reference')
 judges={d['source_trace_id']:d for p in (r.STATE/'auxiliary_v2/exposure_context').glob('*.json') if (d:=json.loads(p.read_text()))['status']=='valid_structure'}
 inter={};deltas=[]
 for kind in ['regex','semantic']:
  pairs=[];registered=0;complete=0;num=den=0;trace_delta=[]
  for row in subset:
   verdict=row['regex_dlp'] if kind=='regex' else judges.get(row['trace_id'],{}).get('verdict')
   registered+=len(row['lexical'])
   if verdict is None:continue
   pairs.extend((row['lexical'][k],v) for k,v in verdict.items() if type(v)==bool)
   s=a.score(row['scenario']['secrets'],verdict)
   if s['status']=='complete':
    complete+=1;num+=s['weighted_amount'];den+=s['inventory_mass'];trace_delta.append(s['RI']-row['lexical_scores']['RI'])
  n=len(pairs);agree=sum(x==y for x,y in pairs)/n if n else None
  pa=sum(x for x,y in pairs)/n if n else 0;pb=sum(y for x,y in pairs)/n if n else 0;chance=pa*pb+(1-pa)*(1-pb)
  pp=sum(x and y for x,y in pairs);nn=sum(not x and not y for x,y in pairs);discord=sum(x!=y for x,y in pairs)
  inter[kind]={'registered':registered,'resolved_pairs':n,'agreement':agree,'kappa':(agree-chance)/(1-chance) if n and chance!=1 else None,'positive_agreement':2*pp/(2*pp+discord) if 2*pp+discord else None,'negative_agreement':2*nn/(2*nn+discord) if 2*nn+discord else None,
 'complete_traces':complete,'RI_complete':num/den if den else None,'mean_delta_RI_complete':statistics.mean(trace_delta) if trace_delta else None,'delta_RI_range':[min(trace_delta),max(trace_delta)] if trace_delta else None,'reference':'lexical detector for agreement, not ground-truth accuracy'}
 r.save(OUT/'interoperability.json',inter)
 bymulti={s['id']:s for s in r.scenarios('multihop')};workflows=[]
 utility={d['source_workflow']:d for p in (r.STATE/'auxiliary_v2/utility_context').glob('*.json') if (d:=json.loads(p.read_text()))['status']=='valid_structure'}
 for p,d in active_workflows():
  sc=bymulti[d['scenario_id']]
  leaks={k:r.legacy.detect_leaks(v,sc['secrets']) for k,v in d['channels'].items()}
  union={s['id']:any(v[s['id']] for v in leaks.values()) for s in sc['secrets']}
  score=a.score(sc['secrets'],union); final=a.score(sc['secrets'],leaks['archivist_to_storage'])
  workflows.append(dict(workflow_id=p.stem,model=d['model'],scenario_id=d['scenario_id'],topology=d['topology'],condition=d['condition'],global_score=score,final_score=final,channel_scores={k:a.score(sc['secrets'],v) for k,v in leaks.items()},utility=utility.get(p.stem),cost=d['total_cost']))
 r.save(OUT/'multihop_rows.json',workflows)
 multi=[]
 for model in sorted({x['model'] for x in workflows}):
  for topology in ['CHAIN','FANOUT','DYNAMIC']:
   for condition in ['FULL','SCOPED']:
    g=[x for x in workflows if x['model']==model and x['topology']==topology and x['condition']==condition]
    if not g:continue
    def pooled(key):return sum(x[key]['weighted_amount'] for x in g)/sum(x[key]['inventory_mass'] for x in g)
    valid=[x['utility']['verdict'] for x in g if x['utility']]
    multi.append({'model':model,'topology':topology,'condition':condition,'n':len(g),'global_RI':pooled('global_score'),'final_RI':pooled('final_score'),
    'internal_any_final_zero':sum(x['global_score']['binary_any'] and not x['final_score']['binary_any'] for x in g),'utility_valid':len(valid),'utility_unresolved':sum(v['unresolved'] for v in valid),'utility_complete':sum(v['complete'] for v in valid),'cost':sum(x['cost'] for x in g)})
 r.save(OUT/'multihop_summary.json',multi)
 r.save(OUT/'ledger_summary.json',{'requests':len(r.Ledger(r.STATE).rows),'usd':sum(x['charged_or_reserved_usd'] for x in r.Ledger(r.STATE).rows.values())})
 print(json.dumps(summary,indent=2));print(json.dumps(inter,indent=2));print('workflows',len(workflows))
if __name__=='__main__':main()
