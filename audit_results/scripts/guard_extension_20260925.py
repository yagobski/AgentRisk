"""Additive, explicitly invoked Guard comparison; existing code/config unchanged."""
from pathlib import Path
import argparse,json,random,sys
R=Path(__file__).resolve().parents[1]
E=Path('experiments')
sys.path.insert(0,str(E));import runner as r, campaign as c
from multihop_campaign import ARCHIVIST
O=R/'evidence/round2_20260925/guard';O.mkdir(parents=True,exist_ok=True)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--live',action='store_true');args=ap.parse_args()
 cfg=r.config(E/'config.local.json');r.verify_originals()
 jobs=[(sc,m) for sc in r.scenarios('multihop') for m in cfg['models']];random.Random(20260925).shuffle(jobs)
 manifest={'experiment':'guard-chain-20260925','created_at':r.utc(),'planned_workflows':12,'planned_calls':36,
 'comparison':'same six cases, two models and chain topology; archived FULL/SCOPED comparators; one execution per cell, date-separated exploratory comparison',
 'change':'coordinator system prompt COORD_GUARD replaces COORD_BASE; full source and downstream prompts unchanged',
 'guard_prompt':r.case.COORD_GUARD,'max_additional_usd':5,'local_absolute_cap_usd':45,
 'jobs':[{'scenario':s['id'],'model':m['id']} for s,m in jobs], 'public_config':r.public_config(cfg)}
 if not args.live:print(json.dumps(manifest,indent=2));return
 bill=c.account(cfg['api_key']);manifest['account_before']=bill
 # Consent is this explicit --live invocation; do not change the disabled local config.
 cfg['total_budget_usd']=min(45,bill['usage']+5);cfg['stage_budgets_usd']['multihop']=5
 if not (O/'manifest.json').exists():r.save(O/'manifest.json',manifest)
 r.save(O/'catalog.json',r.check_catalog(cfg,r.catalog()))
 client=c.Client(cfg,cfg['api_key'],state=O/'state')
 # A transport-uncertain request is never retried. Keep its full cost reservation
 # and exclude that workflow before continuing unrelated scheduled cells.
 for rid,row in client.ledger.rows.items():
  if row['status']=='transport_uncertain':
   row.update(reconciled=True,budget_note='Full scheduling allowance retained; actual billing unresolved; no retry')
 client.ledger.flush()
 def run(job):
  sc,m=job;wid=r.digest({'experiment':manifest['experiment'],'case':sc['id'],'model':m['id']})
  path=O/'workflows'/(wid+'.json')
  if path.exists():return
  if (O/'exclusions'/(wid+'.json')).exists():return
  recs=[]
  def call(role,system,user,parents=()):
   meta={'experiment':manifest['experiment'],'scenario_id':sc['id'],'scenario_sha256':r.digest(sc),'condition':'GUARD','topology':'CHAIN','turn':role,'parents':list(parents),'repeat':0}
   v=client.call(m,r.messages(system,user),'multihop',meta);recs.append(v);return v
  try:
   co=call('coordinator',r.case.COORD_GUARD,r.case.coord_user(sc,False));c1,c2=r.strict_channels(r.content(co))
   wo=call('worker',r.case.WORKER_SYS,f"{sc['worker_task']}\n\nHANDOFF NOTE:\n{c2}\n\nReturn ONLY the record.",[co['request_id']])
   ar=call('archivist',ARCHIVIST,f"TASK: {sc['worker_task']}\n\nRECORDS:\n{r.content(wo)}",[wo['request_id']])
   doc={'workflow_id':wid,'model':m['id'],'scenario_id':sc['id'],'condition':'GUARD','topology':'CHAIN','synthetic_extension':True,
    'request_ids':[v['request_id'] for v in recs],'channels':{'C1':c1,'coordinator_to_worker':c2,'worker_to_archivist':r.content(wo),'archivist_to_storage':r.content(ar)},
    'total_cost':sum(v['response']['usage']['cost'] for v in recs),'protocol_sha256':r.protocol_id(cfg),'recorded_at':r.utc()}
   r.save(path,doc);print('COMPLETED',sc['id'],m['id'],flush=True)
  except c.Excluded:
   r.save(O/'exclusions'/(wid+'.json'),{'workflow_id':wid,'scenario_id':sc['id'],'model':m['id'],'condition':'GUARD','status':'provider_refusal','request_ids':[v['request_id'] for v in recs]})
  except r.Blocked as exc:
   uncertain=[rid for rid,row in client.ledger.rows.items() if row['status']=='transport_uncertain' and rid in str(exc)]
   if not uncertain:raise
   with client.lock:
    for rid in uncertain:client.ledger.rows[rid].update(reconciled=True,budget_note='Full allowance retained; billing unresolved; no retry')
    client.ledger.flush()
   r.save(O/'exclusions'/(wid+'.json'),{'workflow_id':wid,'scenario_id':sc['id'],'model':m['id'],'condition':'GUARD','status':'transport_uncertain','request_ids':[v['request_id'] for v in recs]+uncertain,'treatment':'no retry; retained full budget reservation; not scored as zero or success'})
 with r.exclusive():c.batched(jobs,run,2)
 r.save(O/'costs.json',{'account_after':c.account(cfg['api_key']),'additional_charged_or_reserved_usd':sum(v['charged_or_reserved_usd'] for v in client.ledger.rows.values()),'requests':len(client.ledger.rows)})
if __name__=='__main__':main()
