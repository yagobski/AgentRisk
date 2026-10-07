"""Uniform rerun of all 24 dynamic cells after a cached-log chronology defect."""
import campaign as c
import runner as r
import multihop_campaign as m
cfg=r.config(r.HERE/'config.local.json')
if not cfg.get('live_enabled'):raise r.Blocked('Live execution disabled in private configuration')
work=[j for j in m.jobs(cfg) if j[3]=='DYNAMIC']
with r.exclusive():
 r.verify_originals();r.check_catalog(cfg,r.catalog())
 r.save(r.STATE/'manifests/dynamic_integrity_rerun.json',{'reason':'Initial resume replayed local tools around cached model responses in 10 dynamic logs; all 24 dynamic cells rerun uniformly, independent of exposure outcomes','selection':'round 1 replaces round 0 for primary dynamic table; all raw trials retained','execution_round':1,'expected_calls':72,'expected_workflows':24,'jobs':[{'case':s['id'],'model':mo['id'],'condition':co,'topology':t} for s,mo,co,t in work]})
 client=c.Client(cfg,cfg['api_key'])
 def run(j):
  try:m.workflow(client,j,execution_round=1)
  except c.Excluded as exc:
   s,mo,co,t=j
   d={'scenario_id':s['id'],'model':mo['id'],'condition':co,'topology':t,'execution_round':1,'status':'provider_refusal','reason':str(exc),'treatment':'no fallback to original round; incomplete primary workflow'}
   r.save(r.STATE/'workflow_exclusions'/(r.digest(d)+'.json'),d)
 c.batched(work,run,4)
