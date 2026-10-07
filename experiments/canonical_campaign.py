"""Canonical detector records and explicitly bounded observed-knowledge edge scopes."""
import json,re
from collections import Counter
import runner as r
import analysis as a
from multihop_campaign import active_workflows
G=r.HERE/'generated/campaign_v2'
rows=json.loads((G/'frontier_rows.json').read_text())
judges={d['source_trace_id']:d for p in (r.STATE/'auxiliary_v2/exposure_context').glob('*.json') if (d:=json.loads(p.read_text()))['status']=='valid_structure'}
records=[]
for row in rows:
 if row['repeat']!=0:continue
 for detector,labels in [('marker',row['lexical']),('regex_dlp',row['regex_dlp']),('cross_model_judge',judges.get(row['trace_id'],{}).get('verdict'))]:
  if labels is None:continue
  for sec in row['scenario']['secrets']:
   sid=sec['id'];val=labels[sid];evidence=None
   if val and detector!='cross_model_judge':
    evidence=next((hit.group(0) for m in sec['markers'] if (hit:=re.search(re.escape(m),row['output'],re.I))),None)
   if val and detector=='cross_model_judge':
    raw=json.loads((r.STATE/'responses'/(judges[row['trace_id']]['request_id']+'.json')).read_text());evidence=a.parse_json(r.content(raw))[sid]['evidence']
   records.append({'trace_id':row['trace_id'],'trace_sha256':row['trace_sha256'],'secret_id':row['scenario']['id']+'/'+sid,'scope_id':row['scenario']['id']+'/full-vault','inventory_sha256':r.digest(row['scenario']['secrets']),'channel':'OUT','detector':detector,'disclosed':val,'evidence':evidence,'severity':sec['severity'],'task_required':None,'task_required_status':'independent contextual annotation unavailable'})
r.save(G/'canonical_records.json',records)
scs={s['id']:s for s in r.scenarios('multihop')};edges=[]
for p,d in active_workflows():
 sc=scs[d['scenario_id']];weights={s['id']:s['severity'] for s in sc['secrets']};ch=d['channels']
 def hits(text):return {k for k,v in r.legacy.detect_leaks(text,sc['secrets']).items() if v}
 known_co=set(d['provisioned_scopes']['coordinator']['provisioned_registered_ids']);known_worker=hits(ch['coordinator_to_worker'])|set(d['provisioned_scopes'].get('worker',{}).get('provisioned_registered_ids',[]))
 known_arch=hits(ch['worker_to_archivist'])|hits(ch.get('peer_to_archivist',''))
 spec=[('C1','coordinator','user',known_co),('coordinator_to_worker','coordinator','worker',known_co),('worker_to_archivist','worker','archivist',known_worker),('archivist_to_storage','archivist','storage',known_arch)]
 if d['topology']=='FANOUT':spec += [('coordinator_to_peer','coordinator','peer',known_co),('peer_to_archivist','peer','archivist',hits(ch['coordinator_to_peer']))]
 for channel,sender,recipient,scope in spec:
  observed=hits(ch[channel]);consistent=observed<=scope
  edges.append({'workflow_id':p.stem,'scenario_id':sc['id'],'model':d['model'],'condition':d['condition'],'topology':d['topology'],'channel':channel,'sender':sender,'recipient':recipient,'inventory':sorted(scope),'exposed':sorted(observed),'scope_basis':'provisioned registered secrets plus marker-observed incoming knowledge; not complete semantic reachability','scope_consistent':consistent,'scope_score':a.edge_score(scope,observed,weights) if consistent else None,'full_vault_score':a.edge_score(weights,observed,weights),'input_record':str(p.relative_to(r.HERE))})
r.save(G/'observed_knowledge_edges.json',edges)
r.save(G/'canonical_summary.json',{'records_by_detector':dict(Counter(x['detector'] for x in records)),'edge_records':len(edges),'scope_inconsistencies':sum(not x['scope_consistent'] for x in edges),'empty_scope_edges':sum(not x['inventory'] for x in edges),'fully_reachable_scope_claim':False})
print(json.dumps(json.loads((G/'canonical_summary.json').read_text()),indent=2))
