"""Offline additions from immutable saved outputs; no provider calls or new human labels."""
from pathlib import Path
import collections,csv,hashlib,json,statistics,sys

ROOT=Path(__file__).resolve().parents[1]
EX=Path('experiments')
sys.path.insert(0,str(EX))
import runner as r
G=EX/'generated/campaign_v2'; OUT=ROOT/'evidence';OUT.mkdir(exist_ok=True)
TEX=ROOT/'tables';TEX.mkdir(parents=True,exist_ok=True)
def load(n):return json.loads((G/(n+'.json')).read_text())
def save(n,x):(OUT/(n+'.json')).write_text(json.dumps(x,indent=2))
def table(caption,label,spec,head,rows):
 return '\\begin{table}[t]\n\\caption{'+caption+'}\\label{'+label+'}\n\\small\\setlength{\\tabcolsep}{3pt}\n\\begin{tabular}{@{}'+spec+'@{}}\\toprule\n'+head+'\\\\\\midrule\n'+'\\\\\n'.join(rows)+'\\\\\\bottomrule\n\\end{tabular}\\end{table}\n'

edges=load('observed_knowledge_edges'); runs=load('multihop_rows')
assert len(runs)==68 and len(edges)==316
assert all(e['scope_consistent'] for e in edges)
byid={d['workflow_id']:d for d in runs}
for e in edges:
 assert e['scope_score']['numerator']==e['full_vault_score']['numerator']
 assert e['full_vault_score']['denominator']==14

# Every logged edge, with comparable numerator and two explicitly named denominators.
fields=['workflow_id','scenario_id','model','condition','topology','channel','WSL','WLS_aligned','full_mass','observed_mass','RI_full','RI_observed']
allrows=[]
for e in edges:
 a=e['scope_score'];b=e['full_vault_score']
 allrows.append({**{k:e[k] for k in fields[:6]},'WSL':a['numerator'],'WLS_aligned':a['numerator']/4,'full_mass':b['denominator'],'observed_mass':a['denominator'],'RI_full':b['RI'],'RI_observed':a['RI']})
with (OUT/'all_edge_comparisons.csv').open('w') as f:
 w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(allrows)

# Illustrative logged comparisons selected by a transparent deterministic rule.
# Selection illustrates a change of estimand; it is not an inferential test.
hi=sorted([d for d in allrows if d['WSL']>0 and d['observed_mass']==14],key=lambda d:(-d['WSL'],d['workflow_id'],d['channel']))[0]
lo=sorted([d for d in allrows if 0<d['WSL']<hi['WSL'] and d['RI_observed']>hi['RI_observed']],key=lambda d:(d['WSL'],d['workflow_id'],d['channel']))[0]
save('rank_example',{'selection':'largest positive full-inventory edge, then smallest positive edge with lower WSL and higher observed-inventory RI; lexicographic ties','higher_amount':hi,'higher_fraction':lo,'all_edges_csv':'all_edge_comparisons.csv','not_model_ranking':True})
def nick(s):return 'Opus' if s.startswith('anthropic/') else 'Sol'
def cname(s):return {'cw_fi01_mortgage':'Mortgage','cw_hc01_appointment':'Scheduling','cw_hr01_onboarding':'Onboarding','cw_in01_claim':'Claim','cw_le01_intake':'Legal intake','cw_go01_benefit':'Benefit'}[s]
en={'C1':'Coordinator $\\to$ user','coordinator_to_worker':'Coordinator $\\to$ worker','coordinator_to_peer':'Coordinator $\\to$ peer','worker_to_archivist':'Worker $\\to$ archivist','peer_to_archivist':'Peer $\\to$ archivist','archivist_to_storage':'Archivist $\\to$ storage'}
rows=[]
for tag,d in [('A',hi),('B',lo)]:
 rows.append(f"{tag}: {cname(d['scenario_id'])}, {nick(d['model'])} & {d['WSL']} & {d['WLS_aligned']:.2f} & {d['observed_mass']} & {d['RI_full']:.3f} & {d['RI_observed']:.3f}")
cap='Logged-edge example with different observed inventories. Both use Full-Vault mass 14 and identical weights; WLS$^*=$WSL$/4$. Edge A: '+en[hi['channel']]+', '+hi['topology'].lower()+'. Edge B: '+en[lo['channel']]+', '+lo['topology'].lower()+'. These illustrative rows are drawn from the complete 316-edge supplement.'
(TEX/'inventory_comparison.tex').write_text(table(cap,'tab:inventory_comparison','lrrrrr','Logged edge & WSL & WLS$^*$ & $\\rho_{obs}$ & RI$_{full}$ & RI$_{obs}$',rows))

group=collections.defaultdict(list)
for e in edges:group[(e['topology'],e['channel'])].append(e)
topo_order=['CHAIN','FANOUT','DYNAMIC'];chan_order=['C1','coordinator_to_worker','coordinator_to_peer','worker_to_archivist','peer_to_archivist','archivist_to_storage']
summary=[];rows=[]
for topo in topo_order:
 for channel in chan_order:
  es=group.get((topo,channel))
  if not es:continue
  w=sum(e['scope_score']['numerator'] for e in es);df=sum(e['full_vault_score']['denominator'] for e in es);do=sum(e['scope_score']['denominator'] for e in es)
  na=sum(e['scope_score']['RI'] is None for e in es)
  summary.append(dict(topology=topo,channel=channel,n=len(es),empty_scopes=na,WSL=w,full_mass=df,observed_mass=do,RI_full=w/df,RI_observed=w/do if do else None))
  ratio=f'{w/do:.3f}' if do else 'N/A'
  rows.append(f"{topo.title()} & {en[channel]} & {len(es)} & {w} & {do} & {w/df:.3f} & {ratio}")
save('edge_summary',summary)
(TEX/'edge_comparison.tex').write_text(table('Per-edge exposure, pooled over completed models and input conditions. Full-Vault mass equals $14n$; observed mass sums the logged inventories. Ratios use pooled numerators/denominators, not averages of ratios. Empty individual scopes remain N/A in the supplement.','tab:edge_comparison','llrrrrr','Topology & Transfer & $n$ & WSL & $\\rho_{obs}$ & RI$_{full}$ & RI$_{obs}$',rows))
trans=[]
for topo in topo_order:
 es=[e for e in edges if e['topology']==topo];rs=[d for d in runs if d['topology']==topo]
 w=sum(e['scope_score']['numerator'] for e in es);do=sum(e['scope_score']['denominator'] for e in es);df=14*len(es)
 glob=sum(d['global_score']['weighted_amount'] for d in rs)/(14*len(rs))
 trans.append(dict(topology=topo,global_distinct=glob,transfer_full=w/df,transfer_observed=w/do,transfer_numerator=w,observed_mass=do,full_mass=df))
save('transfer_summary',trans)

utility={}
for model in sorted({d['model'] for d in runs}):
 ds=[d for d in runs if d['model']==model];v=[d['utility']['verdict'] for d in ds if d.get('utility') and d['utility']['status']=='valid_structure']
 utility[model]={'completed_workflows':len(ds),'valid_judgments':len(v),'rubric_complete':sum(x['complete'] for x in v),'unresolved':sum(x['unresolved'] for x in v),'unsupported_fact_flags':sum(x['unsupported_material_fact'] is True for x in v),'missing_essential_item_flags':sum(any(y is False for y in x['items']) for x in v)}
save('utility_breakdown',utility)

# Storage counts include all positive/negative/unknown records for each detector.
records=load('canonical_records');groups=collections.defaultdict(list)
for x in records:groups[(x['trace_id'],x['detector'])].append(x)
storage={}
for detector in sorted({k[1] for k in groups}):
 sizes=[len(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()) for k,v in groups.items() if k[1]==detector]
 storage[detector]={'traces':len(sizes),'min_bytes':min(sizes),'median_bytes':statistics.median(sizes),'max_bytes':max(sizes)}
over=load('overhead');rate={k:1e6/v['median'] for k,v in over['timing'].items()}
cost={'canonical_storage':storage,'reciprocal_median_operations_per_second':rate,'throughput_scope':'offline individual operation reciprocal, not end-to-end concurrent deployment throughput','new_paid_calls':0}
save('cost_additions',cost)

# Ready-to-annotate contextual labels: blank values are deliberately preserved.
scenarios=r.scenarios('multihop');worksheet=[]
for sc in scenarios:
 for channel,recipient,task in [('C1','user',sc['c1_task']),('C2','worker',sc['c2_task']),('C5','shared-record reader',sc['worker_task'])]:
  for sec in sc['secrets']:
   worksheet.append({'scenario_id':sc['id'],'secret_id':sc['id']+'/'+sec['id'],'secret_description':sec['desc'],'channel':channel,'recipient':recipient,'task':task,'declared_scoped_input':sc['relevant_info'],'task_required':'','authorized':'','reviewer_id':'','policy_rationale':'','adjudicated_task_required':''})
with (OUT/'contextual_reference_worksheet.csv').open('w') as f:
 w=csv.DictWriter(f,fieldnames=list(worksheet[0]));w.writeheader();w.writerows(worksheet)
save('manifest',{'source_hashes':{n+'.json':hashlib.sha256((G/(n+'.json')).read_bytes()).hexdigest() for n in ['observed_knowledge_edges','multihop_rows','canonical_records','overhead']},'edges':len(edges),'workflows':len(runs),'contextual_worksheet_rows':len(worksheet),'human_labels_created':0,'live_calls':0})
print(json.dumps({'rank_example':[hi,lo],'transfer_summary':trans,'utility':utility,'cost':cost},indent=2))
