"""Paired local capture replay on saved synthetic three-agent workflows; no inference."""
from pathlib import Path
import json,platform,random,statistics,sys,tempfile,time
R=Path(__file__).resolve().parents[1]
EX=Path('experiments')
sys.path.insert(0,str(EX));import runner as r
from multihop_campaign import active_workflows
docs=[d for p,d in active_workflows() if d['topology']=='CHAIN']
assert len(docs)==24
rows=[];rng=random.Random(20260924)
with tempfile.TemporaryDirectory(prefix='agentrisk_capture_') as td:
 for i in range(530):
  d=docs[i%len(docs)];order=[False,True];rng.shuffle(order);times={}
  for capture in order:
   t=time.perf_counter_ns()
   # Same saved channel payloads traverse the baseline and capture-enabled path.
   channels={key:value for key,value in d['channels'].items()}
   if capture:
    hashes={key:r.digest(value) for key,value in channels.items()}
    r.save(Path(td)/'captured.json',dict(channels=channels,channel_sha256=hashes,request_ids=d['request_ids'],captured_at=r.utc()))
   times[capture]=(time.perf_counter_ns()-t)/1e6
  if i>=30:rows.append(dict(baseline_ms=times[False],capture_ms=times[True],added_ms=times[True]-times[False]))
 def stat(key):
  v=sorted(x[key] for x in rows);return dict(median=statistics.median(v),p95=v[int(.95*(len(v)-1))])
 out=dict(scope='paired local replay of saved three-agent channels with SHA-256, timestamp, JSON serialization, flush, fsync and atomic replacement; excludes model inference, network collection and production contention',
  machine=platform.platform(),workflows=24,warmups=30,pairs=500,seed=20260924,new_model_calls=0,baseline_ms=stat('baseline_ms'),capture_ms=stat('capture_ms'),added_ms=stat('added_ms'),samples=rows)
(R/'evidence/capture_overhead.json').write_text(json.dumps(out,indent=2))
print(json.dumps({k:v for k,v in out.items() if k!='samples'},indent=2))
