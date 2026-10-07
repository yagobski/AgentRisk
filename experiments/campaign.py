#!/usr/bin/env python3
"""Budgeted revision campaign. Shared durable ledger, up to four simultaneous calls."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import math
import os
from pathlib import Path
import random
import threading
import time
import urllib.request
import urllib.error
import runner as r

LIMIT = 50.0
SOFT_LIMIT = 45.0
CAMPAIGN = 'revision-20260924-v2'

class Excluded(r.Blocked):
    """Recorded provider refusal; excluded, never retried or scored as zero."""
    pass


def account(key):
    req=urllib.request.Request(r.API+'/key',headers={'Authorization':'Bearer '+key})
    with urllib.request.urlopen(req,timeout=30) as response:
        d=json.load(response)['data']
    result={k:d.get(k) for k in ('limit','limit_remaining','limit_reset','usage')}
    if result['limit'] is None or result['limit']>LIMIT or result['limit_reset'] is not None:
        raise r.Blocked('Require a non-resetting server key limit of at most USD 50')
    if not isinstance(result['usage'],(int,float)) or not math.isfinite(result['usage']):
        raise r.Blocked('Account usage unavailable')
    return result


class Client:
    def __init__(self,cfg,key,state=r.STATE,transport=r.post,billing=account):
        self.cfg=cfg; self.key=key; self.transport=transport; self.billing=billing
        self.ledger=r.Ledger(state); self.lock=threading.RLock(); self.active=set()

    def call(self,model,msg,stage,meta):
        body=r.payload(self.cfg,model,msg); rid=r.request_id(body,meta)
        raw_path=self.ledger.root/'responses'/(rid+'.json')
        allowance=r.reserve_cost(self.cfg,model,msg)
        with self.lock:
            previous=self.ledger.rows.get(rid)
            if previous and previous['status']=='provider_refusal':
                raise Excluded('Previously recorded provider refusal: '+rid)
            if previous and previous['status']=='ok':
                cached=json.loads(raw_path.read_text())
                if cached['response_sha256']!=r.digest(cached['response']) or cached['request_sha256']!=r.digest(body):
                    raise r.Blocked('Cached response changed')
                return cached
            if previous: raise r.Blocked('Unresolved request, manual billing reconciliation required: '+rid)
            if any(v['status']!='ok' and k not in self.active and not v.get('reconciled')
                   for k,v in self.ledger.rows.items()):
                raise r.Blocked('Unreconciled prior request blocks new spending')
            bill=self.billing(self.key)
            spent=sum(v['charged_or_reserved_usd'] for v in self.ledger.rows.values())
            pending=sum(self.ledger.rows[k]['allowance_usd'] for k in self.active)
            stage_spent=sum(v['charged_or_reserved_usd'] for v in self.ledger.rows.values() if v['stage']==stage)
            cap=min(SOFT_LIMIT,self.cfg['total_budget_usd'])
            if (spent+allowance>cap or bill['usage']+pending+allowance>cap
                or allowance>bill['limit_remaining']-pending
                or stage_spent+allowance>self.cfg['stage_budgets_usd'][stage]
                or allowance>self.cfg['max_request_usd']):
                raise r.Blocked('Budget guard stopped BEFORE network generation')
            self.ledger.rows[rid]={'status':'reserved','stage':stage,'started_at':r.utc(),
                                  'charged_or_reserved_usd':allowance,'allowance_usd':allowance,
                                  'account_usage_before':bill['usage'],'meta':meta}
            self.active.add(rid); self.ledger.flush()
        start=time.perf_counter()
        try:
            response=self.transport(body,self.key,self.cfg['timeout_seconds'])
        except Exception as exc:
            detail={'error_type':type(exc).__name__}
            if isinstance(exc,urllib.error.HTTPError):
                detail['http_status']=exc.code
                detail['body']=exc.read().decode('utf-8',errors='replace').replace(self.key,'[REDACTED]')[:5000]
            r.save(self.ledger.root/'errors'/(rid+'.json'),detail)
            with self.lock:
                self.ledger.rows[rid].update(status='transport_uncertain',error_type=detail['error_type'])
                self.active.discard(rid); self.ledger.flush()
            raise r.Blocked('Transport error saved; no automatic retry: '+rid) from None
        record={'request_id':rid,'request_sha256':r.digest(body),'request':body,'meta':meta,
                'response':response,'response_sha256':r.digest(response),'recorded_at':r.utc(),
                'wall_seconds':time.perf_counter()-start}
        r.save(raw_path,record)
        cost=(response.get('usage') or {}).get('cost'); status='ok'
        choice=(response.get('choices') or [{}])[0]; text=(choice.get('message') or {}).get('content')
        if not isinstance(cost,(int,float)) or isinstance(cost,bool) or not math.isfinite(cost) or cost<0:
            status='cost_unknown'
        elif cost>allowance: status='cost_exceeded_allowance'
        elif response.get('error') or not isinstance(text,str) or not text.strip(): status='empty_or_error'
        elif choice.get('finish_reason')!='stop': status='incomplete_'+str(choice.get('finish_reason'))
        elif response.get('model')!=model['id']: status='model_mismatch'
        if choice.get('finish_reason')=='content_filter' and (choice.get('message') or {}).get('refusal'):
            status='provider_refusal'
        with self.lock:
            row=self.ledger.rows[rid]
            if isinstance(cost,(int,float)) and not isinstance(cost,bool) and math.isfinite(cost) and cost>=0:
                row.update(charged_or_reserved_usd=cost,actual_cost_usd=cost)
            if status=='provider_refusal': row.update(reconciled=True,billing_note='Maximum reservation retained when cost absent; refusal excluded without retry')
            row.update(status=status,response_id=response.get('id'),finished_at=r.utc())
            self.active.discard(rid); self.ledger.flush()
        if status=='provider_refusal': raise Excluded('Provider refusal excluded without retry: '+rid)
        if status!='ok': raise r.Blocked('Recorded response excluded: '+status+' '+rid)
        print('SAVED',stage,model['id'],meta.get('scenario_id',''),meta.get('repeat',''),rid[:10],f'${cost:.6f}',flush=True)
        return record


def frontier_jobs(cfg,pilot=False):
    jobs=[]
    cases=r.scenarios()
    if pilot: cases=[cases[i] for i in (0,12,24)]
    for repeat in range(1 if pilot else 3):
        for sc in cases:
            msg=r.messages(r.legacy.AGENT_SYSTEM,f"TASK:\n{sc['instruction']}\n\nCONTEXT:\n{sc['context']}\n\nNow produce ONLY the requested deliverable.")
            for model in cfg['models']:
                meta={'campaign':CAMPAIGN,'experiment':'frontier','scenario_id':sc['id'],
                      'scenario_sha256':r.digest(sc),'repeat':repeat}
                jobs.append((model,msg,meta))
    random.Random(20260924).shuffle(jobs)
    return jobs


def batched(work,fn,workers=4):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for offset in range(0,len(work),workers):
            results=[pool.submit(fn,item) for item in work[offset:offset+workers]]
            errors=[]
            for future in results:
                try: future.result()
                except Exception as exc: errors.append(exc)
            if errors: raise errors[0]


def frontier(client,pilot=False):
    stage='pilot' if pilot else 'frontier'
    batched(frontier_jobs(client.cfg,pilot),lambda job:client.call(job[0],job[1],stage,job[2]),2 if pilot else 4)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('stage',choices=('pilot','frontier','status'))
    ap.add_argument('--config',type=Path,default=r.HERE/'config.local.json'); ap.add_argument('--live',action='store_true')
    args=ap.parse_args(); r.verify_originals(); cfg=r.config(args.config)
    cfg['total_budget_usd']=min(cfg['total_budget_usd'],SOFT_LIMIT)
    if args.stage=='status':
        bill=account(cfg['api_key']); ledger=r.Ledger(r.STATE)
        print(json.dumps({'account':bill,'requests':len(ledger.rows),'actual_or_reserved':sum(v['charged_or_reserved_usd'] for v in ledger.rows.values()),
                          'statuses':{s:sum(v['status']==s for v in ledger.rows.values()) for s in {v['status'] for v in ledger.rows.values()}}})); return
    jobs=frontier_jobs(cfg,args.stage=='pilot')
    manifest={'campaign':CAMPAIGN,'stage':args.stage,'created_at':r.utc(),'config':r.public_config(cfg),
              'requests':[{'id':r.request_id(r.payload(cfg,m,msg),meta),'meta':meta,'model':m['id']} for m,msg,meta in jobs],
              'repetitions':3,'execution':'four workers maximum, durable reservations, server key cap <=50, local cap45'}
    if not args.live:
        print(json.dumps({'calls':len(jobs),'allowance_usd':sum(r.reserve_cost(cfg,m,msg) for m,msg,meta in jobs)})); return
    if not cfg.get('live_enabled'): raise r.Blocked('Disabled configuration')
    with r.exclusive():
        r.save(r.STATE/'manifests'/(r.digest(manifest)+'.json'),manifest)
        r.save(r.STATE/'catalog_v2.json',r.check_catalog(cfg,r.catalog()))
        client=Client(cfg,cfg['api_key']); frontier(client,args.stage=='pilot')


if __name__=='__main__':
    try: main()
    except r.Blocked as exc:
        print('STOP:',str(exc),flush=True); raise SystemExit(2)
