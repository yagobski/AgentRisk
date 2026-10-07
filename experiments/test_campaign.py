import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
import campaign as c
import runner as r

class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.cfg=r.config(r.HERE/'config.example.json'); self.cfg['total_budget_usd']=45
        self.cfg['stage_budgets_usd']['frontier']=20
        self.calls=0; self.lock=threading.Lock()
    def fake(self,body,key,timeout):
        with self.lock: self.calls+=1
        time.sleep(.001)
        return {'id':'test','model':body['model'],'usage':{'cost':.001},
                'choices':[{'finish_reason':'stop','message':{'content':'Test output'}}]}
    def bill(self,key): return {'usage':0,'limit':50,'limit_remaining':50,'limit_reset':None}
    def test_three_repeats_pilot_reused(self):
        client=c.Client(self.cfg,'TEST',self.tmp.name,self.fake,self.bill)
        with contextlib.redirect_stdout(io.StringIO()): c.frontier(client,True); c.frontier(client,False)
        self.assertEqual(self.calls,216)
        self.assertEqual(len(client.ledger.rows),216)
        self.assertAlmostEqual(sum(v['charged_or_reserved_usd'] for v in client.ledger.rows.values()),.216)
    def test_server_spend_checked_before_new_call(self):
        client=c.Client(self.cfg,'TEST',self.tmp.name,self.fake,lambda key:{'usage':44.999,'limit_remaining':5.001})
        model,msg,meta=c.frontier_jobs(self.cfg,True)[0]
        with self.assertRaises(r.Blocked): client.call(model,msg,'pilot',meta)
        self.assertEqual(self.calls,0)
    def test_concurrent_reservations_cannot_overspend(self):
        self.cfg['total_budget_usd']=.02
        client=c.Client(self.cfg,'TEST',self.tmp.name,self.fake,self.bill)
        with self.assertRaises(r.Blocked): c.frontier(client,True)
        self.assertEqual(self.calls,0)
    def test_requests_have_distinct_repetition_ids(self):
        jobs=c.frontier_jobs(self.cfg)
        self.assertEqual(len({r.request_id(r.payload(self.cfg,m,msg),meta) for m,msg,meta in jobs}),216)
    def test_refusal_keeps_reservation_and_never_retries(self):
        def refusal(body,key,timeout):
            self.calls+=1
            return {'id':'refusal','model':body['model'],'choices':[{'finish_reason':'content_filter','message':{'content':None,'refusal':'Provider policy refusal'}}]}
        client=c.Client(self.cfg,'TEST',self.tmp.name,refusal,self.bill)
        model,msg,meta=c.frontier_jobs(self.cfg,True)[0]
        for _ in range(2):
            with self.assertRaises(c.Excluded):client.call(model,msg,'pilot',meta)
        self.assertEqual(self.calls,1)
        row=next(iter(client.ledger.rows.values()))
        self.assertTrue(row['reconciled']);self.assertGreater(row['charged_or_reserved_usd'],0)
if __name__=='__main__': unittest.main()
