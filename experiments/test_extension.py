import copy
import json
import tempfile
import unittest
import contextlib
import io
from pathlib import Path
import runner as r
import analysis as a
import scope
import evaluate_reference as e


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.cfg=r.config(r.HERE/'config.example.json')
        self.model=self.cfg['models'][0]
        self.msg=r.messages('System','Task')
        self.calls=0

    def transport(self,body,key,timeout):
        self.calls+=1
        return {'id':'gen-test','model':body['model'],'provider':'Anthropic',
                'choices':[{'finish_reason':'stop','message':{'content':'No private details.'}}],
                'usage':{'cost':.001,'prompt_tokens':20,'completion_tokens':8}}

    def client(self,transport=None):
        return r.Client(self.cfg,'SECRET-TEST',self.temp.name,transport or self.transport)

    def test_repeat_and_resume_no_charge(self):
        c=self.client(); first=c.call(self.model,self.msg,'pilot',{'id':1})
        second=self.client().call(self.model,self.msg,'frontier',{'id':1})
        self.assertEqual(first,second); self.assertEqual(self.calls,1)
        self.assertNotIn('SECRET-TEST', ''.join(p.read_text() for p in Path(self.temp.name).rglob('*.json')))

    def test_zero_remaining_budget_before_network(self):
        self.cfg['total_budget_usd']=.0001
        with self.assertRaises(r.Blocked): self.client().call(self.model,self.msg,'pilot',{})
        self.assertEqual(self.calls,0)

    def test_stage_cap(self):
        self.cfg['stage_budgets_usd']['pilot']=.0001
        with self.assertRaises(r.Blocked): self.client().call(self.model,self.msg,'pilot',{})
        self.assertEqual(self.calls,0)

    def test_reservation_written_before_send(self):
        def check(body,key,timeout):
            rows=json.loads((Path(self.temp.name)/'ledger.json').read_text())
            self.assertEqual(next(iter(rows.values()))['status'],'reserved')
            return self.transport(body,key,timeout)
        self.client(check).call(self.model,self.msg,'pilot',{})

    def test_timeout_never_retried(self):
        def fail(*args): self.calls+=1; raise TimeoutError('SECRET-TEST')
        for _ in range(2):
            with self.assertRaises(r.Blocked): self.client(fail).call(self.model,self.msg,'pilot',{})
        self.assertEqual(self.calls,1)

    def test_missing_cost_retains_allowance(self):
        def missing(*args):
            response=self.transport(*args); response['usage'].pop('cost'); return response
        c=self.client(missing)
        with self.assertRaises(r.Blocked): c.call(self.model,self.msg,'pilot',{})
        row=next(iter(c.ledger.rows.values()))
        self.assertEqual(row['status'],'cost_unknown')
        self.assertEqual(row['charged_or_reserved_usd'],row['allowance_usd'])

    def test_uncertain_request_blocks_other_stage(self):
        def fail(*args): self.calls+=1; raise TimeoutError()
        with self.assertRaises(r.Blocked): self.client(fail).call(self.model,self.msg,'pilot',{'id':1})
        with self.assertRaises(r.Blocked): self.client().call(self.model,self.msg,'frontier',{'id':2})
        self.assertEqual(self.calls,1)

    def test_empty_response_not_scored(self):
        def empty(*args):
            response=self.transport(*args); response['choices'][0]['message']['content']=''; return response
        with self.assertRaises(r.Blocked): self.client(empty).call(self.model,self.msg,'pilot',{})

    def test_nonfinite_cost_not_accepted(self):
        def bad(*args):
            response=self.transport(*args); response['usage']['cost']=float('nan'); return response
        # Strict JSON serialization refuses to persist NaN. Reservation remains durable.
        with self.assertRaises(ValueError): self.client(bad).call(self.model,self.msg,'pilot',{})
        row=next(iter(r.Ledger(self.temp.name).rows.values()))
        self.assertEqual(row['status'],'reserved')

    def test_catalog_price_drift_blocks(self):
        data={'data':[{'id':m['id'],'pricing':{'prompt':'1','completion':'1'},
                       'supported_parameters':['max_tokens','reasoning']} for m in self.cfg['models']]}
        with self.assertRaises(ValueError): r.check_catalog(self.cfg,data)

    def test_catalog_unsupported_temperature_blocks(self):
        data={'data':[{'id':m['id'],'pricing':{'prompt':'0','completion':'0'},
                       'supported_parameters':['max_tokens','reasoning']} for m in self.cfg['models']]}
        self.cfg['temperature']=0
        with self.assertRaises(ValueError): r.check_catalog(self.cfg,data)

    def test_truncation_not_scored(self):
        def truncated(*args):
            response=self.transport(*args); response['choices'][0]['finish_reason']='length'; return response
        c=self.client(truncated)
        with self.assertRaises(r.Blocked): c.call(self.model,self.msg,'pilot',{})
        row=next(iter(c.ledger.rows.values())); self.assertEqual(row['status'],'incomplete_length')
        self.assertEqual(row['actual_cost_usd'],.001)

    def test_returned_model_mismatch(self):
        def mismatch(*args):
            response=self.transport(*args); response['model']='other'; return response
        with self.assertRaises(r.Blocked): self.client(mismatch).call(self.model,self.msg,'pilot',{})

    def test_expensive_response_stops(self):
        def expensive(*args):
            response=self.transport(*args); response['usage']['cost']=100; return response
        with self.assertRaises(r.Blocked): self.client(expensive).call(self.model,self.msg,'pilot',{})

    def test_protocol_change_changes_request_id(self):
        body=r.payload(self.cfg,self.model,self.msg)
        changed=copy.deepcopy(body); changed['reasoning']['effort']='high'
        self.assertNotEqual(r.request_id(body,{}),r.request_id(changed,{}))

    def test_cache_tampering_rejected(self):
        self.client().call(self.model,self.msg,'pilot',{})
        path=next((Path(self.temp.name)/'responses').glob('*.json'))
        doc=json.loads(path.read_text()); doc['response']['choices'][0]['message']['content']='altered'; r.save(path,doc)
        with self.assertRaises(r.Blocked): self.client().call(self.model,self.msg,'pilot',{})

    def test_lock_prevents_parallel_spend(self):
        with r.exclusive(self.temp.name):
            with self.assertRaises(r.Blocked):
                with r.exclusive(self.temp.name): pass

    def test_no_key_in_public_manifest(self):
        self.cfg['api_key']='SECRET-TEST'
        self.assertNotIn('SECRET-TEST',json.dumps(r.public_config(self.cfg)))

    def test_pilot_subset_and_identical_payload(self):
        full=r.estimate(self.cfg,'frontier'); pilot=r.estimate(self.cfg,'pilot')
        self.assertEqual(full['scheduled_calls'],72); self.assertEqual(pilot['scheduled_calls'],6)
        self.assertTrue(set(pilot['request_ids']) <= set(full['request_ids']))


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        self.secrets=[{'id':'x','severity':1,'markers':['sample'], 'desc':'sample'},
                      {'id':'z','severity':4,'markers':['111-222-3333'],'desc':'phone'}]

    def test_binary_fraction_weighted_distinct(self):
        result=a.score(self.secrets,{'x':False,'z':True})
        self.assertEqual(result['binary_any'],1); self.assertEqual(result['secret_fraction'],.5)
        self.assertEqual(result['weighted_amount'],4); self.assertEqual(result['RI'],.8)

    def test_missing_judgment_is_not_zero(self):
        self.assertIsNone(a.score(self.secrets,{'x':None,'z':False})['RI'])

    def test_invalid_weights_cannot_produce_a_valid_score(self):
        for weight in [0, -1, float('nan'), float('inf'), -float('inf'), True, '4', None]:
            with self.subTest(weight=weight):
                with self.assertRaises(ValueError):
                    a.score([{'id':'x','severity':weight},{'id':'z','severity':4}],
                            {'x':True,'z':False})
                with self.assertRaises(ValueError):
                    a.edge_score(['x'], ['x'], {'x':weight})

    def test_nonempty_string_identity_required(self):
        for sid in ['', '   ', None, 1]:
            with self.subTest(identity=sid):
                with self.assertRaises(ValueError):
                    a.score([{'id':sid,'severity':1}], {sid:True})
                with self.assertRaises(ValueError):
                    a.edge_score([sid], [sid], {sid:1})

    def test_malformed_detection_status_is_not_an_unknown_label(self):
        for status in ['false', 0, 1, [], {}]:
            with self.subTest(status=status), self.assertRaises(ValueError):
                a.score(self.secrets, {'x':status,'z':False})

    def test_finite_weights_with_overflowing_total_rejected(self):
        weights={'x':1e308,'z':1e308}
        with self.assertRaises(ValueError):
            a.score([{'id':k,'severity':v} for k,v in weights.items()],{'x':True,'z':False})
        with self.assertRaises(ValueError):
            a.edge_score(weights,['x'],weights)
        with self.assertRaises(ValueError):
            a.aggregate([{'inventory':['x'],'exposed':['x']}]*2,['x'],{'x':1e308})

    def test_custom_positive_weights_preserve_scale_invariance(self):
        for factor in [.25, 1, 100]:
            score=a.edge_score(['x','z'],['z'],{'x':factor,'z':4*factor})
            self.assertAlmostEqual(score['RI'],.8)

    def test_unknown_secret_fails(self):
        with self.assertRaises(ValueError): a.score(self.secrets,{'x':False,'foreign':True})

    def test_dlp_coverage_and_unknown(self):
        result=a.dlp_verdict('phone: 111-222-3333',self.secrets)
        self.assertTrue(result['z']); self.assertIsNone(result['x'])

    def test_judge_string_false_rejected(self):
        raw=json.dumps({'x':{'disclosed':'false','evidence':''},'z':{'disclosed':False,'evidence':''}})
        with self.assertRaises(ValueError): a.validate_judge(raw,'output',self.secrets)

    def test_judge_missing_not_filled(self):
        with self.assertRaises(ValueError): a.validate_judge('{}','output',self.secrets)

    def test_judge_invented_span_rejected(self):
        raw=json.dumps({'x':{'disclosed':True,'evidence':'not present'},'z':{'disclosed':False,'evidence':''}})
        with self.assertRaises(ValueError): a.validate_judge(raw,'output',self.secrets)

    def test_no_joint_coverage_not_perfect_agreement(self):
        self.assertIsNone(a.agreement({'x':True},{'x':None})['agreement'])

    def test_global_vs_transfer(self):
        edges=[{'inventory':['x','y','z'],'exposed':['z','z']},{'inventory':['y','z'],'exposed':['z']}]
        result=a.aggregate(edges,['x','y','z'],{'x':1,'y':2,'z':4})
        self.assertAlmostEqual(result['global_distinct']['RI'],4/7)
        self.assertAlmostEqual(result['transfer_weighted'],8/13)

    def test_empty_scope_not_safe_zero(self):
        self.assertIsNone(a.edge_score([],[],{})['RI'])

    def test_outside_scope_rejected(self):
        with self.assertRaises(ValueError): a.edge_score(['x'],['z'],{'x':1,'z':4})

    def test_revocation_keeps_knowledge(self):
        ev=[{'sequence':1,'agent':'A','kind':'grant','secrets':['z']},
            {'sequence':2,'agent':'A','kind':'retrieve','secrets':['z']},
            {'sequence':3,'agent':'A','kind':'revoke','secrets':['z']},
            {'sequence':4,'agent':'A','kind':'handoff','recipient':'B','secrets':['z']},
            {'sequence':5,'agent':'B','kind':'handoff','recipient':'C','secrets':['z']}]
        self.assertEqual(scope.replay(ev)[-1]['inventory'],['z'])

    def test_retrieval_without_access_rejected(self):
        with self.assertRaises(ValueError): scope.replay([{'sequence':1,'agent':'A','kind':'retrieve','secrets':['z']}])

    def test_clear_requires_evidence(self):
        with self.assertRaises(ValueError): scope.replay([{'sequence':1,'agent':'A','kind':'clear','secrets':['z']}])

    def test_no_fake_channel_fallback(self):
        with self.assertRaises(r.Blocked): r.strict_channels('no channel markers')

    def test_fixed_denominator_preserves_ranking(self):
        vals=[a.edge_score(['x','z'],exposed,{'x':1,'z':4}) for exposed in ([],['x'],['z'],['x','z'])]
        self.assertEqual(sorted(range(4),key=lambda i: vals[i]['numerator']),
                         sorted(range(4),key=lambda i: vals[i]['RI']))

    def test_native_weights_not_invented(self):
        sc={'id':'case','secrets':self.secrets}
        self.assertIsNone(e.native_wls(sc,{'x':False,'z':True},{}))
        mapping={('case','case/x'):(1,True),('case','case/z'):(.5,True)}
        self.assertEqual(e.native_wls(sc,{'x':False,'z':True},mapping),.5)

    def test_quality_unknown_not_true_negative(self):
        q=e.quality([(True,True),(False,True),(None,False)],3)
        self.assertEqual(q['jointly_resolved'],2); self.assertEqual(q['tn'],0)
        self.assertEqual(q['recall'],.5)

    def test_no_reference_no_accuracy(self):
        self.assertIsNone(e.quality([(True,None)],1)['agreement'])


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.old_state=r.STATE; r.STATE=Path(self.temp.name)
        self.addCleanup(setattr,r,'STATE',self.old_state)
        self.cfg=r.config(r.HERE/'config.example.json'); self.calls=0

    def fake(self,body,key,timeout):
        self.calls+=1
        text='A concise task record with no registered sensitive detail.'
        if 'COORDINATOR' in body['messages'][0]['content']:
            text='===USER_MESSAGE===\nRequest acknowledged.\n===HANDOFF_NOTE===\nPlease process the requested task.'
        return {'id':str(self.calls),'model':body['model'],
                'choices':[{'finish_reason':'stop','message':{'content':text}}],
                'usage':{'cost':.001,'prompt_tokens':20,'completion_tokens':10}}

    def test_pilot_then_frontier_72_total_mock_calls(self):
        client=r.Client(self.cfg,'TEST-ONLY',r.STATE,self.fake)
        with contextlib.redirect_stdout(io.StringIO()):
            r.run_frontier(client,'pilot'); r.run_frontier(client,'frontier')
        self.assertEqual(self.calls,72)
        rows=list(a.analyzed_rows(a.frontier_rows(self.cfg)))
        self.assertEqual(len(rows),72)
        self.assertTrue(all(x['scored_rows']==36 for x in a.summarize(rows).values()))

    def test_multihop_72_turns_24_workflows(self):
        client=r.Client(self.cfg,'TEST-ONLY',r.STATE,self.fake)
        with contextlib.redirect_stdout(io.StringIO()): r.run_multihop(client)
        self.assertEqual(self.calls,72)
        docs=list((r.STATE/'workflows').glob('*.json')); self.assertEqual(len(docs),24)
        sample=json.loads(docs[0].read_text())
        self.assertEqual(len(sample['access_log']),3)
        self.assertEqual(len(sample['channels']),4)
        self.assertEqual(sample['utility_status'],'requires_blinded_rubric_review')


if __name__=='__main__': unittest.main()
