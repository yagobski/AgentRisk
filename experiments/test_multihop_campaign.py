import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import runner as r
import multihop_campaign as m

class MultiTests(unittest.TestCase):
    def test_all_topologies_and_revocation(self):
        cfg=r.config(r.HERE/'config.example.json')
        class Fake:
            def __init__(self): self.cfg=cfg; self.calls=0
            def call(self,model,msg,stage,meta):
                self.calls+=1
                text='===USER_MESSAGE===\nDone\n===HANDOFF_NOTE===\nHandoff' if meta['turn']=='coordinator' else 'Record'
                return {'request_id':str(self.calls),'recorded_at':r.utc(),'wall_seconds':.01,
                        'response':{'usage':{'cost':.001},'choices':[{'message':{'content':text}}]}}
        client=Fake()
        with tempfile.TemporaryDirectory() as tmp, patch.object(r,'STATE',Path(tmp)), contextlib.redirect_stdout(io.StringIO()):
            for job in m.jobs(cfg): m.workflow(client,job)
            preserved={p.name:p.read_bytes() for p in (Path(tmp)/'workflows_v2').glob('*.json')}
            for job in m.jobs(cfg): m.workflow(client,job)
            self.assertEqual(preserved,{p.name:p.read_bytes() for p in (Path(tmp)/'workflows_v2').glob('*.json')})
            import json
            docs=[json.loads(p.read_text()) for p in (Path(tmp)/'workflows_v2').glob('*.json')]
            self.assertEqual(len(docs),72)
            self.assertEqual(client.calls,240)
            for d in docs:
                self.assertEqual(len(d['request_ids']),4 if d['topology']=='FANOUT' else 3)
                if d['topology']=='DYNAMIC':
                    self.assertEqual([x['event'] for x in d['access_log'] if x['event']!='model_call'],
                                     ['grant','retrieve','revoke','retrieval_denied_after_revocation'])
                    self.assertTrue(next(x for x in d['access_log'] if x['event']=='revoke')['retained_in_context'])
    def test_latest_round_refusal_does_not_fall_back(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(r,'STATE',Path(tmp)):
            doc={'scenario_id':'case','model':'model','condition':'FULL','topology':'DYNAMIC','execution_round':0}
            r.save(Path(tmp)/'workflows_v2/a.json',doc)
            self.assertEqual(len(m.active_workflows()),1)
            r.save(Path(tmp)/'workflow_exclusions/b.json',dict(doc,execution_round=1,status='provider_refusal'))
            self.assertEqual(m.active_workflows(),[])
if __name__=='__main__': unittest.main()
