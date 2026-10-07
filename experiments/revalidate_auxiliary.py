"""Parse saved auxiliary responses; strip only complete JSON fences, never repair labels."""
import json
import runner as r
import analysis as a
from auxiliary_campaign import validate_utility
scs={s['id']:s for s in r.scenarios()};rub={x['scenario_id']:x for x in json.loads((r.HERE/'utility_rubrics.json').read_text())['cases']}
front={d['request_id']:d for p in (r.STATE/'responses').glob('*.json') if (d:=json.loads(p.read_text()))['meta'].get('experiment')=='frontier'}
for kind in ['exposure','exposure_context','utility','utility_context']:
 for p in (r.STATE/'auxiliary_v2'/kind).glob('*.json'):
  d=json.loads(p.read_text());raw=json.loads((r.STATE/'responses'/(d['request_id']+'.json')).read_text());d.setdefault('initial_parse_status',d['status'])
  try:
   if kind.startswith('exposure'):
    f=front[d['source_trace_id']];v=a.validate_judge(r.content(raw),r.content(f),scs[f['meta']['scenario_id']]['secrets'])
   else:
    work=json.loads((r.STATE/'workflows_v2'/(d['source_workflow']+'.json')).read_text());v=validate_utility(r.content(raw),work['channels']['archivist_to_storage'],rub[work['scenario_id']])
   d.update(status='valid_structure',verdict=v,parser='strict JSON; optional surrounding JSON code fence')
  except (ValueError,TypeError,KeyError) as exc:d.update(status='invalid_schema',verdict=None,validation_error=str(exc))
  r.save(p,d)
