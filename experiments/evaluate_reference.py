#!/usr/bin/env python3
"""Compare detectors to completed independent reference CSV; blanks stay unknown."""
import argparse
import csv
import json
import math
from pathlib import Path
import analysis as a
import runner as r


def boolean(text):
    if text in ('true','1'): return True
    if text in ('false','0'): return False
    if text in ('','unknown'): return None
    raise ValueError('Use true/false/unknown (or blank), not free-text labels')


def quality(pairs, total):
    valid=[(x,y) for x,y in pairs if type(x) is bool and type(y) is bool]
    n=len(valid)
    tp=sum(x and y for x,y in valid); tn=sum(not x and not y for x,y in valid)
    fp=sum(x and not y for x,y in valid); fn=sum(not x and y for x,y in valid)
    observed=(tp+tn)/n if n else None
    expected=(((tp+fp)*(tp+fn)+(tn+fn)*(tn+fp))/n**2) if n else None
    return {'total_registered':total,'jointly_resolved':n,'tp':tp,'tn':tn,'fp':fp,'fn':fn,
            'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None,
            'agreement':observed,
            'kappa':(observed-expected)/(1-expected) if expected is not None and expected < 1 else None}


def read_reference(path, rows):
    lookup={(row['trace_id'],row['scenario']['id']+'/'+sec['id']):(row,sec)
            for row in rows for sec in row['scenario']['secrets'] if row['output'] is not None}
    result={}
    with Path(path).open(newline='') as f:
        for ref in csv.DictReader(f):
            key=(ref['trace_id'],ref['secret_id'])
            if key in result or key not in lookup:
                raise ValueError('Duplicate or unknown reference identity')
            row,sec=lookup[key]
            if ref['trace_sha256'] != row['trace_sha256']:
                raise ValueError('Reference bound to a different trace')
            value=boolean(ref['disclosed'])
            if value is not None and not ref['reviewer_id'].strip():
                raise ValueError('Resolved reference needs a reviewer identifier')
            if value is True and (not ref['evidence_span'] or ref['evidence_span'] not in row['output']):
                raise ValueError('Positive reference requires literal evidence')
            result[key]=value
    return result


def read_weights(path):
    result={}
    if path is None: return result
    with Path(path).open(newline='') as f:
        for row in csv.DictReader(f):
            key=(row['scenario_id'],row['secret_id'])
            if key in result: raise ValueError('Duplicate weight identity')
            result[key]=None
            if row['status']!='reviewed': continue
            if not all(row[k].strip() for k in ('reviewer_id','native_policy_source','weight_source')):
                raise ValueError('Reviewed mapping requires reviewer and sources')
            weight=float(row['native_weight']); eligible=boolean(row['native_counting_eligibility'])
            if not math.isfinite(weight) or not 0 <= weight <= 1 or eligible is None:
                raise ValueError('Incomplete/invalid native mapping')
            result[key]=(weight,eligible)
    return result


def native_wls(sc, disclosed, mapping):
    rows=[(s['id'],mapping.get((sc['id'],sc['id']+'/'+s['id']))) for s in sc['secrets']]
    if any(v is None or type(disclosed.get(sid)) is not bool for sid,v in rows): return None
    return sum(w for sid,(w,eligible) in rows if eligible and disclosed[sid])


def evaluate(rows, refs, mapping, judgment_dir=None):
    pairs={k:[] for k in ('lexical','regex_dlp','semantic')}; delta={k:[] for k in pairs}
    native=[]; total=0
    for row in rows:
        if row['output'] is None: continue
        sc=row['scenario']; total+=len(sc['secrets'])
        reference={sec['id']:refs.get((row['trace_id'],sc['id']+'/'+sec['id'])) for sec in sc['secrets']}
        methods={'lexical':row['lexical'],'regex_dlp':row['regex_dlp'],
                 'semantic':{s['id']:None for s in sc['secrets']}}
        path=Path(judgment_dir)/(row['trace_id']+'.json') if judgment_dir else None
        if path and path.exists():
            saved=json.loads(path.read_text())
            if saved['source_trace_id'] != row['trace_id']: raise ValueError('Judge trace mismatch')
            if saved['status']=='valid_structure_not_validated_accuracy':
                methods['semantic']=saved['verdict']
                if set(methods['semantic']) != set(reference): raise ValueError('Judge IDs mismatch')
        ref_ri=a.score(sc['secrets'],reference)['RI']
        for name,verdict in methods.items():
            pairs[name].extend((verdict.get(sid),ref) for sid,ref in reference.items())
            ri=a.score(sc['secrets'],verdict)['RI']
            if ri is not None and ref_ri is not None: delta[name].append(ri-ref_ri)
        native.append({'trace_id':row['trace_id'],'model':row['model'],
                       'native_weight_and_policy_WLS':native_wls(sc,row['lexical'],mapping),
                       'aligned_weight_amount':row['lexical_scores']['weighted_amount'],
                       'aligned_RI':row['lexical_scores']['RI']})
    return {'reference_comparison':{k:quality(v,total) for k,v in pairs.items()},
            'per_trace_RI_minus_reference':delta,'metric_comparison':native,
            'native_WLS_note':'Weighted field sum using reviewed native weights and eligibility; null if any mapping missing. '
                              'Not a rerun of the published AgentLeak benchmark. Native policy and aligned exposure rows are different estimands.',
            'inference':'Descriptive only; secret rows within a trace are not independent participants.'}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--rows',type=Path,required=True)
    ap.add_argument('--reference',type=Path,required=True)
    ap.add_argument('--weights',type=Path)
    ap.add_argument('--judgments',type=Path)
    ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args(); rows=json.loads(args.rows.read_text())
    refs=read_reference(args.reference,rows); mapping=read_weights(args.weights)
    r.save(args.out,evaluate(rows,refs,mapping,args.judgments))


if __name__=='__main__': main()
