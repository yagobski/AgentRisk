#!/usr/bin/env python3
"""Offline audit-contract examples and source-linked annotation discrepancies.

Uses saved synthetic-model outputs and the released scorer/scope replay. The
small counterexamples are constructed fixtures, not additional experiments or
human observations. No network, model calls, relabeling, or participant data.
"""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments'))
import analysis as scorer
import scope


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def refuses(fn):
    try:
        fn()
    except ValueError:
        return True
    return False


def build():
    source_paths = set()

    def read(rel):
        source_paths.add(rel)
        return json.loads((ROOT / rel).read_text())

    sid = '0138e719d9dd706d87d8150b99b9fdc0cf46c9f808491a783dd66878b9e51c2b'
    wf = read('experiments/state/workflows_v2/' + sid + '.json')
    scenarios = read('data/case_study_workflows.json')['scenarios']
    scenario = next(s for s in scenarios if s['id'] == wf['scenario_id'])
    secrets = scenario['secrets']
    weights = {s['id']: s['severity'] for s in secrets}
    detected = {channel: sorted(s['id'] for s in secrets
                               if any(m.lower() in text.lower() for m in s['markers']))
                for channel, text in wf['channels'].items()}
    log = wf['access_log']
    retrieve = next(e for e in log if e['event'] == 'retrieve')
    revoke = next(e for e in log if e['event'] == 'revoke')
    denied = next(e for e in log if e['event'] == 'retrieval_denied_after_revocation')
    call = next(e for e in log if e['event'] == 'model_call' and e['agent'] == 'worker')
    # The campaign hashes canonical JSON values, including strings.
    require(scorer.r.digest(retrieve['returned_text']) == retrieve['returned_sha256'],
            'Retrieved text no longer matches the recorded hash')
    require(retrieve['sequence'] < revoke['sequence'] < denied['sequence'] < call['sequence'],
            'Unexpected access-event order')
    require(revoke['retained_in_context'] is True, 'No recorded retention evidence')
    require(detected['C1'] == [], 'Example user-facing reply contains a registered-secret marker')
    exposed = detected['worker_to_archivist']
    require(exposed == detected['archivist_to_storage'] == ['s2'], 'Changed example exposure')
    full = scorer.edge_score(weights, exposed, weights)
    observed = scorer.edge_score(exposed, exposed, weights)
    require(full['numerator'] == 2 and full['denominator'] == 14, 'Changed inventory weights')
    # The released aggregate consumes explicit per-edge inventories. These two
    # selected edges isolate repetition; the whole-workflow transfer value is
    # published separately, including all observed channels.
    selected = [{'inventory': list(weights), 'exposed': exposed},
                {'inventory': exposed, 'exposed': exposed}]
    agg = scorer.aggregate(selected, weights, weights)

    # Cross-check the selected observed-knowledge edge against the full frozen
    # edge table rather than presenting a manually copied value as a replay.
    edge_rel = 'measurement/evidence/all_edge_comparisons.csv'
    source_paths.add(edge_rel)
    with (ROOT / edge_rel).open() as handle:
        edges = list(csv.DictReader(handle))
    matched = next(e for e in edges if e['workflow_id'] == sid and e['channel'] == 'archivist_to_storage')
    require(float(matched['RI_full']) == full['RI'] and float(matched['RI_observed']) == observed['RI'],
            'Frozen edge table and replay disagree')

    fixture = [{'id': 'x', 'severity': 1}, {'id': 'y', 'severity': 2}, {'id': 'z', 'severity': 4}]
    complete = scorer.score(fixture, {'x': False, 'y': False, 'z': False})
    unknown = scorer.score(fixture, {'x': False, 'y': None, 'z': False})
    empty = scorer.edge_score([], [], {})
    snapshots = scope.replay([
        {'sequence': 1, 'kind': 'grant', 'agent': 'a', 'secrets': ['x','y','z']},
        {'sequence': 2, 'kind': 'retrieve', 'agent': 'a', 'secrets': ['x','y','z']},
        {'sequence': 3, 'kind': 'revoke', 'agent': 'a', 'secrets': ['x','y','z']},
        {'sequence': 4, 'kind': 'handoff', 'agent': 'a', 'recipient': 'b', 'secrets': ['z']},
    ])
    checks = {
        'unresolved_is_not_zero': unknown['status'] == 'incomplete' and unknown['RI'] is None and complete['RI'] == 0,
        'empty_scope_is_not_zero': empty['RI'] is None,
        'revocation_preserves_retained_inventory': snapshots[0]['inventory'] == ['x','y','z'],
        'out_of_scope_exposure_rejected': refuses(lambda: scorer.edge_score(['x'], ['z'], {'x':1,'z':4})),
        'missing_secret_identity_rejected': refuses(lambda: scorer.score(fixture, {'x':False,'y':False})),
        'duplicate_secret_identity_rejected': refuses(lambda: scorer.score(fixture + [fixture[0]], {'x':False,'y':False,'z':False})),
        'unsubstantiated_erasure_rejected': refuses(lambda: scope.replay([{'sequence':1,'kind':'clear','agent':'a','secrets':['x']}])),
        'deduplication_separates_distinct_and_transfer_mass': agg['global_distinct']['numerator'] == 2 and sum(scorer.edge_score(e['inventory'],e['exposed'],weights)['numerator'] for e in selected) == 4,
    }
    require(all(checks.values()), 'A conformance fixture failed: ' + str(checks))

    forms = read('expert_evaluation/input/workflows.json')
    examples = []
    for row in forms:
        if row['id'] not in {'W001', 'W015', 'W033', 'W047'}:
            continue
        candidates = sorted(ROOT.rglob(row['workflow_id'] + '.json'))
        candidates = [p for p in candidates if sha(p) == row['file_sha256']]
        require(bool(candidates), 'Source workflow/hash missing for ' + row['id'])
        path = candidates[0]
        raw = read(path.relative_to(ROOT).as_posix())
        final_channel = 'archivist_to_storage'
        require(final_channel in raw['channels'], 'Unknown final channel')
        examples.append({
            'annotation_id': row['id'], 'workflow_id': row['workflow_id'],
            'source_path': path.relative_to(ROOT).as_posix(), 'source_sha256': sha(path),
            'final_channel': final_channel, 'final_text': raw['channels'][final_channel],
            'automated_verdict': row['old_verdict'], 'final_form_A': row['A'], 'final_form_B': row['B'],
            'interpretation': ('Explicit-versus-implicit representation request is a candidate explanation; the final forms do not supply a literal supporting span.'
                               if row['id'] == 'W001' else
                               'Partial global rating without an identified missing item; counted conservatively as partial.'),
            'new_human_adjudication': False,
        })
    require(len(examples) == 4, 'Incomplete discrepancy dossier')
    source_paths.update(['experiments/analysis.py', 'experiments/scope.py'])
    return {
        'evidence_kind': 'saved synthetic execution plus explicitly constructed conformance fixtures',
        'new_model_calls': 0, 'new_human_labels': 0,
        'logged_example': {'workflow_id': sid, 'selection': 'Saved denominator-ranking example selected to illustrate scope and retention.',
                           'marker_detections': detected, 'worker_full_inventory': full,
                           'downstream_observed_inventory': observed,
                           'retrieval_sequence': retrieve['sequence'], 'revocation_sequence': revoke['sequence'],
                           'worker_call_sequence': call['sequence'], 'retained_after_revoke': True,
                           'selected_two_edge_aggregate': agg, 'repeated_transfer_mass': 4,
                           'distinct_exposure_mass': 2, 'full_edge_table_rows': len(edges)},
        'constructed_fixtures': {'checks': checks, 'fully_resolved_negative': complete,
                                 'unresolved_observation': unknown, 'empty_inventory': empty},
        'utility_discrepancies': examples,
        'limits': ['Marker detections cover registered surface forms only.',
                   'Observed knowledge is not a complete semantic reachable inventory.',
                   'Conformance fixtures establish implementation behavior, not deployment accuracy or novelty priority.',
                   'Finalized annotation forms do not recover initial independent reliability.'],
        'sources_sha256': {p: sha(ROOT / p) for p in sorted(source_paths)},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--check', action='store_true', help='Compare with the checked-in reference without modifying it')
    args = parser.parse_args()
    result = build()
    reference = Path(__file__).parent / 'evidence/contract_replay.json'
    if args.check:
        require(result == json.loads(reference.read_text()), 'Replay differs from the checked-in reference')
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n')
    print(json.dumps({'checks_passed': len(result['constructed_fixtures']['checks']),
                      'source_linked_utility_examples': len(result['utility_discrepancies']),
                      'reference_matches': True if args.check else None, 'new_model_calls': 0}))


if __name__ == '__main__':
    main()
