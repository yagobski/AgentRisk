#!/usr/bin/env python3
"""Export and check the manuscript's canonical schema without model calls."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments'))
from canonical_schema import to_canonical, validate
from analysis import score

SOURCES = ('experiments/generated/campaign_v2/canonical_records.json',
           'measurement/evidence/presidio_canonical.json')
OUTPUT = ROOT / 'verification/evidence/canonical_observations.json'


def build_export():
    original = [row for path in SOURCES for row in json.loads((ROOT / path).read_text())]
    canonical = [to_canonical(row) for row in original]
    groups = defaultdict(list)
    seen = set()
    for before, after in zip(original, canonical):
        key = (after['trace_id'], after['channel_id'], after['detector_source'], after['scope_id'])
        identity = key + (after['secret_id'],)
        if identity in seen:
            raise ValueError('Duplicate canonical observation: ' + str(identity))
        seen.add(identity)
        groups[key].append((before, after))
    for pairs in groups.values():
        before = score([{'id': a['secret_id'], 'severity': a['severity']} for a, b in pairs],
                       {a['secret_id']: a['disclosed'] for a, b in pairs})
        after = score([{'id': b['secret_id'], 'severity': b['severity_level']} for a, b in pairs],
                      {b['secret_id']: b['disclosed'] for a, b in pairs})
        if before != after:
            raise ValueError('Canonical export changed a score')
    return canonical, len(groups)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='Check the saved export (default)')
    mode.add_argument('--write', action='store_true', help='Rebuild the deterministic export')
    args = parser.parse_args()
    expected, groups = build_export()
    if args.write:
        OUTPUT.write_text(json.dumps(expected, indent=2, ensure_ascii=False) + '\n')
    saved = json.loads(OUTPUT.read_text())
    for row in saved:
        validate(row)
    if saved != expected:
        raise ValueError('Saved canonical export differs from archived observations')
    print(json.dumps({'status': 'passed', 'observations': len(saved),
                      'detectors': dict(Counter(x['detector_source'] for x in saved)),
                      'score_groups_unchanged': groups,
                      'unavailable_task_adjudication': sum(x['task_required'] == 'unsure' for x in saved),
                      'unresolved_disclosures_preserved': sum(x['disclosed'] is None for x in saved)}, indent=2))


if __name__ == '__main__':
    main()
