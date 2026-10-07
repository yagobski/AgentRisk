#!/usr/bin/env python3
"""Verify release identity and offline evidence; never invoke model providers."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def files(root):
    return {p.relative_to(root).as_posix(): p for p in root.rglob('*')
            if p.is_file() and not any(x in p.parts for x in ['__pycache__','.git','.venv'])
            and p.name not in ['.DS_Store','SHA256SUMS.json']}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--full', action='store_true')
    ap.add_argument('--report', type=Path, help='Write a verification report outside the artifact')
    args = ap.parse_args()
    manifest = json.loads((ROOT / 'SHA256SUMS.json').read_text())
    actual = files(ROOT)
    require(set(manifest) == set(actual), 'Manifest/file-set mismatch: ' + str(set(manifest) ^ set(actual)))
    for name, path in actual.items():
        require(hashlib.sha256(path.read_bytes()).hexdigest() == manifest[name], 'Checksum mismatch: ' + name)
        if path.suffix in {'.json','.csv','.py','.md','.txt','.yml'}:
            text = path.read_text(errors='replace')
            require(not re.search(r'(?:sk-or-v1-[a-f0-9]{32,}|gh[pousr]_[A-Za-z0-9]{30,})', text), 'Possible credential: ' + name)
    report = {'manifest_files_verified': len(actual), 'commands': [],
              'network_or_model_calls_requested': False}

    def run(root, argv, env=None):
        merged = os.environ.copy()
        merged['PYTHONDONTWRITEBYTECODE'] = '1'
        if env:
            merged.update(env)
        result = subprocess.run([sys.executable, *argv], cwd=root, env=merged,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        require(result.returncode == 0, 'Failed: ' + ' '.join(argv) + '\n' + result.stdout[-5000:])
        entry = {'command': argv, 'passed': True}
        match = re.search(r'Ran (\d+) tests', result.stdout)
        if match:
            entry['tests'] = int(match.group(1))
        report['commands'].append(entry)

    def same(copy, rel, ignored=()):
        a, b = json.loads((ROOT / rel).read_text()), json.loads((copy / rel).read_text())
        for name in ignored:
            a.pop(name, None); b.pop(name, None)
        def equivalent(x, y):
            if isinstance(x, str) and isinstance(y, str):
                # Directory consolidation changes descriptive source paths only.
                replacements = {
                    'revision_tests_20260924': 'experiments',
                    'revision_strengthening': 'measurement',
                    'revision_round2': 'audit_results',
                    'revision_20261003': 'verification',
                    'final_annotations': 'expert_evaluation',
                    'generated/revision_20260929': 'generated/audit_summary',
                    'revision_analyses_20260929.py': 'audit_analysis.py',
                }
                for before, after in replacements.items():
                    x = x.replace(before, after)
                    y = y.replace(before, after)
                return x == y
            if isinstance(x, float) and isinstance(y, float):
                return math.isclose(x, y, rel_tol=1e-12, abs_tol=1e-12)
            if isinstance(x, dict) and isinstance(y, dict):
                return x.keys() == y.keys() and all(equivalent(x[k], y[k]) for k in x)
            if isinstance(x, list) and isinstance(y, list):
                return len(x) == len(y) and all(equivalent(u, v) for u, v in zip(x, y))
            return type(x) == type(y) and x == y
        require(equivalent(a, b), 'Numerical replay differs: ' + rel)

    run(ROOT, ['verification/reproduce_contract.py', '--check'])
    run(ROOT, ['verification/export_canonical.py', '--check'])
    run(ROOT, ['verification/verify_native_wls.py'])
    run(ROOT, ['verification/reconcile_task_evaluation.py', '--check'])
    if args.full:
        try:
            import numpy
        except ImportError:
            raise SystemExit('Install verification/requirements-offline.txt for --full')
        report['numpy_version'] = numpy.__version__
        report['float_comparison_tolerance'] = {'relative': 1e-12, 'absolute': 1e-12}
        with tempfile.TemporaryDirectory(prefix='agentrisk-offline-') as temp:
            copy = Path(temp) / 'artifact'
            shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns('__pycache__','.venv','.git'))
            run(copy, ['-m','unittest','discover','-s','experiments','-p','test_*.py'])
            run(copy, ['expert_evaluation/analyze_expert_evaluation.py','--data-dir','expert_evaluation/input','--out','expert_evaluation'])
            same(copy, 'expert_evaluation/results.json')
            same(copy, 'expert_evaluation/workflow_results.json')
            run(copy, ['experiments/validate_replay.py'])
            same(copy, 'experiments/generated/campaign_v2/paired_control.json')
            same(copy, 'experiments/generated/campaign_v2/original_metric_table.json')
            run(copy, ['measurement/scripts/strengthening_analysis.py'])
            for name in ['edge_summary','transfer_summary','rank_example']:
                same(copy, f'measurement/evidence/{name}.json')
            scratch = Path(temp) / 'tex'; scratch.mkdir()
            run(copy, ['experiments/audit_analysis.py'],
                {'AGENTRISK_RESULTS_TEX': str(scratch)})
            same(copy, 'experiments/generated/audit_summary/results.json')
            same(copy, 'experiments/generated/audit_summary/native_per_workflow.json')
            run(copy, ['audit_results/scripts/round2_analysis.py','--artifact-root','.'])
            same(copy, 'audit_results/frontier_blind_spots.json')
        report['numerical_replays_match'] = True
    report['status'] = 'passed'
    if args.report:
        require(not args.report.resolve().is_relative_to(ROOT), 'Store reports outside the hashed artifact')
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
