import copy
import unittest
from canonical_schema import to_canonical, validate


class CanonicalSchemaTests(unittest.TestCase):
    def setUp(self):
        self.row = {'trace_id': 't1', 'trace_sha256': 'source-hash', 'secret_id': 's1',
                    'scope_id': 'inventory1', 'channel': 'OUT', 'detector': 'marker',
                    'severity': 3, 'disclosed': None, 'evidence': None,
                    'task_required': None,
                    'task_required_status': 'independent contextual annotation unavailable'}

    def test_unknown_policy_is_not_unknown_detection_or_a_negative(self):
        original = copy.deepcopy(self.row)
        output = to_canonical(self.row)
        self.assertEqual(self.row, original)
        self.assertEqual(output['task_required'], 'unsure')
        self.assertEqual(output['task_required_provenance'], original['task_required_status'])
        self.assertIsNone(output['disclosed'])
        self.assertEqual(output['channel_id'], 'OUT')
        self.assertEqual(output['trace_sha256'], original['trace_sha256'])
        self.assertEqual(to_canonical(output), output)

    def test_adjudicated_policy_is_preserved(self):
        for label in ('yes', 'no', 'unsure'):
            row = dict(self.row, task_required=label, task_required_status='policy-record-1')
            self.assertEqual(to_canonical(row)['task_required'], label)
        for status in (None, '', 'unrecognized reason'):
            with self.assertRaises(ValueError):
                to_canonical(dict(self.row, task_required_status=status))

    def test_alias_conflicts_and_invalid_values_are_rejected(self):
        invalid = ({'channel_id': 'C1'}, {'severity_level': True}, {'severity': True},
                   {'severity': 5}, {'disclosed': 0}, {'disclosed': 'false'},
                   {'task_required': 'unknown'}, {'confidence': float('nan')},
                   {'confidence': 1.1}, {'secret_id': ''})
        for patch in invalid:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                to_canonical(dict(self.row, **patch))

    def test_required_fields_cannot_be_dropped(self):
        canonical = to_canonical(self.row)
        for field in ('trace_id', 'channel_id', 'secret_id', 'disclosed', 'severity_level',
                      'task_required', 'detector_source', 'scope_id', 'task_required_provenance'):
            row = dict(canonical)
            del row[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(row)

    def test_positive_evidence_is_required_and_retained(self):
        for evidence in ('literal span', [{'text': 'literal span', 'start': 0, 'end': 12}]):
            row = dict(self.row, disclosed=True, evidence=evidence)
            self.assertEqual(to_canonical(row)['evidence'], evidence)
        for evidence in (None, '', [], [{}]):
            with self.assertRaises(ValueError):
                to_canonical(dict(self.row, disclosed=True, evidence=evidence))

    def test_frozen_export_preserves_all_detector_scores(self):
        import importlib.util
        from pathlib import Path
        path = Path(__file__).resolve().parents[1] / 'verification/export_canonical.py'
        spec = importlib.util.spec_from_file_location('export_canonical', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        rows, groups = module.build_export()
        self.assertEqual(len(rows), 1440)
        self.assertEqual(groups, 288)
        self.assertEqual(sum(x['disclosed'] is None for x in rows), 592)


if __name__ == '__main__':
    unittest.main()
