import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.ai_groups import group_facts, group_key, render_groups
from app.ai_generation import GenerationError, fingerprint, model_payload


def row(**changes):
    return dict(dict(finding_id='internal-finding-id', package_id='pkg-1', package_name='example',
                     type='vulnerability', severity='HIGH', priority=None, relationship='direct',
                     has_fixed_candidates=False, manual_review_required=False), **changes)


def choices(snapshot):
    return {'items': [dict(evidence_id=x['evidence_id'], reasons=x['allowed_reasons'][:2]) for x in snapshot['items']]}


class GroupTests(unittest.TestCase):
    def test_all_501_rows_counted_without_sending_individual_findings(self):
        s = group_facts([row(finding_id=str(i)) for i in range(501)], 'completed', [])
        self.assertEqual(s['finding_count'], 501)
        self.assertEqual(s['items'][0]['finding_count'], 501)
        self.assertEqual(len(s['items']), 1)
        self.assertEqual(s['items'][0]['package_count'], 1)
        output = render_groups(s, choices(s))
        self.assertNotIn('highlights', output)
        self.assertLess(len(str(output)), 1800)
        model_payload(s, 'test-model')

    def test_stored_priorities_control_order_without_severity_mapping(self):
        s = group_facts([row(priority='P2'), row(finding_id='b', priority='P0', severity='LOW'),
                         row(finding_id='c', severity='CRITICAL')], 'completed', [])
        self.assertEqual([x['group_key'] for x in s['items']], ['P0', 'P2', 'unranked-CRITICAL'])

    def test_unknown_and_non_security_are_separate(self):
        for severity in [None, 'UNKNOWN']:
            self.assertEqual(group_key(row(severity=severity, priority='P0')), 'unknown')
        self.assertEqual(group_key(row(type='license', priority='P0')), 'license')
        self.assertEqual(group_key(row(type='maintenance', priority='P0')), 'maintenance')

    def test_dedup_within_group_and_cross_group_counts(self):
        s = group_facts([row(priority='P0'), row(priority='P0', package_id='pkg-2'),
                         row(priority='P1', package_id='pkg-3')], 'completed', [])
        self.assertEqual(s['finding_count'], 1)
        self.assertEqual([x['finding_count'] for x in s['items']], [1, 1])
        self.assertEqual([x['package_count'] for x in s['items']], [2, 1])
        self.assertIn('중복', render_groups(s, choices(s))['count_note'])

    def test_membership_change_invalidates_equal_counts(self):
        a = group_facts([row()], 'completed', [])
        b = group_facts([row(finding_id='different')], 'completed', [])
        self.assertNotEqual(fingerprint(a), fingerprint(b))

    def test_partial_and_mixed_candidates_do_not_overclaim(self):
        s = group_facts([row(has_fixed_candidates=True), row(finding_id='b', package_id='pkg-2')], 'partial', [])
        out = render_groups(s, choices(s))
        self.assertIn('부분 완료', out['uncertainty'])
        self.assertIn('1개', out['groups'][0]['guidance'][1])
        self.assertNotIn('internal-finding-id', str(out))

    def test_license_does_not_claim_manual_flag(self):
        s = group_facts([row(type='license')], 'completed', [])
        self.assertNotIn('수동 확인 대상으로 표시', str(render_groups(s, choices(s))))

    def test_reordered_fabricated_or_duplicated_groups_rejected(self):
        s = group_facts([row(priority='P0'), row(priority='P1')], 'completed', [])
        bad = choices(s)
        bad['items'].reverse()
        with self.assertRaises(GenerationError):
            render_groups(s, bad)
        for codes in [['priority', 'priority'], ['priority', 'license'], [[], {}]]:
            bad = choices(s)
            bad['items'][0]['reasons'] = codes
            with self.assertRaises(GenerationError):
                render_groups(s, bad)
