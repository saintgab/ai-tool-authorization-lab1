import json
import unittest
from datetime import datetime
from engine import Call, Denied, Lab
from scenarios import MaliciousModel, prepare, provenance


class RequestControlTests(unittest.TestCase):
    def setup_attack(self, variant='same_user_injection'):
        lab = Lab()
        session, call, _ = prepare(lab, variant, [1000.0])
        source = provenance(variant, lab)
        request_id = lab.new_request(session, source['task'], source)
        return lab, session, call, request_id

    def events(self, lab):
        return [json.loads(r[0]) for r in lab.db.execute('SELECT data FROM events')]

    def test_summarization_disallows_any_mutation_not_just_other_tickets(self):
        for target in (1, 3):
            result = Lab.assess_task({'kind': 'summarize', 'ticket_id': 3}, Call(target))
            self.assertTrue(result['off_task'])
        result = Lab.assess_task({'kind': 'summarize', 'ticket_id': 3}, Call(1))
        self.assertEqual(result['banner'], 'Off-task: you asked to summarize ticket 3. This would close ticket 1.')

    def test_exact_mutation_scope(self):
        task = {'kind': 'set_status', 'ticket_id': 1, 'target_status': 'closed'}
        self.assertFalse(Lab.assess_task(task, Call(1))['off_task'])
        self.assertTrue(Lab.assess_task(task, Call(3))['off_task'])
        self.assertTrue(Lab.assess_task(task, Call(1, target_status='in_progress'))['off_task'])
        self.assertIsNone(Lab.assess_task(None, Call(1))['off_task'])

    def test_unconfirmed_off_task_approval_is_denied(self):
        lab, session, call, request_id = self.setup_attack()
        with self.assertRaises(Denied):
            lab.dispatch_model(session, MaliciousModel().propose(call), request_id=request_id)
        with self.assertRaisesRegex(Denied, 'Explicit confirmation'):
            lab.approve_from_ui(session, call, request_id=request_id)
        self.assertEqual(lab.db.execute('SELECT COUNT(*) FROM approvals').fetchone()[0], 0)
        self.assertEqual(lab.ticket(1)['status'], 'open')
        lab.close()

    def test_confirmed_override_has_linked_audit_chain(self):
        lab, session, call, request_id = self.setup_attack('same_user_injection_subtle')
        with self.assertRaises(Denied):
            lab.dispatch_model(session, MaliciousModel().propose(call), request_id=request_id)
        token = lab.approve_from_ui(session, call, request_id=request_id, confirm_off_task=True)
        lab.execute(session, call, token)
        events = self.events(lab)
        self.assertEqual([e['event'] for e in events], ['proposal', 'denial', 'approval', 'commit'])
        self.assertTrue(all(e['request_id'] == request_id for e in events))
        self.assertTrue(all(e['off_task'] is True for e in events))
        self.assertTrue(all(e['source']['author'] == 'bob' for e in events))
        self.assertTrue(events[2]['confirmed_off_task'])
        for event in events:
            self.assertTrue(event['time'].endswith('Z'))
            datetime.fromisoformat(event['time'].replace('Z', '+00:00'))
        self.assertNotIn(token, json.dumps(events))
        lab.close()

    def test_model_cannot_suppress_mismatch_or_confirm_it(self):
        lab, session, call, request_id = self.setup_attack()
        proposal = {**MaliciousModel().propose(call), 'off_task': False, 'confirm_off_task': True,
                    'task': {'kind': 'set_status', 'ticket_id': 1, 'target_status': 'closed'}}
        with self.assertRaises(Denied):
            lab.dispatch_model(session, proposal, request_id=request_id)
        self.assertTrue(self.events(lab)[0]['off_task'])
        with self.assertRaisesRegex(Denied, 'Explicit confirmation'):
            lab.approve_from_ui(session, call, request_id=request_id)
        lab.close()

    def test_reject_revokes_pending_request_and_prevents_approval(self):
        lab, session, call, request_id = self.setup_attack()
        with self.assertRaises(Denied):
            lab.dispatch_model(session, MaliciousModel().propose(call), request_id=request_id)
        lab.reject_from_ui(session, request_id)
        with self.assertRaises(Denied):
            lab.approve_from_ui(session, call, request_id=request_id, confirm_off_task=True)
        self.assertEqual(lab.ticket(1)['status'], 'open')
        rejected = next(e for e in self.events(lab) if e['event'] == 'review_rejected')
        self.assertEqual(rejected['request_id'], request_id)
        self.assertTrue(rejected['off_task'])
        lab.close()

    def test_reject_after_grant_prevents_execution(self):
        lab, session, call, request_id = self.setup_attack()
        with self.assertRaises(Denied):
            lab.dispatch_model(session, MaliciousModel().propose(call), request_id=request_id)
        token = lab.approve_from_ui(session, call, request_id=request_id, confirm_off_task=True)
        lab.reject_from_ui(session, request_id)
        with self.assertRaises(Denied):
            lab.execute(session, call, token)
        self.assertEqual(lab.ticket(1)['status'], 'open')
        lab.close()

    def test_request_is_bound_to_session(self):
        lab, session, call, request_id = self.setup_attack()
        other = lab.login_demo('alice')
        with self.assertRaises(Denied):
            lab.approval_review(other, call, request_id=request_id)
        lab.close()

    def test_review_uses_stored_source_not_replacement(self):
        lab, session, call, request_id = self.setup_attack()
        review = lab.approval_review(session, call, {'author': 'alice', 'task': None}, request_id=request_id)
        self.assertEqual(review['input_provenance']['author'], 'bob')
        self.assertEqual(review['input_provenance']['field'], 'comments[0].body')
        self.assertTrue(review['off_task'])
        lab.close()

    def test_malformed_call_with_task_scope_denies_without_crashing(self):
        lab, session, _, request_id = self.setup_attack()
        with self.assertRaises(Denied):
            lab.dispatch_model(session, {'ticket_id': 1, 'target_status': []}, request_id=request_id)
        self.assertEqual(self.events(lab)[-1]['event'], 'denial')
        lab.close()
