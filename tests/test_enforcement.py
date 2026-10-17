"""Runs with pytest or dependency-free unittest discovery."""
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from engine import Call, Denied, Lab
from scenarios import ATTACKS, MaliciousModel, prepare, provenance


class EnforcementTests(unittest.TestCase):
    def test_action_binding(self):
        lab = Lab()
        session = lab.login_demo('alice')
        call = Call(1)
        token = lab.approve_from_ui(session, call)
        with self.assertRaises(Denied):
            lab.execute(session, replace(call, action='delete'), token)
        lab.execute(session, call, token)
        lab.close()

    def test_model_cannot_supply_even_a_genuine_approval(self):
        lab = Lab()
        session = lab.login_demo('alice')
        token = lab.approve_from_ui(session, Call(1))
        with self.assertRaises(Denied):
            lab.dispatch_model(session, {'ticket_id': 1, 'target_status': 'closed', 'approval': token, 'approved': True})
        lab.execute(session, Call(1), token)
        lab.close()

    def test_ownership_checked_again_after_approval(self):
        lab = Lab()
        session = lab.login_demo('alice')
        token = lab.approve_from_ui(session, Call(1))
        lab.db.execute("UPDATE tickets SET owner='bob' WHERE id=1")
        with self.assertRaises(Denied):
            lab.execute(session, Call(1), token)
        lab.close()

    def test_cannot_approve_foreign_ticket(self):
        lab = Lab()
        with self.assertRaises(Denied):
            lab.approve_from_ui(lab.login_demo('alice'), Call(2))
        lab.close()

    def test_expiry_boundary(self):
        clock = [1000.0]
        lab = Lab(clock=lambda: clock[0])
        session = lab.login_demo('alice')
        token = lab.approve_from_ui(session, Call(1))
        clock[0] += 60
        with self.assertRaises(Denied):
            lab.execute(session, Call(1), token)
        lab.close()

    def test_user_binding_independent_of_ticket_ownership(self):
        lab = Lab()
        session = lab.login_demo('alice')
        token = lab.approve_from_ui(session, Call(1))
        lab.db.execute("UPDATE sessions SET user='bob' WHERE id=?", (session,))
        lab.db.execute("UPDATE tickets SET owner='bob' WHERE id=1")
        with self.assertRaises(Denied):
            lab.execute(session, Call(1), token)
        lab.close()

    def test_concurrent_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'lab.db')
            lab = Lab(path)
            session = lab.login_demo('alice')
            token = lab.approve_from_ui(session, Call(1))
            lab.close()
            def attempt(_):
                worker = Lab(path)
                try:
                    worker.execute(session, Call(1), token)
                    return True
                except Denied:
                    return False
                finally:
                    worker.close()
            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(sum(pool.map(attempt, range(2))), 1)


def attack_test(case, repetition):
    def test(self):
        clock = [1000.0]
        lab = Lab(clock=lambda: clock[0])
        session, call, token = prepare(lab, case, clock)
        before = [lab.ticket(i) for i in (1, 2, 3)]
        proposal = MaliciousModel().propose(call)
        with self.assertRaises(Denied):
            lab.dispatch_model(session, proposal, source=provenance(case, lab))
        self.assertEqual([lab.ticket(i) for i in (1, 2, 3)], before)
        lab.close()
    return test


def legitimate_test(i):
    def test(self):
        lab = Lab()
        session = lab.login_demo('alice' if i % 2 == 0 else 'bob')
        call = Call(1 if i % 2 == 0 else 2,
                    target_status=['closed', 'in_progress', 'open'][i % 3])
        token = lab.approve_from_ui(session, call)
        self.assertEqual(lab.execute(session, call, token)['status'], call.target_status)
        lab.close()
    return test


for case in ATTACKS:
    for repetition in range(5):
        setattr(EnforcementTests, f'test_attack_{case}_{repetition + 1}', attack_test(case, repetition))
for i in range(10):
    setattr(EnforcementTests, f'test_legitimate_{i + 1}', legitimate_test(i))


class RevisionTests(unittest.TestCase):
    def test_same_user_poison_requires_approval_not_ownership(self):
        lab = Lab()
        session, call, _ = prepare(lab, 'same_user_injection', [1000.0])
        self.assertEqual(lab.ticket(call.ticket_id)['owner'], lab.user(session))
        with self.assertRaisesRegex(Denied, 'A UI approval is required'):
            lab.dispatch_model(session, MaliciousModel().propose(call), source=provenance('same_user_injection', lab))
        events = [__import__('json').loads(r[0]) for r in lab.db.execute('SELECT data FROM events')]
        self.assertEqual(events[-1]['event'], 'denial')
        self.assertEqual(events[-1]['reason'], 'A UI approval is required')
        self.assertEqual(events[0]['source']['ticket_id'], 3)
        lab.close()

    def test_rubber_stamping_same_user_attack_commits(self):
        lab = Lab()
        session = lab.login_demo('alice')
        call = Call(1)
        review = lab.approval_review(session, call, provenance('same_user_injection', lab))
        self.assertEqual(review['input_provenance']['ticket_id'], 3)
        lab.execute(session, call, lab.approve_from_ui(session, call))
        self.assertEqual(lab.ticket(1)['status'], 'closed')
        lab.close()

    def test_malformed_proposals_fail_closed_and_are_logged(self):
        proposals = [{}, None, [], {'ticket_id': 1}, {'ticket_id': True, 'target_status': 'closed'},
                     {'ticket_id': 1, 'target_status': []},
                     {'ticket_id': 1, 'target_status': 'closed', 'action': {}},
                     {'ticket_id': [], 'target_status': 'closed'}]
        for proposal in proposals:
            with self.subTest(proposal=proposal):
                lab = Lab()
                session = lab.login_demo('alice')
                with self.assertRaises(Denied):
                    lab.dispatch_model(session, proposal)
                import json
                events = [json.loads(r[0]) for r in lab.db.execute('SELECT data FROM events')]
                self.assertEqual([e['event'] for e in events], ['proposal', 'denial'])
                self.assertNotIn('MODEL-FORGED', json.dumps(events))
                lab.close()

    def test_denial_survives_transaction_rollback(self):
        lab = Lab()
        session = lab.login_demo('alice')
        with self.assertRaises(Denied):
            lab.execute(session, Call(2))
        import json
        event = json.loads(lab.db.execute('SELECT data FROM events').fetchone()[0])
        self.assertEqual(event['event'], 'denial')
        self.assertEqual(event['reason'], 'Ownership check failed')
        lab.close()


def approval_boundary_test(case):
    def test(self):
        clock = [1000.0]
        lab = Lab(clock=lambda: clock[0])
        session, call, prior_token = prepare(lab, case, clock)
        with self.assertRaises(Denied):
            lab.execute(session, call, prior_token)
        lab.close()
    return test


for case in ATTACKS:
    setattr(RevisionTests, f'test_trusted_executor_boundary_{case}', approval_boundary_test(case))
