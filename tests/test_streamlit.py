"""Optional real Streamlit interaction tests. Run after installing requirements."""
import unittest
from pathlib import Path
try:
    from streamlit.testing.v1 import AppTest
except ImportError:
    AppTest = None


@unittest.skipIf(AppTest is None, 'Streamlit not installed; UI runtime remains unverified')
class StreamlitTests(unittest.TestCase):
    def app(self):
        return AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py')).run(timeout=20)

    @staticmethod
    def choose(app, label):
        return next(w for w in app.selectbox if w.label == label)

    def test_default_persona_is_automatic(self):
        app = self.app()
        self.assertFalse(app.exception)
        persona = self.choose(app, 'Demo persona')
        self.assertEqual(persona.value, 'alice')
        self.assertTrue(persona.disabled)

    def test_review_shows_bob_and_no_commit(self):
        app = self.app()
        next(b for b in app.button if b.label == 'Run model (malicious stub)').click().run()
        self.assertFalse(app.exception)
        text = '\n'.join(m.value for m in app.markdown)
        self.assertIn('comment by **bob**', text)
        self.assertIn('Original user task:', text)
        self.assertTrue(any('A UI approval is required' in s.value for s in app.success))
        self.assertTrue(any(b.label == 'Reject proposed change' for b in app.button))

    def test_switching_from_bob_forces_alice_for_scenario(self):
        app = self.app()
        self.choose(app, 'Scenario').select('Manual proposal').run()
        self.choose(app, 'Demo persona').select('bob').run()
        self.choose(app, 'Scenario').select('Same-user poisoned ticket').run()
        self.assertFalse(app.exception)
        self.assertEqual(self.choose(app, 'Demo persona').value, 'alice')
        self.assertTrue(self.choose(app, 'Demo persona').disabled)

    def test_approval_requires_confirmation_checkbox(self):
        app = self.app()
        next(b for b in app.button if b.label == 'Run model (malicious stub)').click().run()
        self.assertFalse(app.exception)
        approve = next(b for b in app.button if b.label == 'Approve and execute this exact action')
        self.assertTrue(approve.disabled)
        self.assertTrue(any('Off-task: you asked to summarize ticket 3. This would close ticket 1.'
                            in error.value for error in app.error))
        app.checkbox[0].check().run()
        self.assertFalse(app.exception)
        self.assertFalse(next(b for b in app.button if b.label == 'Approve and execute this exact action').disabled)

    def test_reject_clears_review_without_change(self):
        app = self.app()
        next(b for b in app.button if b.label == 'Run model (malicious stub)').click().run()
        next(b for b in app.button if b.label == 'Reject proposed change').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any('No change committed' in s.value for s in app.success))
        self.assertFalse(any(b.label == 'Approve and execute this exact action' for b in app.button))
