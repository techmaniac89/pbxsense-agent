import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pbxsense_agent.credentials import AppCredentials


class CredentialTest(unittest.TestCase):
    def test_admin_token_rotation_revokes_sessions_and_apps(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "apps.json"
            store = AppCredentials(path, "storage-key", "old-admin-token")
            token = store.issue()
            store.activate(token)
            rotated = AppCredentials(path, "storage-key", "new-admin-token")
            self.assertFalse(rotated.accepts(token))
            self.assertNotEqual(store.cookie(), rotated.cookie())

    def test_individual_revocation_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "apps.json"
            store = AppCredentials(path, "secret")
            first, second = store.issue(), store.issue()
            self.assertTrue(store.bind(first, "111111111111"))
            self.assertTrue(store.bind(second, "222222222222"))
            self.assertFalse(store.bind(first, "222222222222"))
            store.revoke("111111111111")
            restored = AppCredentials(path, "secret")
            self.assertFalse(restored.accepts(first))
            self.assertTrue(restored.accepts(second))
            self.assertNotIn(second, path.read_text())
            self.assertEqual(store.cookie(), restored.cookie())

    def test_internet_only_activation_and_pending_expiration(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppCredentials(Path(directory) / "apps.json", "secret")
            first, second = store.issue("activation-one"), store.issue("activation-two")
            self.assertFalse(store.bind(first, "someone-elses-device"))
            store.sync_devices([
                {"id": "one", "activationId": "activation-one"},
                {"id": "two", "activationId": "activation-two"},
            ])
            pending = store.issue()
            with patch("pbxsense_agent.credentials.time.time", return_value=10**12):
                self.assertFalse(store.accepts(pending))
                self.assertTrue(store.accepts(first))
            store.revoke("one")
            self.assertFalse(store.accepts(first))
            self.assertTrue(store.accepts(second))
            store.sync_devices([{"id": "one", "activationId": "activation-one"}])
            self.assertFalse(store.accepts(first))

    def test_local_only_use_is_durable_but_fails_closed_on_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            store = AppCredentials(Path(directory) / "apps.json", "secret")
            token = store.issue()
            store.activate(token)
            with patch("pbxsense_agent.credentials.time.time", return_value=10**12):
                self.assertTrue(store.accepts(token))
            store.revoke("unknown-old-relay-device")
            self.assertFalse(store.accepts(token))
