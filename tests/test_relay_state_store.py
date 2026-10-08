import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pbxsense_agent.relay_state_store import RelayStateStore


class RelayStateStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "identity.json"
        self.state = {
            "agent_id": "existing-agent", "private_key": "private-material",
            "outbox": [{"eventId": "queued-event", "attempts": 2}],
            "delivered": {"signal": "fingerprint"},
            "future_field": {"preserve": True},
        }

    def store(self, secret="current-key", legacy=()):
        return RelayStateStore(
            str(self.path), storage_secret=secret, legacy_storage_secrets=legacy,
        )

    def test_missing_file_returns_fresh_containers(self):
        store = self.store()
        first = store.load()
        first["outbox"].append({})
        self.assertEqual(store.load(), {"outbox": [], "delivered": {}})

    def test_round_trip_preserves_identity_outbox_and_unknown_fields(self):
        self.store().save(self.state)
        self.assertEqual(self.store().load(), self.state)
        envelope = json.loads(self.path.read_text())
        self.assertEqual(envelope["format"], "pbxsense-relay-state-v1")
        self.assertNotIn("private-material", self.path.read_text())
        self.assertNotIn("existing-agent", self.path.read_text())

    def test_plaintext_migrates_even_when_unchanged(self):
        self.path.write_text(json.dumps(self.state))
        store = self.store()
        loaded = store.load()
        self.assertEqual(loaded, self.state)
        store.save(loaded)
        self.assertEqual(json.loads(self.path.read_text())["format"],
                         "pbxsense-relay-state-v1")
        self.assertEqual(self.store().load(), self.state)

    def test_legacy_key_rewrites_using_current_key(self):
        self.store("old-key").save(self.state)
        store = self.store(legacy=("old-key",))
        store.save(store.load())
        self.assertEqual(self.store().load(), self.state)
        with self.assertRaisesRegex(RuntimeError, "could not be decrypted"):
            self.store("old-key").load()

    def test_wrong_or_missing_key_does_not_replace_identity(self):
        self.store().save(self.state)
        original = self.path.read_bytes()
        for secret in ("wrong-key", ""):
            with self.subTest(secret=bool(secret)), self.assertRaises(RuntimeError):
                self.store(secret).load()
            self.assertEqual(self.path.read_bytes(), original)

    def test_unchanged_save_skips_replacement_but_changed_state_writes(self):
        store = self.store()
        store.save(self.state)
        original = self.path.read_bytes()
        with patch.object(Path, "replace", side_effect=AssertionError("unexpected write")):
            store.save(dict(self.state))
        self.assertEqual(self.path.read_bytes(), original)
        self.state["outbox"].append({"eventId": "next-event"})
        store.save(self.state)
        self.assertEqual(self.store().load(), self.state)

    def test_failed_replace_keeps_previous_state_and_allows_retry(self):
        store = self.store()
        store.save(self.state)
        original = self.path.read_bytes()
        self.state["agent_id"] = "updated-agent"
        with patch.object(Path, "replace", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                store.save(self.state)
        self.assertEqual(self.path.read_bytes(), original)
        store.save(self.state)
        self.assertEqual(self.store().load(), self.state)

    def test_missing_secret_cannot_write_plaintext(self):
        with self.assertRaisesRegex(RuntimeError, "required"):
            self.store("").save(self.state)
        self.assertFalse(self.path.exists())

    def test_malformed_encrypted_envelope_fails_closed(self):
        self.path.write_text(json.dumps({"format": "pbxsense-relay-state-v1"}))
        with self.assertRaisesRegex(RuntimeError, "malformed"):
            self.store().load()

    def test_posix_permissions_are_requested_for_directory_and_files(self):
        # Patch the module's OS reference, not global os.name (Path uses it).
        with patch("pbxsense_agent.relay_state_store.os") as operating_system:
            operating_system.name = "posix"
            with patch.object(Path, "chmod") as chmod:
                store = self.store()
                store.save(self.state)
                store.protect_storage()
                modes = [call.args[0] for call in chmod.call_args_list]
                self.assertEqual(modes, [0o700, 0o600, 0o600, 0o700, 0o600])
