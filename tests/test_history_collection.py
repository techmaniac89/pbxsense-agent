from dataclasses import replace
from datetime import datetime, timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from pbxsense_agent.history import SecurityEvent
from pbxsense_agent.history_collection import HistoryCollector, history_paths, security_log_path
from pbxsense_agent.observations import PbxSnapshot


class HistoryCollectionTest(unittest.TestCase):
    def setUp(self):
        self.clock = [0.0]
        self.wall = datetime(2026, 10, 9, 12)
        self.calls, self.voicemails, self.events = [Mock()], [Mock()], []
        self.read_calls = Mock(return_value=self.calls)
        self.read_vm = Mock(return_value=self.voicemails)
        self.read_security = Mock(return_value=self.events)
        self.read_cucm = Mock(return_value=self.calls)
        self.collector = HistoryCollector(
            poll_interval=30, monotonic=lambda: self.clock[0], now=lambda: self.wall,
            read_calls=self.read_calls, read_voicemails=self.read_vm,
            read_security=self.read_security, read_cucm=self.read_cucm,
        )
        self.settings = SimpleNamespace(
            pbx_type="asterisk", cdr_csv_path="", voicemail_path="", asterisk_security_log_path="",
            grandstream_cdr_csv_path="ucm-cdr", grandstream_voicemail_path="ucm-voicemail",
            grandstream_security_log_path="ucm-security", cucm_cdr_path="cucm-cdr", cucm_cmr_path="cucm-cmr",
        )
        self.snapshot = PbxSnapshot(True, "test")
        # These tests inject readers rather than real files; availability is
        # exercised separately with real temporary paths.
        self.available = patch.object(self.collector, "_available", return_value=True)
        self.available.start()
        self.addCleanup(self.available.stop)

    def test_poll_boundary_and_unchanged_fingerprints_preserve_records(self):
        first = self.collector.enrich(self.snapshot, self.settings)
        self.assertIs(first.recent_calls, self.calls)
        self.assertIs(first.voicemails, self.voicemails)
        self.assertEqual(self.snapshot.recent_calls, [])
        self.clock[0] = 29.9
        self.assertIs(self.collector.enrich(self.snapshot, self.settings).recent_calls, self.calls)
        self.clock[0] = 30
        self.collector.enrich(self.snapshot, self.settings)
        self.read_calls.assert_called_once_with("", limit=1000)
        self.read_vm.assert_called_once_with("")
        self.read_security.assert_called_once_with("")

    def test_changed_fingerprint_rereads_at_next_poll_only(self):
        with patch("pbxsense_agent.history_collection.file_signature", return_value=("", 0, 0)):
            self.collector.enrich(self.snapshot, self.settings)
        newer = [Mock()]
        self.read_calls.return_value = newer
        with patch("pbxsense_agent.history_collection.file_signature", return_value=("", 1, 1)):
            self.clock[0] = 29
            self.assertIs(self.collector.enrich(self.snapshot, self.settings).recent_calls, self.calls)
            self.clock[0] = 30
            self.assertIs(self.collector.enrich(self.snapshot, self.settings).recent_calls, newer)
        self.assertEqual(self.read_calls.call_count, 2)

    def test_failed_reader_does_not_commit_any_fingerprint_or_generation(self):
        with patch("pbxsense_agent.history_collection.file_signature", return_value=("", 0, 0)):
            published = self.collector.enrich(self.snapshot, self.settings)
        newer = [Mock()]
        self.read_calls.return_value = newer
        self.read_security.side_effect = RuntimeError("read failed")
        self.clock[0] = 30
        with patch("pbxsense_agent.history_collection.file_signature", return_value=("", 1, 1)):
            with self.assertRaisesRegex(RuntimeError, "read failed"):
                self.collector.enrich(self.snapshot, self.settings)
            self.assertIs(self.collector._records.calls, self.calls)
            self.read_security.side_effect = None
            result = self.collector.enrich(self.snapshot, self.settings)
        self.assertEqual(self.read_calls.call_count, 3)
        self.assertIs(result.recent_calls, newer)
        self.assertIs(published.recent_calls, self.calls)

    def test_unchanged_security_log_ages_events_without_mutating_published_list(self):
        fresh = SecurityEvent("failed-login", "sip", self.wall)
        boundary = SecurityEvent("failed-login", "sip", self.wall - timedelta(minutes=15))
        old = SecurityEvent("failed-login", "sip", self.wall - timedelta(minutes=16))
        unknown = SecurityEvent("failed-login", "sip", None)
        self.read_security.return_value = [fresh, boundary, old, unknown]
        initial = self.collector.enrich(self.snapshot, self.settings)
        self.clock[0] = 30
        result = self.collector.enrich(self.snapshot, self.settings)
        self.assertEqual(result.security_events, [fresh, boundary])
        self.assertEqual(len(initial.security_events), 4)
        self.read_security.assert_called_once()

    def test_connector_owned_history_passes_through_without_io(self):
        for pbx_type in ("mock", "freeswitch", "yeastar"):
            self.settings.pbx_type = pbx_type
            self.assertIs(self.collector.enrich(self.snapshot, self.settings), self.snapshot)
        self.read_calls.assert_not_called()
        self.read_vm.assert_not_called()
        self.read_security.assert_not_called()
        self.read_cucm.assert_not_called()

    def test_grandstream_paths_remain_connector_specific(self):
        self.settings.pbx_type = "grandstream"
        self.assertEqual(history_paths(self.settings), ("ucm-cdr", "ucm-voicemail"))
        self.assertEqual(security_log_path(self.settings), "ucm-security")
        self.collector.enrich(self.snapshot, self.settings)
        self.read_calls.assert_called_once_with("ucm-cdr", limit=1000)
        self.read_vm.assert_called_once_with("ucm-voicemail")
        self.read_security.assert_called_once_with("ucm-security")

    def test_cucm_reloads_on_interval_and_enriches_each_observation(self):
        self.settings.pbx_type = "cucm"
        enriched_endpoints = [Mock()]
        with patch("pbxsense_agent.history_collection.enrich_cucm_trunks_with_history",
                   return_value=enriched_endpoints) as enrich:
            first = self.collector.enrich(self.snapshot, self.settings)
            self.clock[0] = 29
            second = self.collector.enrich(replace(self.snapshot, reachable=False), self.settings)
            self.clock[0] = 30
            self.collector.enrich(self.snapshot, self.settings)
        self.assertEqual(self.read_cucm.call_count, 2)
        self.read_cucm.assert_called_with("cucm-cdr", "cucm-cmr", limit=1000)
        self.assertEqual(enrich.call_count, 3)
        self.assertIs(first.endpoints, enriched_endpoints)
        self.assertFalse(second.reachable)
        self.assertIs(second.recent_calls, self.calls)
        self.assertEqual(second.voicemails, [])
        self.read_calls.assert_not_called()
