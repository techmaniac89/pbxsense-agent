from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from pbxsense_agent import main
from pbxsense_agent.history_collection import HistoryCollector
from pbxsense_agent.observations import PbxEndpoint, PbxSnapshot
from pbxsense_agent.presence_history import EndpointLastActiveTracker
from pbxsense_agent.pulse import (
    ActivityTracker, EndpointAvailabilitySignalTracker, EndpointAggregateTipTracker,
    SignalNotificationEpisodeTracker,
)
from pbxsense_agent.signal_collection import SignalCollector
from pbxsense_agent.snapshot_runtime import SnapshotRuntime


class SnapshotPipelineTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(TemporaryDirectory())
        self.seconds = 0
        self.origin = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
        self.connector = Mock()
        self.connector.snapshot.return_value = self.snapshot()
        self.history = HistoryCollector(poll_interval=30, monotonic=lambda: self.seconds)
        self.signals = SignalCollector(
            activity=ActivityTracker(), endpoints=EndpointAvailabilitySignalTracker(),
            trunks=EndpointAvailabilitySignalTracker(role="trunk", recovery_confirmation=timedelta(0)),
            aggregate_tip=EndpointAggregateTipTracker(timedelta(seconds=180)),
            last_active=EndpointLastActiveTracker(str(Path(directory) / "activity.json")),
        )
        self.runtime = SnapshotRuntime(
            collect=main._collect_home_state,
            build_payload=lambda state, hours: main._home_payload_from_state(state, moment_hours=hours),
            stale_after=10, stall_after=60, clock=lambda: self.seconds,
        )
        settings = replace(main.settings, pbx_type="mock", timezone="UTC")
        for name, value in (("settings", settings), ("connector", self.connector),
                            ("_history_collector", self.history), ("_signal_collector", self.signals),
                            ("signal_notification_episode_tracker", SignalNotificationEpisodeTracker())):
            self.stack.enter_context(patch.object(main, name, value))
        self.stack.enter_context(patch.object(main, "_now", side_effect=lambda _: self.origin + timedelta(seconds=self.seconds)))
        self.stack.enter_context(patch.object(main.push_relay, "status", return_value={"agentId": "test-agent"}))
        self.stack.enter_context(patch.object(main.internet_relay, "status", return_value={"enabled": False}))

    def snapshot(self, *offline, reachable=True):
        return PbxSnapshot(reachable, "test", endpoints=[
            PbxEndpoint(extension, "Unavailable" if extension in offline else "Reachable")
            for extension in ("101", "102", "103")
        ])

    def publish(self, seconds, *offline, reachable=True):
        self.seconds = seconds
        self.connector.snapshot.return_value = self.snapshot(*offline, reachable=reachable)
        self.runtime.refresh()
        return self.runtime.home()

    def health(self, payload):
        return [signal for signal in payload["signals"] if signal["kind"] == "endpoint_unavailable"]

    def test_phone_incident_confirmation_recovery_and_rearming_across_pipeline(self):
        self.publish(0)
        self.assertEqual(self.health(self.publish(1, "101")), [])
        self.assertEqual(self.health(self.publish(5.9, "101")), [])
        first = self.publish(6, "101")
        incident = self.health(first)[0]["notificationId"]
        self.assertEqual(self.health(self.publish(20, "101"))[0]["notificationId"], incident)
        # Brief recovery keeps the confirmed incident; full recovery rearms it.
        self.assertEqual(self.health(self.publish(21))[0]["notificationId"], incident)
        recovered = self.publish(36)
        self.assertEqual(self.health(recovered), [])
        activities = [s for s in recovered["signals"] if s["kind"] == "pbx_phone_recovered_activity"]
        self.assertEqual(len(activities), 1)
        self.publish(37, "101")
        second = self.publish(42, "101")
        self.assertNotEqual(self.health(second)[0]["notificationId"], incident)
        self.assertEqual(len(self.health(first)), 1)  # Prior cached generation is unchanged.
        self.assertFalse(any(s["kind"] == "pbx_phone_recovered_activity" for s in second["signals"]))

    def test_partial_inventory_does_not_declare_all_phones_recovered(self):
        self.publish(0)
        self.publish(1, "101", "102")
        self.publish(6, "101", "102")
        self.publish(7, "102")
        self.seconds = 22
        self.connector.snapshot.return_value = PbxSnapshot(True, "test", endpoints=[
            PbxEndpoint("101", "Reachable"), PbxEndpoint("103", "Reachable"),
        ])
        self.runtime.refresh()
        payload = self.runtime.home()
        self.assertEqual([s["technical"]["extension"] for s in self.health(payload)], ["102"])
        activity = next(s for s in payload["signals"] if s["kind"] == "pbx_phone_recovered_activity")
        self.assertEqual(activity["technical"]["recovered_extensions"], "101")
        self.assertEqual(activity["technical"]["remaining_unavailable_extensions"], "102")
        self.assertNotIn("All monitored", activity["title"])

    def test_history_failure_preserves_publication_then_recovers_without_signal_observation(self):
        self.stack.enter_context(patch.object(main, "settings", replace(
            main.settings, pbx_type="asterisk", cdr_csv_path="", voicemail_path="", asterisk_security_log_path="",
        )))
        security = Mock(return_value=[])
        self.history = HistoryCollector(
            poll_interval=30, monotonic=lambda: self.seconds,
            read_calls=Mock(return_value=[]), read_voicemails=Mock(return_value=[]), read_security=security,
        )
        self.stack.enter_context(patch.object(main, "_history_collector", self.history))
        self.stack.enter_context(patch.object(self.history, "_available", return_value=True))
        initial = self.publish(0)
        security.side_effect = OSError("history unavailable")
        self.seconds = 30
        with patch("pbxsense_agent.history_collection.file_signature", return_value=("changed", 1, 1)), \
                patch.object(self.signals, "collect", wraps=self.signals.collect) as observe:
            with self.assertRaisesRegex(OSError, "history unavailable"):
                self.runtime.refresh()
            observe.assert_not_called()
            stale = self.runtime.home()
            self.assertTrue(stale["snapshotStale"])
            self.assertEqual(stale["connection"]["kind"], "reconnecting")
            self.assertEqual(stale["snapshotObservedAt"], initial["snapshotObservedAt"])
            self.assertFalse(initial["snapshotStale"])
            security.side_effect = None
            self.runtime.refresh()
            observe.assert_called_once()
        recovered = self.runtime.home()
        self.assertFalse(recovered["snapshotStale"])
        self.assertNotEqual(recovered["snapshotObservedAt"], initial["snapshotObservedAt"])
