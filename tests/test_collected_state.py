from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from pbxsense_agent import main
from pbxsense_agent.collected_state import CollectedHomeState
from pbxsense_agent.connectors import MockConnector


class CollectedStateTest(unittest.TestCase):
    def state(self, **overrides):
        values = dict(
            snapshot=MockConnector().snapshot(),
            observed_at=datetime(2026, 10, 9, tzinfo=timezone.utc),
            moment_events=[{"id": "activity"}],
            endpoint_unavailability_signals={"101"},
            endpoint_notification_ids={"101": "episode"},
            endpoint_unavailability_evidence={},
            endpoint_signal_lifecycle={"101": {"startedAt": "now"}},
            trunk_unavailability_signals={"trunk"},
            show_aggregate_tip=False,
            endpoint_last_active={"101": datetime(2026, 10, 8, tzinfo=timezone.utc)},
        )
        values.update(overrides)
        return CollectedHomeState(**values)

    def test_state_requires_named_fields_and_prevents_rebinding(self):
        state = self.state()
        with self.assertRaises(TypeError):
            CollectedHomeState(state.snapshot)
        with self.assertRaises(FrozenInstanceError):
            state.show_aggregate_tip = True

    def test_payload_maps_named_fields_without_copying_collections(self):
        state = self.state()
        raw = {"signals": [{"id": "health"}, {"id": "sig_tip_multiple_endpoints_unavailable"}], "connection": {}}
        with patch.object(main, "build_home_payload", return_value=raw) as builder, \
                patch.object(main.signal_notification_episode_tracker, "observe") as episodes, \
                patch.object(main.push_relay, "status", return_value={"agentId": "agent"}), \
                patch.object(main.internet_relay, "status", return_value={"enabled": False}):
            payload = main._home_payload_from_state(state, moment_hours=12)
        self.assertIs(builder.call_args.args[0], state.snapshot)
        for name in ("moment_events", "endpoint_unavailability_signals", "endpoint_notification_ids",
                     "endpoint_unavailability_evidence", "endpoint_signal_lifecycle",
                     "trunk_unavailability_signals", "endpoint_last_active"):
            self.assertIs(builder.call_args.kwargs[name], getattr(state, name))
        self.assertEqual(builder.call_args.kwargs["now"], state.observed_at)
        self.assertEqual(builder.call_args.kwargs["moment_hours"], 12)
        self.assertEqual(payload["signals"], [{"id": "health"}])
        episodes.assert_called_once_with(payload["signals"])
        self.assertEqual(payload["snapshotObservedAt"], state.observed_at.isoformat())
        self.assertFalse(payload["snapshotStale"])
        self.assertEqual(payload["connection"]["pushRelayAgentId"], "agent")

    def test_aggregate_tip_is_preserved_when_ready(self):
        state = replace(self.state(), show_aggregate_tip=True)
        signals = [{"id": "sig_tip_multiple_endpoints_unavailable"}]
        with patch.object(main, "build_home_payload", return_value={"signals": signals, "connection": {}}), \
                patch.object(main.signal_notification_episode_tracker, "observe"), \
                patch.object(main.push_relay, "status", return_value={}), \
                patch.object(main.internet_relay, "status", return_value={}):
            self.assertIs(main._home_payload_from_state(state, moment_hours=24)["signals"], signals)
