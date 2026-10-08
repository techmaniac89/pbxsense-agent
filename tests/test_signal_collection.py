from datetime import datetime, timezone
import unittest
from unittest.mock import Mock, patch

from pbxsense_agent import main
from pbxsense_agent.observations import PbxSnapshot
from pbxsense_agent.signal_collection import SignalCollector


class SignalCollectionTest(unittest.TestCase):
    def test_tracker_order_and_state_mapping_are_preserved(self):
        root = Mock()
        activity, endpoints, trunks, tip, last = (getattr(root, name) for name in
                                                 ("activity", "endpoints", "trunks", "tip", "last"))
        activity.observe.return_value = [{"id": "activity"}]
        endpoints.observe.return_value = {"101"}
        endpoints.notification_ids.return_value = {"101": "episode"}
        endpoints.signal_endpoints.return_value = {"101": Mock()}
        endpoints.signal_lifecycle.return_value = {"101": {"startedAt": "now"}}
        trunks.observe.return_value = {"trunk"}
        tip.observe.return_value = False
        last.observe.return_value = {"101": datetime(2026, 10, 8, tzinfo=timezone.utc)}
        collector = SignalCollector(activity=activity, endpoints=endpoints, trunks=trunks,
                                    aggregate_tip=tip, last_active=last)
        snapshot = PbxSnapshot(False, "test", error="offline")
        now = datetime(2026, 10, 9, tzinfo=timezone.utc)
        state = collector.collect(snapshot, now)
        self.assertEqual([call[0] for call in root.mock_calls], [
            "activity.observe", "endpoints.observe", "endpoints.notification_ids",
            "endpoints.signal_endpoints", "endpoints.signal_lifecycle", "trunks.observe",
            "tip.observe", "last.observe",
        ])
        for tracker in (activity, endpoints, trunks, tip, last):
            tracker.observe.assert_called_once_with(snapshot, now)
        self.assertIs(state.snapshot, snapshot)
        self.assertIs(state.observed_at, now)
        for field, result in (
            ("moment_events", activity.observe.return_value),
            ("endpoint_unavailability_signals", endpoints.observe.return_value),
            ("endpoint_notification_ids", endpoints.notification_ids.return_value),
            ("endpoint_unavailability_evidence", endpoints.signal_endpoints.return_value),
            ("endpoint_signal_lifecycle", endpoints.signal_lifecycle.return_value),
            ("trunk_unavailability_signals", trunks.observe.return_value),
            ("endpoint_last_active", last.observe.return_value),
        ):
            self.assertIs(getattr(state, field), result)
        self.assertFalse(state.show_aggregate_tip)

    def test_main_enriches_history_before_observing_signals(self):
        order = Mock()
        snapshot, enriched, state = Mock(), Mock(), Mock()
        now = datetime(2026, 10, 9, tzinfo=timezone.utc)
        order.connector.snapshot.return_value = snapshot
        order.history.enrich.return_value = enriched
        order.signals.collect.return_value = state
        with patch.object(main, "connector", order.connector), \
                patch.object(main, "_history_collector", order.history), \
                patch.object(main, "_signal_collector", order.signals), \
                patch.object(main, "_now", return_value=now):
            self.assertIs(main._collect_home_state(), state)
        order.history.enrich.assert_called_once_with(snapshot, main.settings)
        order.signals.collect.assert_called_once_with(enriched, now)
        self.assertEqual([call[0] for call in order.mock_calls],
                         ["connector.snapshot", "history.enrich", "signals.collect"])
