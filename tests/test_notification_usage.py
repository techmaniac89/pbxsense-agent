from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock
import unittest

from push_relay.notification_usage import NotificationUsageRecorder


class NotificationUsageTests(unittest.TestCase):
    def setUp(self):
        self.db = MagicMock()
        self.now = datetime(2026, 10, 9, 12, 30, tzinfo=timezone.utc)
        self.update = MagicMock(return_value={"usageDate": "2026-10-09"})
        self.recorder = NotificationUsageRecorder(
            db=self.db, server_timestamp="server-time",
            usage_update=self.update, now=lambda: self.now,
        )

    def record(self, **changes):
        values = dict(eligible=2, accepted=1, failed=1, invalid=1, latency_ms=50)
        values.update(changes)
        self.recorder.record("agent", {"siteId": "site"}, **values)

    def test_fields_and_rollup_callback_preserve_counter_contract(self):
        self.record(quota_count=7, transport_errors=1)
        self.db.collection.assert_called_once_with("agents")
        reference = self.db.collection.return_value.document.return_value
        fields = reference.update.call_args.args[0]
        self.assertEqual(fields, {
            "lastFcmAttemptAt": "server-time", "lastFcmLatencyMs": 50,
            "lastFcmAccepted": 1, "lastFcmFailed": 1,
            "currentEventQuotaHour": "2026100912", "currentEventQuotaCount": 7,
            "usageDate": "2026-10-09",
        })
        self.assertEqual(self.update.call_args.args,
                         (reference, {"siteId": "site"}, "agent", "agent"))
        self.assertEqual(self.update.call_args.kwargs, {
            "notificationAttempts": 1, "notificationFcmAttempts": 1,
            "notificationEligible": 2, "notificationAccepted": 1,
            "notificationFailed": 1, "notificationInvalidTokens": 1,
            "notificationLatencyMs": 50, "notificationNoRecipients": 0,
            "notificationTransportErrors": 1,
        })

    def test_empty_attempt_and_negative_values_are_clamped(self):
        self.record(eligible=-1, accepted=-1, failed=-1, invalid=-1,
                    latency_ms=-1, no_recipients=1, transport_errors=-1, quota_count=-1)
        counters = self.update.call_args.kwargs
        self.assertEqual(counters["notificationAttempts"], 1)
        self.assertEqual(counters["notificationFcmAttempts"], 0)
        self.assertTrue(all(value >= 0 for value in counters.values()))
        fields = self.db.collection.return_value.document.return_value.update.call_args.args[0]
        self.assertEqual(fields["currentEventQuotaCount"], 0)

    def test_status_reporting_does_not_overwrite_event_quota(self):
        self.record(eligible=0, no_recipients=1)
        fields = self.db.collection.return_value.document.return_value.update.call_args.args[0]
        self.assertNotIn("currentEventQuotaHour", fields)
        self.assertNotIn("currentEventQuotaCount", fields)
        self.assertEqual(self.update.call_args.kwargs["notificationFcmAttempts"], 0)

    def test_rollup_failure_prevents_agent_update(self):
        self.update.side_effect = RuntimeError("rollup failed")
        with self.assertRaises(RuntimeError):
            self.record()
        self.db.collection.return_value.document.return_value.update.assert_not_called()

    def test_cloud_image_includes_reporting_module(self):
        self.assertIn("COPY notification_usage.py .", Path("push_relay/Dockerfile").read_text())
