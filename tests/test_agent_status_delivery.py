from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock
import unittest

from push_relay.notification_delivery import AgentStatusDelivery


class AgentStatusDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.messaging = MagicMock()
        self.messaging.send_each_for_multicast.return_value = SimpleNamespace(
            responses=[SimpleNamespace(success=True, exception=None)],
            success_count=1, failure_count=0,
        )
        self.order = []
        self.cleanup = MagicMock(side_effect=lambda *a: self.order.append("cleanup") or 1)
        self.usage = MagicMock(side_effect=lambda *a, **k: self.order.append("usage"))
        self.log = MagicMock(side_effect=lambda *a: self.order.append("log"))
        self.delivery = AgentStatusDelivery(
            messaging=self.messaging, cleanup=self.cleanup,
            record_usage=self.usage, log=self.log,
            safe_identifier=lambda value: "safe-agent", monotonic=lambda: 5.0,
        )

    def send(self, devices=None, agent=None):
        return self.delivery.deliver(
            agent_id="agent", agent=agent,
            devices=[{"fcmToken": "token"}] if devices is None else devices,
            title="Agent unavailable", body="Check the Agent.", now=self.now,
        )

    def test_status_preferences_expiry_and_token_deduplication(self):
        self.send([
            {"fcmToken": "disabled", "meaningfulEnabled": False},
            {"fcmToken": "expired", "expiresAt": self.now - timedelta(seconds=1)},
            {"fcmToken": "token", "_documentId": "older"},
            {"fcmToken": "token", "_documentId": "newer", "activityEnabled": False,
             "mutedSignalIds": ["anything"]},
        ])
        message = self.messaging.MulticastMessage.call_args.kwargs
        self.assertEqual(message["tokens"], ["token"])
        self.assertEqual(message["data"], {"kind": "agent_connection", "agentId": "agent"})
        self.messaging.AndroidConfig.assert_called_once_with(priority="high")
        self.assertEqual(self.cleanup.call_args.args[1][0]["_documentId"], "newer")
        self.assertEqual(self.order, ["cleanup", "usage", "log"])
        self.assertNotIn("quota_count", self.usage.call_args.kwargs)
        self.assertEqual(self.usage.call_args.kwargs["invalid"], 1)

    def test_no_recipients_records_without_sending(self):
        self.send([])
        self.messaging.send_each_for_multicast.assert_not_called()
        self.cleanup.assert_not_called()
        self.assertEqual(self.order, ["usage", "log"])
        self.assertEqual(self.usage.call_args.kwargs["no_recipients"], 1)
        self.assertEqual(self.usage.call_args.args[1], {})

    def test_transport_failure_records_then_propagates(self):
        failure = RuntimeError("send failed")
        self.messaging.send_each_for_multicast.side_effect = failure
        with self.assertRaises(RuntimeError) as caught:
            self.send()
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.order, ["usage"])
        self.assertEqual(self.usage.call_args.kwargs["transport_errors"], 1)
        self.assertEqual(self.usage.call_args.kwargs["failed"], 1)
        self.cleanup.assert_not_called()

    def test_cleanup_failure_prevents_usage_and_logging(self):
        self.cleanup.side_effect = RuntimeError("cleanup failed")
        with self.assertRaises(RuntimeError):
            self.send()
        self.usage.assert_not_called()
        self.log.assert_not_called()

    def test_reporting_failure_after_send_preserves_cleanup_order(self):
        self.usage.side_effect = RuntimeError("usage failed")
        with self.assertRaises(RuntimeError):
            self.send()
        self.cleanup.assert_called_once()
        self.log.assert_not_called()
