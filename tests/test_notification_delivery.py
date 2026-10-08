from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
import unittest

from fastapi import HTTPException
from push_relay.notification_delivery import NotificationDelivery, _recipient_digest


class NotificationDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.calls = []
        self.messaging = MagicMock()
        self.messaging.send_each_for_multicast.return_value = SimpleNamespace(
            responses=[SimpleNamespace(success=True, exception=None)],
            success_count=1, failure_count=0,
        )
        self.checkpoint = MagicMock(
            side_effect=lambda completed, done: self.calls.append(
                ("checkpoint", set(completed), done),
            ),
        )
        self.cleanup = MagicMock(side_effect=lambda *args: self.calls.append(("cleanup",)) or 0)
        self.usage = MagicMock(side_effect=lambda *args, **kwargs: self.calls.append(("usage",)))
        self.log = MagicMock()
        self.coordinator = NotificationDelivery(
            messaging=self.messaging, checkpoint=self.checkpoint,
            cleanup=self.cleanup, record_usage=self.usage,
            log=self.log, safe_identifier=lambda value: "safe-id",
            monotonic=lambda: 10.0,
        )

    def deliver(self, devices=None, completed=None, **changes):
        parameters = dict(
            agent_id="agent", agent={"siteId": "site"},
            devices=[{"fcmToken": "token"}] if devices is None else devices,
            completed=set() if completed is None else completed, quota_count=7,
            event_id="episode", signal_id="signal", title="Title", body="Body",
            category="health", importance="attention", notification_tag="stable-tag",
            now=self.now,
        )
        parameters.update(changes)
        return self.coordinator.deliver(**parameters)

    def test_payload_tags_and_checkpoint_precede_cleanup_and_usage(self):
        self.assertEqual(self.deliver(), {"status": "accepted", "sent": 1, "failed": 0})
        message = self.messaging.MulticastMessage.call_args.kwargs
        self.assertEqual(message["tokens"], ["token"])
        self.assertEqual(message["data"], {
            "signalId": "signal", "notificationId": "episode",
            "siteId": "site", "agentId": "agent", "category": "health",
            "importance": "attention",
        })
        self.messaging.AndroidNotification.assert_called_once_with(tag="stable-tag")
        self.assertEqual([call[0] for call in self.calls], ["checkpoint", "cleanup", "usage"])
        self.checkpoint.assert_called_once_with({_recipient_digest("token")}, True)
        self.assertEqual(self.usage.call_args.kwargs["quota_count"], 7)
        self.assertEqual(self.log.call_args.args[1], "safe-id")

    def test_selection_preserves_preferences_expiration_dedupe_and_completed(self):
        devices = [
            {"fcmToken": "disabled", "meaningfulEnabled": False},
            {"fcmToken": "muted", "mutedSignalIds": ["signal"]},
            {"fcmToken": "expired", "expiresAt": self.now - timedelta(seconds=1)},
            {"fcmToken": "done"},
            {"fcmToken": ""},
            {"fcmToken": "token", "_documentId": "older"},
            {"fcmToken": "token", "_documentId": "newer", "activityEnabled": False},
        ]
        self.deliver(devices, completed={_recipient_digest("done")})
        self.assertEqual(self.messaging.MulticastMessage.call_args.kwargs["tokens"], ["token"])
        self.assertEqual(self.cleanup.call_args.args[1][0]["_documentId"], "newer")

    def test_activity_requires_both_existing_preference_flags(self):
        self.deliver([
            {"fcmToken": "activity-off", "activityEnabled": False},
            {"fcmToken": "meaningful-off", "meaningfulEnabled": False, "activityEnabled": True},
            {"fcmToken": "token"},
        ], category="activity", importance="feed")
        self.assertEqual(self.messaging.MulticastMessage.call_args.kwargs["tokens"], ["token"])

    def test_no_recipients_completes_without_sending(self):
        self.assertEqual(self.deliver([]), {"status": "accepted", "sent": 0})
        self.messaging.send_each_for_multicast.assert_not_called()
        self.checkpoint.assert_called_once_with(set(), True)
        self.cleanup.assert_not_called()
        self.assertEqual(self.usage.call_args.kwargs["no_recipients"], 1)
        self.assertEqual([call[0] for call in self.calls], ["checkpoint", "usage"])

    def test_partial_transient_failure_is_pending_and_retry_skips_completed(self):
        self.messaging.send_each_for_multicast.return_value = SimpleNamespace(
            responses=[
                SimpleNamespace(success=True, exception=None),
                SimpleNamespace(success=False, exception=SimpleNamespace(code="unavailable")),
            ], success_count=1, failure_count=1,
        )
        completed = set()
        with self.assertRaises(HTTPException) as caught:
            self.deliver([{"fcmToken": "a"}, {"fcmToken": "b"}], completed=completed)
        self.assertEqual(caught.exception.status_code, 503)
        self.checkpoint.assert_called_once_with({_recipient_digest("a")}, False)
        self.messaging.send_each_for_multicast.return_value = SimpleNamespace(
            responses=[SimpleNamespace(success=True, exception=None)],
            success_count=1, failure_count=0,
        )
        self.deliver([{"fcmToken": "a"}, {"fcmToken": "b"}], completed=completed)
        self.assertEqual(self.messaging.MulticastMessage.call_args.kwargs["tokens"], ["b"])

    def test_permanent_failure_is_terminal_and_cleanup_result_is_reported(self):
        self.messaging.send_each_for_multicast.return_value = SimpleNamespace(
            responses=[SimpleNamespace(
                success=False, exception=SimpleNamespace(code="unregistered"),
            )], success_count=0, failure_count=1,
        )
        self.cleanup.side_effect = None
        self.cleanup.return_value = 1
        self.assertEqual(self.deliver(), {"status": "accepted", "sent": 0, "failed": 1})
        self.checkpoint.assert_called_once_with({_recipient_digest("token")}, True)
        self.assertEqual(self.usage.call_args.kwargs["invalid"], 1)

    def test_transport_error_records_usage_then_releases_pending_before_raise(self):
        failure = RuntimeError("FCM transport unavailable")
        self.messaging.send_each_for_multicast.side_effect = failure
        with self.assertRaises(RuntimeError) as caught:
            self.deliver()
        self.assertIs(caught.exception, failure)
        self.assertEqual([call[0] for call in self.calls], ["usage", "checkpoint"])
        self.checkpoint.assert_called_once_with(set(), False)
        self.cleanup.assert_not_called()
        self.assertEqual(self.usage.call_args.kwargs["transport_errors"], 1)

    def test_usage_failure_after_send_does_not_erase_delivery_checkpoint(self):
        self.usage.side_effect = RuntimeError("usage write failed")
        with self.assertRaises(RuntimeError):
            self.deliver()
        self.checkpoint.assert_called_once_with({_recipient_digest("token")}, True)
        self.cleanup.assert_called_once()

    def test_lost_lease_blocks_cleanup_and_usage_after_send(self):
        self.checkpoint.side_effect = HTTPException(503, "Event delivery lease changed")
        with self.assertRaises(HTTPException):
            self.deliver()
        self.cleanup.assert_not_called()
        self.usage.assert_not_called()

    def test_incomplete_fcm_response_is_checkpointed_pending(self):
        self.messaging.send_each_for_multicast.return_value = SimpleNamespace(
            responses=[], success_count=0, failure_count=0,
        )
        with self.assertRaises(HTTPException) as caught:
            self.deliver()
        self.assertEqual(caught.exception.status_code, 503)
        self.checkpoint.assert_called_once_with(set(), False)

    def test_cloud_image_copies_delivery_module(self):
        self.assertIn("COPY notification_delivery.py .",
                      Path("push_relay/Dockerfile").read_text())
