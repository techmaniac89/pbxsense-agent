import ast
import asyncio
import hashlib
import json
import secrets
import time
import unittest
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, AsyncMock

from fastapi import HTTPException
from pbxsense_agent.live import home_live_events
from pbxsense_agent.relay import _secure_snapshot_projection


class DeliveryLifecycleTest(unittest.TestCase):
    def setUp(self):
        tree = ast.parse(Path("push_relay/app.py").read_text(encoding="utf-8"))
        names = {"_claim_event_delivery", "_finish_event_delivery", "_recipient_digest",
                 "_retryable_fcm_failure", "publish_event"}
        nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
        for node in nodes:
            node.decorator_list = []
        self.ns = dict(Any=object, Request=object, datetime=datetime, timedelta=timedelta,
                       timezone=timezone, hashlib=hashlib, json=json, secrets=secrets,
                       time=time, HTTPException=HTTPException,
                       firestore=SimpleNamespace(SERVER_TIMESTAMP="server-time"),
                       MAX_EVENTS_PER_AGENT_PER_HOUR=60)
        exec(compile(ast.Module(nodes, type_ignores=[]), "delivery", "exec"), self.ns)

    def test_relay_keeps_pbx_failure_separate_from_transport(self):
        projected = _secure_snapshot_projection({"connection": {"kind": "reconnecting", "label": "Reconnecting"}})
        self.assertEqual(projected["connection"]["kind"], "reconnecting")
        self.assertEqual(projected["connection"]["transport"], "internetRelay")
        self.assertFalse(projected["connection"]["pbxReachable"])
        self.assertEqual(_secure_snapshot_projection({"connection": {"kind": "local"}})["connection"]["kind"], "internetRelay")

    def test_removal_with_other_changes_replaces_full_state(self):
        for collection, key in (("people", "extension"), ("trunks", "endpoint"), ("queues", "queue")):
            previous = {collection: [{key: "one"}, {key: "two"}], "signals": []}
            current = {collection: [{key: "one"}], "signals": [{"id": "new"}]}
            self.assertEqual(home_live_events(previous, current), [{"type": "home_snapshot", "data": current}])

    def test_new_delivery_and_quota_are_written_atomically(self):
        txn, event, quota = MagicMock(), MagicMock(), MagicMock()
        event.get.return_value.exists = False
        quota.get.return_value.exists = False
        now = datetime.now(timezone.utc)
        row = self.ns["_claim_event_delivery"](txn, event, quota, "agent", "hash", "owner", now)
        self.assertEqual(row["state"], "sending")
        self.assertEqual(row["quotaCount"], 1)
        self.assertEqual(txn.set.call_count, 2)

    def test_expired_lease_resumes_without_charging_quota_again(self):
        txn, event, quota = MagicMock(), MagicMock(), MagicMock()
        now = datetime.now(timezone.utc)
        event.get.return_value.exists = True
        event.get.return_value.to_dict.return_value = {"agentId": "agent", "fingerprint": "hash", "state": "sending", "leaseUntil": now - timedelta(seconds=1), "quotaCount": 3, "completedRecipients": ["a"]}
        row = self.ns["_claim_event_delivery"](txn, event, quota, "agent", "hash", "new-owner", now)
        self.assertEqual(row["completedRecipients"], ["a"])
        quota.get.assert_not_called()
        self.assertEqual(row["owner"], "new-owner")
        with self.assertRaises(HTTPException):
            event.get.return_value.to_dict.return_value = row
            self.ns["_claim_event_delivery"](txn, event, quota, "agent", "hash", "concurrent", now)

    def test_partial_failure_retries_only_unsent_recipients(self):
        db = MagicMock()
        event_ref = db.collection.return_value.document.return_value.collection.return_value.document.return_value
        devices = [{"fcmToken": "a"}, {"fcmToken": "b"}]
        db.collection.return_value.document.return_value.collection.return_value.stream.return_value = devices
        delivery = {"quotaCount": 1, "completedRecipients": []}
        claim, finish = MagicMock(return_value=delivery), MagicMock()
        messaging = MagicMock()
        messaging.send_each_for_multicast.return_value = SimpleNamespace(
            success_count=1, failure_count=1, responses=[SimpleNamespace(success=True, exception=None), SimpleNamespace(success=False, exception=SimpleNamespace(code="unavailable"))])
        self.ns.update(db=db, messaging=messaging, logger=MagicMock(),
                       _authenticate_agent=AsyncMock(return_value=({"id": "event", "title": "Title", "body": "Body", "category": "health", "importance": "attention"}, {"siteId": "site"})),
                       _consume_window=lambda *a, **k: True, _event_windows=defaultdict(deque),
                       _bounded_identifier=lambda x, _: str(x), _bounded_text=lambda x, *a: str(x),
                       _optional_identifier=lambda x: x or "", _device_record=lambda x: x,
                       _unique_devices_by_token=lambda x: x, _device_wants_event=lambda *a: True,
                       _record_notification_usage=MagicMock(), _remove_invalid_tokens=lambda *a: 0,
                       _safe_log_identifier=lambda x: x,
                       _claim_event_delivery=claim, _finish_event_delivery=finish)
        with self.assertRaises(HTTPException) as caught:
            asyncio.run(self.ns["publish_event"]("agent", object()))
        self.assertEqual(caught.exception.status_code, 503)
        completed = finish.call_args.args[3]
        self.assertEqual(completed, {hashlib.sha256(b"a").hexdigest()})
        self.assertFalse(finish.call_args.args[4])
        delivery["completedRecipients"] = list(completed)
        messaging.send_each_for_multicast.return_value = SimpleNamespace(success_count=1, failure_count=0, responses=[SimpleNamespace(success=True, exception=None)])
        asyncio.run(self.ns["publish_event"]("agent", object()))
        self.assertEqual(messaging.MulticastMessage.call_args.kwargs["tokens"], ["b"])
        self.assertTrue(finish.call_args.args[4])

    def test_permanent_errors_are_terminal_unknown_errors_retry(self):
        self.assertFalse(self.ns["_retryable_fcm_failure"](SimpleNamespace(code="invalid-argument")))
        self.assertTrue(self.ns["_retryable_fcm_failure"](RuntimeError("unknown")))

    def test_completed_and_legacy_events_are_deduplicated(self):
        event, txn, quota = MagicMock(), MagicMock(), MagicMock()
        event.get.return_value.exists = True
        for state in ({"state": "completed"}, {}):
            event.get.return_value.to_dict.return_value = {"agentId": "agent", **state}
            self.assertIsNone(self.ns["_claim_event_delivery"](txn, event, quota, "agent", "hash", "owner", datetime.now(timezone.utc)))
        txn.set.assert_not_called()

    def test_lost_owner_cannot_checkpoint_another_sender(self):
        event, txn = MagicMock(), MagicMock()
        event.get.return_value.to_dict.return_value = {"owner": "new-owner"}
        with self.assertRaises(HTTPException):
            self.ns["_finish_event_delivery"](txn, event, "old-owner", {"recipient"}, True)
        txn.update.assert_not_called()

    def test_changed_payload_and_exhausted_quota_do_not_write(self):
        event, quota, txn = MagicMock(), MagicMock(), MagicMock()
        now = datetime.now(timezone.utc)
        event.get.return_value.exists = True
        event.get.return_value.to_dict.return_value = {"agentId": "agent", "state": "pending", "fingerprint": "original"}
        with self.assertRaises(HTTPException) as changed:
            self.ns["_claim_event_delivery"](txn, event, quota, "agent", "changed", "owner", now)
        self.assertEqual(changed.exception.status_code, 409)
        event.get.return_value.exists = False
        quota.get.return_value.exists = True
        quota.get.return_value.to_dict.return_value = {"count": 60}
        with self.assertRaises(HTTPException) as limited:
            self.ns["_claim_event_delivery"](txn, event, quota, "agent", "hash", "owner", now)
        self.assertEqual(limited.exception.status_code, 429)
        txn.set.assert_not_called()
