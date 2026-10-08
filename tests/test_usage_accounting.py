from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
import unittest

from push_relay.usage_accounting import UsageAccounting, _current_usage, _usage_identity


class UsageAccountingTests(unittest.TestCase):
    def setUp(self):
        self.db = MagicMock()
        self.now = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
        self.reference = MagicMock()
        self.increment = MagicMock(side_effect=lambda value: ("increment", value))
        self.accounting = UsageAccounting(
            db=self.db, server_timestamp="server-time",
            increment=self.increment, now=lambda: self.now,
        )
        self.old = {"usageDate": "2026-10-08", "usage": {"heartbeats": 10}}

    def archive_reference(self):
        return (self.db.collection.return_value.document.return_value
                .collection.return_value.document.return_value)

    def test_same_day_uses_increments_without_archiving_or_extra_write(self):
        result = self.accounting.update(
            self.reference, {"usageDate": "2026-10-09"}, "agent", "agent-id",
            heartbeats=2, empty=0, negative=-1,
        )
        self.assertEqual(result, {"usage.heartbeats": ("increment", 2)})
        self.db.collection.assert_not_called()
        self.reference.update.assert_not_called()

    def test_rollover_archives_before_marker_and_returns_new_counters(self):
        order = []
        archive = self.archive_reference()
        archive.set.side_effect = lambda *a: order.append("archive")
        self.reference.update.side_effect = lambda *a: order.append("marker")
        result = self.accounting.update(
            self.reference, self.old, "agent", "agent-id", heartbeats=1,
        )
        self.assertEqual(order, ["archive", "marker"])
        self.assertEqual(result, {"usageDate": "2026-10-09", "usage": {"heartbeats": 1}})
        record = archive.set.call_args.args[0]
        self.assertEqual(record, {
            "kind": "agent", "usage": {"heartbeats": 10},
            "archivedAt": "server-time", "expiresAt": self.now + timedelta(days=90),
        })
        self.assertEqual(self.db.collection.return_value.document.call_args.args,
                         ("2026-10-08",))
        self.assertEqual(self.db.collection.return_value.document.return_value
                         .collection.return_value.document.call_args.args,
                         (_usage_identity("agent", "agent-id"),))

    def test_archive_failure_does_not_set_marker_or_return_reset_fields(self):
        self.archive_reference().set.side_effect = RuntimeError("archive write failed")
        with self.assertRaises(RuntimeError):
            self.accounting.update(self.reference, self.old, "agent", "id", heartbeats=1)
        self.reference.update.assert_not_called()

    def test_marker_failure_propagates_after_archive(self):
        self.reference.update.side_effect = RuntimeError("marker failed")
        with self.assertRaises(RuntimeError):
            self.accounting.archive(self.reference, self.old, "agent", "id", "2026-10-09")
        self.archive_reference().set.assert_called_once()

    def test_already_archived_invalid_and_empty_days_are_skipped(self):
        for document in (
            {**self.old, "usageArchivedDate": "2026-10-08"},
            {**self.old, "usageDate": "invalid"},
            {**self.old, "usage": {}},
            {**self.old, "usageDate": "2026-10-09"},
        ):
            self.accounting.archive(self.reference, document, "agent", "id", "2026-10-09")
        self.db.collection.assert_not_called()

    def test_current_usage_preserves_existing_numeric_filtering(self):
        document = {"usageDate": "2026-10-09",
                    "usage": {"positive": 2.9, "zero": 0, "negative": -1, "text": "2"}}
        self.assertEqual(_current_usage(document, "2026-10-09"), {"positive": 2, "zero": 0})
        self.assertEqual(_current_usage(document, "2026-10-08"), {})

    def test_daily_rows_combine_archived_entities_and_current_day(self):
        entities = [
            SimpleNamespace(to_dict=lambda: {"kind": "agent", "usage": {"heartbeats": 3}}),
            SimpleNamespace(to_dict=lambda: {"kind": "app", "usage": {"remoteSnapshotReads": 2}}),
            SimpleNamespace(to_dict=lambda: {"kind": "app", "usage": {"ignored": -1, "text": "3"}}),
        ]
        self.db.collection.return_value.document.return_value.collection.return_value.stream.return_value = entities
        rows = self.accounting.daily(self.now, 2, "2026-10-09", {"heartbeats": 1}, 1, 1)
        self.assertEqual(rows[0], {
            "date": "2026-10-09", "agents": 1, "apps": 1,
            "totals": {"heartbeats": 1}, "complete": False,
        })
        self.assertEqual(rows[1], {
            "date": "2026-10-08", "agents": 1, "apps": 2,
            "totals": {"heartbeats": 3, "remoteSnapshotReads": 2}, "complete": True,
        })

    def test_day_limits_and_no_mutation_of_current_totals(self):
        self.db.collection.return_value.document.return_value.collection.return_value.stream.return_value = []
        totals = {"heartbeats": 1}
        self.assertEqual(len(self.accounting.daily(self.now, 0, "2026-10-09", totals, 1, 1)), 1)
        self.assertEqual(len(self.accounting.daily(self.now, 100, "2026-10-09", totals, 1, 1)), 31)
        self.assertEqual(totals, {"heartbeats": 1})

    def test_cloud_image_copies_both_components(self):
        source = Path("push_relay/Dockerfile").read_text()
        self.assertIn("COPY usage_accounting.py .", source)
        self.assertIn("COPY usage_dashboard.py .", source)
