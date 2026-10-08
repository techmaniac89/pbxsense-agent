import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from push_relay.cost_model import RelayCostModel
from push_relay.usage_report import UsageReporter


class UsageReportTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
        self.db = MagicMock()
        self.agents = MagicMock()
        self.operations = MagicMock()
        self.db.collection.side_effect = {
            "agents": self.agents, "relayOperations": self.operations,
        }.__getitem__
        self.agents.limit.return_value.stream.return_value = []
        self.operations.document.return_value.get.return_value = SimpleNamespace(exists=False)
        self.archive = MagicMock()
        self.daily = MagicMock(return_value=[])
        self.policy = MagicMock(return_value={"agentLossSeconds": 90})
        self.reporter = UsageReporter(
            db=self.db, archive=self.archive, daily=self.daily,
            cost=RelayCostModel(), policy=self.policy, now=lambda: self.now,
            agent_loss_seconds=90, max_events_per_hour=60,
        )

    def snapshot(self, identifier, row, devices=()):
        reference = MagicMock()
        reference.collection.return_value.stream.return_value = devices
        return SimpleNamespace(id=identifier, reference=reference, to_dict=lambda: row)

    def test_empty_report_keeps_schema_and_query_bound(self):
        report = self.reporter.report()
        self.agents.limit.assert_called_once_with(1000)
        self.assertEqual(report["registeredAgents"], 0)
        self.assertEqual(report["estimatedCostToday"]["total"], 0)
        self.assertIsNone(report["notificationDeliveryPercent"])
        self.assertIsNone(report["averageNotificationLatencyMs"])
        self.assertFalse(report["scheduler"]["healthy"])
        self.assertEqual(report["policy"], {"agentLossSeconds": 90})
        self.assertEqual(report["costModel"]["projectionBasisHours"], 12.0)

    def test_fleet_totals_preferences_retention_and_privacy_fields(self):
        devices = [
            self.snapshot("phone-one", {
                "usageDate": "2026-10-09", "usage": {"remoteSnapshotReads": 2},
                "lastConnectedAt": self.now - timedelta(seconds=120),
                "expiresAt": self.now + timedelta(days=7),
                "secureSnapshotUpdatedAt": self.now,
            }),
            self.snapshot("phone-two", {"expiresAt": self.now - timedelta(seconds=1)}),
        ]
        agent = self.snapshot("private-agent-id", {
            "usageDate": "2026-10-09",
            "usage": {"heartbeats": 10, "notificationAccepted": 3,
                      "notificationFailed": 1, "notificationFcmAttempts": 2,
                      "notificationLatencyMs": 100},
            "lastSeenAt": self.now - timedelta(seconds=90),
            "currentEventQuotaHour": "2026100912", "currentEventQuotaCount": 48,
            "lastFcmLatencyMs": 70,
        }, devices)
        self.agents.limit.return_value.stream.return_value = [agent]
        self.operations.document.return_value.get.return_value = SimpleNamespace(
            exists=True, to_dict=lambda: {
                "lastHeartbeatSweepAt": self.now - timedelta(seconds=180),
                "lastHeartbeatSweepLost": 1,
            },
        )
        report = self.reporter.report(days=3)
        self.assertEqual(report["activeAgents"], 1)
        self.assertEqual(report["registeredApps"], 2)
        self.assertEqual(report["connectedApps"], 1)
        self.assertEqual(report["expiredApps"], 1)
        self.assertEqual(report["appsExpiringSoon"], 1)
        self.assertEqual(report["snapshotCapableApps"], 1)
        self.assertEqual(report["notificationDeliveryPercent"], 75.0)
        self.assertEqual(report["averageNotificationLatencyMs"], 50)
        self.assertEqual(report["quotaWarningAgents"], 1)
        self.assertEqual(report["highestQuotaPercent"], 80)
        self.assertEqual(report["totals"]["remoteSnapshotReads"], 2)
        self.assertTrue(report["scheduler"]["healthy"])
        self.assertEqual(len(self.archive.call_args_list), 3)
        self.assertEqual(report["agents"][0]["agent"],
                         hashlib.sha256(b"private-agent-id").hexdigest()[:12])
        self.assertNotIn("private-agent-id", json.dumps(report))
        self.assertEqual(self.daily.call_args.args[1], 3)

    def test_old_usage_and_old_quota_hour_are_not_counted(self):
        self.agents.limit.return_value.stream.return_value = [self.snapshot("agent", {
            "usageDate": "2026-10-08", "usage": {"heartbeats": 999},
            "currentEventQuotaHour": "2026100911", "currentEventQuotaCount": 60,
            "lastSeenAt": self.now - timedelta(seconds=91),
        })]
        report = self.reporter.report()
        self.assertEqual(report["totals"], {})
        self.assertEqual(report["activeAgents"], 0)
        self.assertEqual(report["highestQuotaPercent"], 0)
        self.archive.assert_called_once()

    def test_projection_uses_one_hour_floor(self):
        self.reporter._now = lambda: self.now.replace(hour=0, minute=1)
        report = self.reporter.report()
        self.assertEqual(report["costModel"]["projectionBasisHours"], 1.0)

    def test_rows_sort_by_workload_and_truncate_at_100(self):
        self.agents.limit.return_value.stream.return_value = [
            self.snapshot(f"agent-{number}", {
                "usageDate": "2026-10-09", "usage": {"heartbeats": number},
            }) for number in range(101)
        ]
        report = self.reporter.report()
        self.assertEqual(report["registeredAgents"], 101)
        self.assertEqual(len(report["agents"]), 100)
        self.assertTrue(report["agentsTruncated"])
        self.assertEqual(report["agents"][0]["usage"]["heartbeats"], 100)

    def test_archive_failure_propagates_without_partial_report(self):
        self.agents.limit.return_value.stream.return_value = [self.snapshot("agent", {})]
        self.archive.side_effect = RuntimeError("archive failed")
        with self.assertRaises(RuntimeError):
            self.reporter.report()
        self.daily.assert_not_called()

    def test_cloud_image_contains_query_and_cost_modules(self):
        dockerfile = Path("push_relay/Dockerfile").read_text()
        self.assertIn("COPY usage_report.py .", dockerfile)
        self.assertIn("COPY cost_model.py .", dockerfile)


class RelayCostModelTests(unittest.TestCase):
    def test_defaults_match_existing_cost_contract(self):
        model = RelayCostModel.from_environment({})
        self.assertEqual(model, RelayCostModel())
        cost = model.estimate({"heartbeats": 10})
        self.assertEqual(cost["requests"], 10)
        self.assertEqual(cost["firestoreReads"], 20)
        self.assertEqual(cost["firestoreWrites"], 20)
        self.assertAlmostEqual(cost["total"],
                               cost["cloudRun"] + cost["firestore"] + cost["egress"])

    def test_environment_bounds_and_invalid_value_fallback(self):
        model = RelayCostModel.from_environment({
            "PBXSENSE_RELAY_COST_CURRENCY": " EUR ",
            "PBXSENSE_RELAY_COST_CLOUD_RUN_REQUEST_USD": "-2",
            "PBXSENSE_RELAY_COST_FIRESTORE_READ_USD": "invalid",
            "PBXSENSE_RELAY_COST_EGRESS_GIB_USD": "1001",
            "PBXSENSE_RELAY_COST_AVERAGE_REQUEST_SECONDS": "0.2",
        })
        self.assertEqual(model.currency, "EUR")
        self.assertEqual(model.cloud_run_request_usd, 0)
        self.assertEqual(model.firestore_read_usd, RelayCostModel().firestore_read_usd)
        self.assertEqual(model.egress_gib_usd, 1000)
        self.assertEqual(model.average_request_seconds, 0.2)
        self.assertEqual(RelayCostModel.from_environment({
            "PBXSENSE_RELAY_COST_CURRENCY": " ",
        }).currency, "USD")

    def test_snapshot_egress_and_notification_delete_formula(self):
        model = RelayCostModel()
        cost = model.estimate({
            "encryptedSnapshotsPublished": 2, "encryptedSnapshotBytes": 2048,
            "remoteSnapshotReads": 3, "notificationAttempts": 2,
            "notificationEligible": 4, "notificationInvalidTokens": 1,
        })
        self.assertEqual(cost["estimatedEgressBytes"], 3072)
        self.assertEqual(cost["firestoreDeletes"], 4)
        self.assertEqual(cost["requests"], 7)
        self.assertEqual(model.estimate({})["total"], 0)
