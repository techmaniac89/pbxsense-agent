from __future__ import annotations

import ast
import hashlib
import html
import hmac
import time
import unittest
from pathlib import Path
from push_relay.cost_model import RelayCostModel
from push_relay.authentication import RelayAuthentication


class RelayDashboardTest(unittest.TestCase):
    def test_admin_cookie_signature_enforces_server_side_expiry(self) -> None:
        source = Path("push_relay/app.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        functions = [
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef)
            and node.name in {"_admin_cookie_value", "_admin_cookie_valid"}
        ]
        namespace = {
            "hashlib": hashlib,
            "hmac": hmac,
            "time": time,
            "_admin_token": "operator-secret",
            "ADMIN_COOKIE_TTL_SECONDS": 8 * 60 * 60,
        }
        exec(compile(ast.Module(functions, type_ignores=[]), "cookie", "exec"), namespace)
        namespace["_relay_auth"] = lambda: RelayAuthentication(
            db=None, server_timestamp=None, already_exists=RuntimeError,
            identifier=lambda value, field: str(value), max_snapshot_bytes=1024,
            admin_token="operator-secret", ticket_secret="", admin_cookie="admin",
            admin_cookie_ttl=8 * 60 * 60, clock=time.time, now=lambda: None,
        )
        cookie = namespace["_admin_cookie_value"](200)

        self.assertTrue(namespace["_admin_cookie_valid"](cookie, 199))
        self.assertFalse(namespace["_admin_cookie_valid"](cookie, 200))
        self.assertFalse(namespace["_admin_cookie_valid"](cookie + "tampered", 199))
        self.assertFalse(namespace["_admin_cookie_valid"]("legacy-signature", 199))

    def test_operations_dashboard_renders_complete_metric_sections(self) -> None:
        source = Path("push_relay/app.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        selected = {"_estimated_relay_cost"}
        functions = [
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name in selected
        ]
        namespace = {
            "html": html,
            "_cost_model": RelayCostModel(),
            "RELAY_VERSION": "test",
            "CLOUD_RUN_REQUEST_USD": 0.0000004,
            "CLOUD_RUN_VCPU_SECOND_USD": 0.000024,
            "CLOUD_RUN_GIB_SECOND_USD": 0.0000025,
            "AVERAGE_REQUEST_SECONDS": 0.05,
            "AVERAGE_REQUEST_VCPU": 1.0,
            "AVERAGE_REQUEST_MEMORY_GIB": 0.5,
            "FIRESTORE_READ_USD": 0.0000003,
            "FIRESTORE_WRITE_USD": 0.0000009,
            "FIRESTORE_DELETE_USD": 0.0000001,
            "EGRESS_GIB_USD": 0.12,
        }
        exec(compile(ast.Module(functions, type_ignores=[]), "dashboard", "exec"), namespace)

        report = {
            "generatedAt": "2026-08-11T12:00:00+00:00",
            "registeredAgents": 2,
            "activeAgents": 1,
            "registeredApps": 3,
            "connectedApps": 2,
            "expiredApps": 1,
            "appsExpiringSoon": 1,
            "snapshotCapableApps": 2,
            "notificationDeliveryPercent": 90.0,
            "averageNotificationLatencyMs": 125,
            "quotaWarningAgents": 1,
            "highestQuotaPercent": 80,
            "workloadOperations": 150,
            "estimatedCostToday": {"total": 0.0123},
            "estimatedCost30Days": 0.369,
            "costModel": {
                "currency": "USD",
                "basis": "Gross estimate.",
                "averageRequestSeconds": 0.05,
                "projectionBasisHours": 12.0,
            },
            "scheduler": {
                "healthy": True,
                "ageSeconds": 60,
                "lastLost": 0,
            },
            "policy": {
                "agentPresenceSeconds": 30,
                "agentLossSeconds": 90,
                "remotePollSeconds": 60,
                "controlExchangeSeconds": 300,
                "maxAppsPerAgent": 10,
                "maxEventsPerAgentHour": 60,
            },
            "totals": {
                "heartbeats": 100,
                "controlExchanges": 10,
                "remoteSnapshotReads": 20,
                "remoteSnapshotUnavailable": 2,
                "encryptedSnapshotsPublished": 5,
                "encryptedSnapshotBytes": 2048,
                "notificationAttempts": 15,
                "notificationAccepted": 9,
                "notificationFailed": 1,
            },
            "daily": [
                {
                    "date": "2026-08-11",
                    "agents": 1,
                    "apps": 2,
                    "complete": False,
                    "totals": {
                        "heartbeats": 100,
                        "notificationAttempts": 15,
                        "notificationAccepted": 9,
                        "notificationFailed": 1,
                    },
                }
            ],
            "agents": [
                {
                    "agent": "abcdef123456",
                    "active": True,
                    "lastSeenSeconds": 20,
                    "registeredApps": 2,
                    "connectedApps": 2,
                    "deliveryPercent": 90.0,
                    "quotaCount": 48,
                    "quotaPercent": 80,
                    "lastFcmLatencyMs": 125,
                    "estimatedCostToday": {"total": 0.01},
                    "estimatedCost30Days": 0.30,
                    "usage": {"heartbeats": 100},
                },
                {
                    "agent": "inactive99999",
                    "active": False,
                    "lastSeenSeconds": 3600,
                    "registeredApps": 1,
                    "connectedApps": 0,
                    "deliveryPercent": None,
                    "quotaCount": 0,
                    "quotaPercent": 0,
                    "lastFcmLatencyMs": None,
                    "estimatedCostToday": {"total": 0},
                    "estimatedCost30Days": 0,
                    "usage": {},
                },
            ],
            "privacy": "Hashed identifiers only.",
        }

        from push_relay.usage_dashboard import _usage_dashboard_page
        rendered = _usage_dashboard_page(
            report, relay_version="test", cost_estimator=namespace["_estimated_relay_cost"],
        )
        cards = rendered.split('<section class="cards">', 1)[1].split("</section>", 1)[0]

        self.assertIn("Operations dashboard", rendered)
        self.assertEqual(cards.count("<article>"), 8)
        self.assertIn("Push acceptance", rendered)
        self.assertIn("Heartbeat scheduler", rendered)
        self.assertIn("Seven-day workload movement", rendered)
        self.assertIn("150</strong> protocol operations today", rendered)
        self.assertNotIn("Workload proxy</span>", rendered)
        self.assertIn("Capacity and retention", rendered)
        self.assertIn("Estimated Relay cost", rendered)
        self.assertIn("Est. 30 days", rendered)
        self.assertIn("Cost model", rendered)
        self.assertIn("abcdef123456", rendered)
        self.assertNotIn("inactive99999", rendered)
        self.assertNotIn("currently inactive", rendered)
        self.assertIn("Metric notes", rendered)
        self.assertNotIn("FCM token", rendered)
        report["privacy"] = "<script>unsafe()</script>"
        escaped = _usage_dashboard_page(
            report, relay_version="<test>", cost_estimator=namespace["_estimated_relay_cost"],
        )
        self.assertIn("&lt;script&gt;unsafe()&lt;/script&gt;", escaped)
        self.assertIn("&lt;test&gt;", escaped)
        self.assertNotIn("<script>unsafe()</script>", escaped)

    def test_usage_identity_is_stable_and_separates_agents_from_apps(self) -> None:
        source = Path("push_relay/usage_accounting.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        function = next(
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == "_usage_identity"
        )
        namespace = {"hashlib": hashlib}
        exec(compile(ast.Module([function], type_ignores=[]), "identity", "exec"), namespace)

        self.assertEqual(namespace["_usage_identity"]("agent", "abc"), namespace["_usage_identity"]("agent", "abc"))
        self.assertNotEqual(namespace["_usage_identity"]("agent", "abc"), namespace["_usage_identity"]("app", "abc"))

    def test_cost_estimate_scales_with_measured_agent_workload(self) -> None:
        source = Path("push_relay/app.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        function = next(
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_estimated_relay_cost"
        )
        namespace = {
            "CLOUD_RUN_REQUEST_USD": 0.0000004,
            "_cost_model": RelayCostModel(),
            "CLOUD_RUN_VCPU_SECOND_USD": 0.000024,
            "CLOUD_RUN_GIB_SECOND_USD": 0.0000025,
            "AVERAGE_REQUEST_SECONDS": 0.05,
            "AVERAGE_REQUEST_VCPU": 1.0,
            "AVERAGE_REQUEST_MEMORY_GIB": 0.5,
            "FIRESTORE_READ_USD": 0.0000003,
            "FIRESTORE_WRITE_USD": 0.0000009,
            "FIRESTORE_DELETE_USD": 0.0000001,
            "EGRESS_GIB_USD": 0.12,
        }
        exec(
            compile(ast.Module([function], type_ignores=[]), "cost", "exec"),
            namespace,
        )

        quiet = namespace["_estimated_relay_cost"]({"heartbeats": 10})
        busy = namespace["_estimated_relay_cost"]({"heartbeats": 100})

        self.assertGreater(quiet["total"], 0)
        self.assertAlmostEqual(busy["total"], quiet["total"] * 10)


if __name__ == "__main__":
    unittest.main()
