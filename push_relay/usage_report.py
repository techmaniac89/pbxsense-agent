"""Usage-report query coordination with injected services and a UTC clock."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

try:
    from .usage_accounting import _current_usage
    from .cost_model import RelayCostModel
except ImportError:
    from usage_accounting import _current_usage
    from cost_model import RelayCostModel


class UsageReporter:
    def __init__(
        self, *, db: Any, archive: Callable[..., None], daily: Callable[..., list],
        cost: RelayCostModel, policy: Callable[[], dict], now: Callable[[], datetime],
        agent_loss_seconds: int, max_events_per_hour: int,
    ) -> None:
        self._db = db
        self._archive = archive
        self._daily = daily
        self._cost = cost
        self._policy = policy
        self._now = now
        self._agent_loss_seconds = agent_loss_seconds
        self._max_events_per_hour = max_events_per_hour

    def report(self, days: int = 7) -> dict[str, object]:
        now = self._now()
        today = now.date().isoformat()
        elapsed_day_hours = max(
            1.0,
            (now - datetime.combine(now.date(), datetime.min.time(), timezone.utc)).total_seconds()
            / 3600,
        )
        monthly_projection_factor = 30 * 24 / elapsed_day_hours
        active_cutoff = now - timedelta(seconds=self._agent_loss_seconds)
        connected_cutoff = now - timedelta(seconds=120)
        totals: dict[str, int] = defaultdict(int)
        agent_rows: list[dict[str, object]] = []
        registered_apps = 0
        connected_apps = 0
        active_agents = 0
        usage_agents = 0
        usage_apps = 0
        expired_apps = 0
        apps_expiring_soon = 0
        snapshot_capable_apps = 0
        quota_warning_agents = 0
        highest_quota_percent = 0
        agents = list(self._db.collection("agents").limit(1000).stream())
        for snapshot in agents:
            agent = snapshot.to_dict() or {}
            self._archive(snapshot.reference, agent, "agent", snapshot.id, today)
            usage = _current_usage(agent, today)
            agent_usage: dict[str, int] = dict(usage)
            if usage:
                usage_agents += 1
            for key, value in usage.items():
                totals[key] += value
            last_seen_at = agent.get("lastSeenAt")
            active = isinstance(last_seen_at, datetime) and last_seen_at >= active_cutoff
            last_seen_seconds = (
                max(0, int((now - last_seen_at).total_seconds()))
                if isinstance(last_seen_at, datetime)
                else None
            )
            if active:
                active_agents += 1
            apps = 0
            connected = 0
            for device_snapshot in snapshot.reference.collection("devices").stream():
                device = device_snapshot.to_dict() or {}
                self._archive(
                    device_snapshot.reference,
                    device,
                    "app",
                    f"{snapshot.id}/{device_snapshot.id}",
                    today,
                )
                apps += 1
                expires_at = device.get("expiresAt")
                if isinstance(expires_at, datetime):
                    if expires_at < now:
                        expired_apps += 1
                    elif expires_at <= now + timedelta(days=7):
                        apps_expiring_soon += 1
                if isinstance(device.get("secureSnapshotUpdatedAt"), datetime):
                    snapshot_capable_apps += 1
                device_usage = _current_usage(device, today)
                if device_usage:
                    usage_apps += 1
                for key, value in device_usage.items():
                    totals[key] += value
                    agent_usage[key] = agent_usage.get(key, 0) + value
                last_connected_at = device.get("lastConnectedAt")
                if (
                    isinstance(last_connected_at, datetime)
                    and last_connected_at >= connected_cutoff
                ):
                    connected += 1
            registered_apps += apps
            connected_apps += connected
            quota_count = (
                int(agent.get("currentEventQuotaCount", 0))
                if agent.get("currentEventQuotaHour") == f"{now:%Y%m%d%H}"
                else 0
            )
            quota_percent = min(
                100,
                round(100 * quota_count / max(1, self._max_events_per_hour)),
            )
            highest_quota_percent = max(highest_quota_percent, quota_percent)
            if quota_percent >= 80:
                quota_warning_agents += 1
            accepted = int(agent_usage.get("notificationAccepted", 0))
            failed = int(agent_usage.get("notificationFailed", 0))
            delivery_total = accepted + failed
            estimated_cost = self._cost.estimate(agent_usage)
            agent_rows.append({
                "agent": hashlib.sha256(snapshot.id.encode("utf-8")).hexdigest()[:12],
                "active": active,
                "lastSeenSeconds": last_seen_seconds,
                "registeredApps": apps,
                "connectedApps": connected,
                "quotaCount": quota_count,
                "quotaPercent": quota_percent,
                "deliveryPercent": (
                    round(100 * accepted / delivery_total, 1)
                    if delivery_total else None
                ),
                "lastFcmLatencyMs": agent.get("lastFcmLatencyMs"),
                "estimatedCostToday": estimated_cost,
                "estimatedCost30Days": estimated_cost["total"] * monthly_projection_factor,
                "usage": agent_usage,
            })
        agent_rows.sort(
            key=lambda row: sum(int(value) for value in row["usage"].values()),
            reverse=True,
        )
        daily = self._daily(
            now,
            days,
            today,
            totals,
            usage_agents,
            usage_apps,
        )
        notification_accepted = totals.get("notificationAccepted", 0)
        notification_failed = totals.get("notificationFailed", 0)
        notification_total = notification_accepted + notification_failed
        notification_attempts = totals.get("notificationFcmAttempts", 0)
        fleet_cost = self._cost.estimate(totals)
        workload_operations = sum(
            totals.get(key, 0)
            for key in (
                "heartbeats",
                "controlExchanges",
                "remoteSnapshotReads",
                "encryptedSnapshotsPublished",
                "notificationAttempts",
            )
        )
        operations_snapshot = self._db.collection("relayOperations").document("current").get()
        operations = operations_snapshot.to_dict() if operations_snapshot.exists else {}
        last_sweep_at = operations.get("lastHeartbeatSweepAt") if operations else None
        sweep_age_seconds = (
            max(0, int((now - last_sweep_at).total_seconds()))
            if isinstance(last_sweep_at, datetime)
            else None
        )
        return {
            "generatedAt": now.isoformat(),
            "usageDate": today,
            "registeredAgents": len(agents),
            "activeAgents": active_agents,
            "registeredApps": registered_apps,
            "connectedApps": connected_apps,
            "expiredApps": expired_apps,
            "appsExpiringSoon": apps_expiring_soon,
            "snapshotCapableApps": snapshot_capable_apps,
            "notificationDeliveryPercent": (
                round(100 * notification_accepted / notification_total, 1)
                if notification_total else None
            ),
            "averageNotificationLatencyMs": (
                round(totals.get("notificationLatencyMs", 0) / notification_attempts)
                if notification_attempts else None
            ),
            "quotaWarningAgents": quota_warning_agents,
            "highestQuotaPercent": highest_quota_percent,
            "workloadOperations": workload_operations,
            "estimatedCostToday": fleet_cost,
            "estimatedCost30Days": fleet_cost["total"] * monthly_projection_factor,
            "costModel": {
                "currency": self._cost.currency,
                "basis": "Gross reference list price before free tier, discounts, taxes, storage, and shared overhead.",
                "averageRequestSeconds": self._cost.average_request_seconds,
                "projectionBasisHours": round(elapsed_day_hours, 1),
                "ratesConfigurable": True,
            },
            "scheduler": {
                "lastSweepAt": last_sweep_at.isoformat() if isinstance(last_sweep_at, datetime) else None,
                "ageSeconds": sweep_age_seconds,
                "healthy": sweep_age_seconds is not None and sweep_age_seconds <= 180,
                "lastLost": int((operations or {}).get("lastHeartbeatSweepLost", 0)),
            },
            "totals": dict(sorted(totals.items())),
            "daily": daily,
            "policy": self._policy(),
            "agents": agent_rows[:100],
            "agentsTruncated": len(agent_rows) > 100,
            "privacy": "Agent identifiers are one-way hashes; PBX and call content is excluded.",
        }

