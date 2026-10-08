"""UTC-day usage accounting with caller-supplied database operations."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable


class UsageAccounting:
    def __init__(
        self, *, db: Any, server_timestamp: Any,
        increment: Callable[[int], Any], now: Callable[[], datetime],
    ) -> None:
        self._db = db
        self._server_timestamp = server_timestamp
        self._increment = increment
        self._now = now

    def update(
        self,
        reference: Any,
        existing: dict[str, object],
        entity_kind: str,
        entity_id: str,
        **increments: int,
    ) -> dict[str, object]:
        """Build counters that reuse an endpoint's existing Firestore write."""
        today = self._now().date().isoformat()
        self.archive(reference, existing, entity_kind, entity_id, today)
        clean = {
            key: max(0, int(value))
            for key, value in increments.items()
            if int(value) > 0
        }
        if existing.get("usageDate") != today:
            return {"usageDate": today, "usage": clean}
        return {
            f"usage.{key}": self._increment(value)
            for key, value in clean.items()
        }
    
    
    def archive(
        self,
        reference: Any,
        document: dict[str, object],
        entity_kind: str,
        entity_id: str,
        today: str,
    ) -> None:
        """Persist the completed UTC-day counters once per entity and date."""
        usage_date = document.get("usageDate")
        if not isinstance(usage_date, str) or usage_date == today:
            return
        if document.get("usageArchivedDate") == usage_date:
            return
        try:
            datetime.strptime(usage_date, "%Y-%m-%d")
        except ValueError:
            return
        usage = _current_usage(document, usage_date)
        if not usage:
            return
        identity = _usage_identity(entity_kind, entity_id)
        archive_ref = (
            self._db.collection("usageDaily")
            .document(usage_date)
            .collection("entities")
            .document(identity)
        )
        archive_ref.set(
            {
                "kind": entity_kind,
                "usage": usage,
                "archivedAt": self._server_timestamp,
                "expiresAt": self._now() + timedelta(days=90),
            }
        )
        reference.update({"usageArchivedDate": usage_date})
    
    
    def daily(
        self,
        now: datetime,
        days: int,
        today: str,
        today_totals: dict[str, int],
        today_agents: int,
        today_apps: int,
    ) -> list[dict[str, object]]:
        rollups: list[dict[str, object]] = []
        for offset in range(max(1, min(days, 31))):
            usage_date = (now.date() - timedelta(days=offset)).isoformat()
            if usage_date == today:
                rollups.append({
                    "date": usage_date,
                    "agents": today_agents,
                    "apps": today_apps,
                    "totals": dict(sorted(today_totals.items())),
                    "complete": False,
                })
                continue
            totals: dict[str, int] = defaultdict(int)
            agent_count = 0
            app_count = 0
            entities = (
                self._db.collection("usageDaily")
                .document(usage_date)
                .collection("entities")
                .stream()
            )
            for entity_snapshot in entities:
                entity = entity_snapshot.to_dict() or {}
                if entity.get("kind") == "agent":
                    agent_count += 1
                elif entity.get("kind") == "app":
                    app_count += 1
                usage = entity.get("usage")
                if not isinstance(usage, dict):
                    continue
                for key, value in usage.items():
                    if isinstance(value, (int, float)) and value >= 0:
                        totals[str(key)] += int(value)
            rollups.append({
                "date": usage_date,
                "agents": agent_count,
                "apps": app_count,
                "totals": dict(sorted(totals.items())),
                "complete": True,
            })
        return rollups


def _current_usage(document: dict[str, object], today: str) -> dict[str, int]:
    if document.get("usageDate") != today:
        return {}
    usage = document.get("usage")
    if not isinstance(usage, dict):
        return {}
    return {
        str(key): max(0, int(value))
        for key, value in usage.items()
        if isinstance(value, (int, float)) and value >= 0
    }


def _usage_identity(entity_kind: str, entity_id: str) -> str:
    return hashlib.sha256(
        f"{entity_kind}:{entity_id}".encode("utf-8")
    ).hexdigest()[:24]




