"""Privacy-safe notification outcome reporting with injected persistence."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable


class NotificationUsageRecorder:
    def __init__(
        self, *, db: Any, server_timestamp: Any,
        usage_update: Callable[..., dict[str, Any]],
        now: Callable[[], datetime],
    ) -> None:
        self._db = db
        self._server_timestamp = server_timestamp
        self._usage_update = usage_update
        self._now = now

    def record(
        self,
        agent_id: str,
        agent: dict[str, object],
        *,
        eligible: int,
        accepted: int,
        failed: int,
        invalid: int,
        latency_ms: int,
        no_recipients: int = 0,
        transport_errors: int = 0,
        quota_count: int | None = None,
    ) -> None:
        """Persist privacy-safe FCM outcomes for operator reliability monitoring."""
        agent_ref = self._db.collection("agents").document(agent_id)
        quota_fields = (
            {
                "currentEventQuotaHour": self._now().strftime("%Y%m%d%H"),
                "currentEventQuotaCount": max(0, quota_count),
            }
            if quota_count is not None
            else {}
        )
        agent_ref.update({
            "lastFcmAttemptAt": self._server_timestamp,
            "lastFcmLatencyMs": max(0, latency_ms),
            "lastFcmAccepted": max(0, accepted),
            "lastFcmFailed": max(0, failed),
            **quota_fields,
            **self._usage_update(
                agent_ref,
                agent,
                "agent",
                agent_id,
                notificationAttempts=1,
                notificationFcmAttempts=1 if eligible > 0 else 0,
                notificationEligible=max(0, eligible),
                notificationAccepted=max(0, accepted),
                notificationFailed=max(0, failed),
                notificationInvalidTokens=max(0, invalid),
                notificationLatencyMs=max(0, latency_ms),
                notificationNoRecipients=max(0, no_recipients),
                notificationTransportErrors=max(0, transport_errors),
            ),
        })

