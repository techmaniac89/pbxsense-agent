"""Notification sending coordination; database ownership stays with the caller."""
from __future__ import annotations

import hashlib
import time
from datetime import datetime
from typing import Any, Callable

from fastapi import HTTPException


class NotificationDelivery:
    """Select recipients and checkpoint outcomes using caller-supplied services."""

    def __init__(
        self, *, messaging: Any,
        checkpoint: Callable[[set[str], bool], None],
        cleanup: Callable[..., int], record_usage: Callable[..., None],
        log: Callable[..., None], safe_identifier: Callable[[str], str],
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._messaging = messaging
        self._checkpoint = checkpoint
        self._cleanup = cleanup
        self._record_usage = record_usage
        self._log = log
        self._safe_identifier = safe_identifier
        self._monotonic = monotonic

    def deliver(
        self, *, agent_id: str, agent: dict[str, Any],
        devices: list[dict[str, Any]], completed: set[str], quota_count: int,
        event_id: str, signal_id: str, title: str, body: str,
        category: str, importance: str, notification_tag: str, now: datetime,
    ) -> dict[str, Any]:
        eligible_devices = _unique_devices_by_token([
            device
            for device in devices
            if _device_wants_event(device, category, importance, signal_id)
            and device.get("expiresAt", now) >= now
            and device.get("fcmToken")
            and _recipient_digest(str(device["fcmToken"])) not in completed
        ])
        tokens = [str(device["fcmToken"]) for device in eligible_devices]
        if not tokens:
            self._checkpoint(completed, True)
            self._record_usage(
                agent_id,
                agent,
                eligible=0,
                accepted=0,
                failed=0,
                invalid=0,
                latency_ms=0,
                no_recipients=1,
                quota_count=quota_count,
            )
            return {"status": "accepted", "sent": 0}
    
        message = self._messaging.MulticastMessage(
            tokens=tokens,
            notification=self._messaging.Notification(title=title, body=body),
            data={
                "signalId": signal_id,
                "notificationId": event_id,
                "siteId": agent["siteId"],
                "agentId": agent_id,
                "category": category,
                "importance": importance,
            },
            android=self._messaging.AndroidConfig(
                priority="high",
                notification=self._messaging.AndroidNotification(tag=notification_tag),
            ),
        )
        started = self._monotonic()
        try:
            response = self._messaging.send_each_for_multicast(message)
        except Exception:
            self._record_usage(
                agent_id,
                agent,
                eligible=len(tokens),
                accepted=0,
                failed=len(tokens),
                invalid=0,
                latency_ms=max(0, round((self._monotonic() - started) * 1000)),
                transport_errors=1,
                quota_count=quota_count,
            )
            self._checkpoint(completed, False)
            raise
        retryable = len(response.responses) != len(eligible_devices)
        for device, outcome in zip(eligible_devices, response.responses):
            if outcome.success or not _retryable_fcm_failure(outcome.exception):
                completed.add(_recipient_digest(str(device["fcmToken"])))
            else:
                retryable = True
        # Persist delivery results before usage reporting, which may itself fail.
        self._checkpoint(completed, not retryable)
        invalid_tokens = self._cleanup(agent_id, eligible_devices, response.responses)
        latency_ms = max(0, round((self._monotonic() - started) * 1000))
        self._record_usage(
            agent_id,
            agent,
            eligible=len(eligible_devices),
            accepted=response.success_count,
            failed=response.failure_count,
            invalid=invalid_tokens,
            latency_ms=latency_ms,
            quota_count=quota_count,
        )
        self._log(
            "fcm_signal agent_id=%s eligible=%d accepted=%d failed=%d invalid_removed=%d",
            self._safe_identifier(agent_id),
            len(eligible_devices),
            response.success_count,
            response.failure_count,
            invalid_tokens,
        )
        if retryable:
            raise HTTPException(status_code=503, detail="Some notification recipients require retry")
        return {"status": "accepted", "sent": response.success_count, "failed": response.failure_count}
    

class AgentStatusDelivery:
    """Agent lost/restored sends, separate from event leases and quotas."""

    def __init__(
        self, *, messaging: Any, cleanup: Callable[..., int],
        record_usage: Callable[..., None], log: Callable[..., None],
        safe_identifier: Callable[[str], str],
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._messaging = messaging
        self._cleanup = cleanup
        self._record_usage = record_usage
        self._log = log
        self._safe_identifier = safe_identifier
        self._monotonic = monotonic

    def deliver(
        self, *, agent_id: str, agent: dict[str, Any] | None,
        devices: list[dict[str, Any]], title: str, body: str, now: datetime,
    ) -> None:
        eligible_devices = _unique_devices_by_token([
            device
            for device in devices
            if device.get("meaningfulEnabled", True)
            and device.get("expiresAt", now) >= now
            and device.get("fcmToken")
        ])
        tokens = [
            str(device.get("fcmToken", ""))
            for device in eligible_devices
        ]
        if not tokens:
            self._record_usage(
                agent_id,
                agent or {},
                eligible=0,
                accepted=0,
                failed=0,
                invalid=0,
                latency_ms=0,
                no_recipients=1,
            )
            self._log(
                "fcm_agent_status agent_id=%s eligible=0 accepted=0 failed=0 invalid_removed=0",
                self._safe_identifier(agent_id),
            )
            return
        started = self._monotonic()
        try:
            response = self._messaging.send_each_for_multicast(
                self._messaging.MulticastMessage(
                    tokens=tokens,
                    notification=self._messaging.Notification(title=title, body=body),
                    data={"kind": "agent_connection", "agentId": agent_id},
                    android=self._messaging.AndroidConfig(priority="high"),
                )
            )
        except Exception:
            self._record_usage(
                agent_id,
                agent or {},
                eligible=len(tokens),
                accepted=0,
                failed=len(tokens),
                invalid=0,
                latency_ms=max(0, round((self._monotonic() - started) * 1000)),
                transport_errors=1,
            )
            raise
        invalid_tokens = self._cleanup(agent_id, eligible_devices, response.responses)
        self._record_usage(
            agent_id,
            agent or {},
            eligible=len(eligible_devices),
            accepted=response.success_count,
            failed=response.failure_count,
            invalid=invalid_tokens,
            latency_ms=max(0, round((self._monotonic() - started) * 1000)),
        )
        self._log(
            "fcm_agent_status agent_id=%s eligible=%d accepted=%d failed=%d invalid_removed=%d",
            self._safe_identifier(agent_id),
            len(eligible_devices),
            response.success_count,
            response.failure_count,
            invalid_tokens,
        )



def _recipient_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _retryable_fcm_failure(error: Any) -> bool:
    # Unknown failures are retryable; only known permanent errors are terminal.
    return str(getattr(error, "code", "")).lower() not in {
        "invalid-argument", "not-found", "unregistered", "sender-id-mismatch",
    }


def _device_wants_event(
    device: dict[str, Any], category: str, importance: str, signal_id: str = ""
) -> bool:
    if not device.get("meaningfulEnabled", True):
        return False
    muted = device.get("mutedSignalIds", [])
    if isinstance(muted, list) and signal_id in muted:
        return False
    if category == "activity":
        return bool(device.get("activityEnabled", True))
    return importance in {"attention", "important"}


def _unique_devices_by_token(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Never send the same multicast message twice to one FCM token."""
    unique: dict[str, dict[str, Any]] = {}
    for device in devices:
        token = str(device.get("fcmToken", ""))
        if token:
            unique[token] = device
    return list(unique.values())



