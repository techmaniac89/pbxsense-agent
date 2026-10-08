from __future__ import annotations

import json
import secrets
from typing import Any, Callable

ENDPOINT_INCIDENT_MINIMUM_PHONES = 2
ENDPOINT_SINGLE_NOTIFICATION_DELAY_SECONDS = 10
ENDPOINT_SHARED_CAUSE_MINIMUM_PHONES = 3
ENDPOINT_INCIDENT_CORRELATION_SECONDS = 15
ENDPOINT_INCIDENT_UPDATE_SECONDS = 30
ENDPOINT_INCIDENT_RECOVERY_SECONDS = 15
ENDPOINT_INCIDENT_COOLDOWN_SECONDS = 120
_FEED_ONLY_LIVE_CALL_KINDS = {
    "call_active",
    "pbx_live_calls_activity",
    "trunk_active",
    "trunk_call_active",
}


class RelayNotificationPolicy:
    """Signal eligibility, deduplication and endpoint incident state transitions.

    The caller owns the shared state lock. Emission is synchronous so its durable
    queue write occurs at the same policy transition as before extraction.
    """

    def __init__(
        self, state: dict[str, Any], emit: Callable[[dict[str, object]], None],
    ) -> None:
        self._state = state
        self._emit = emit

    def observe(
        self, signals: list[dict[str, object]], *,
        total_phones: int = 0, connection_ok: bool = True, now: float,
    ) -> None:
        suppressed_signal_ids = self._correlate_endpoint_incident(
            signals,
            total_phones=max(0, total_phones),
            connection_ok=connection_ok,
            now=now,
        )
        active_ids = {
            str(signal.get("id", ""))
            for signal in signals
            if signal.get("state") == "active"
        }
        delivered = self._state.setdefault("delivered", {})
        if not connection_ok:
            # A connector outage can temporarily remove every endpoint
            # Signal. Preserve dedupe state so reconnecting does not replay
            # a fleet of per-phone notifications.
            active_ids.update(
                signal_id
                for signal_id in delivered
                if signal_id.startswith("sig_endpoint_")
            )
        for signal_id in list(delivered):
            if signal_id not in active_ids:
                delivered.pop(signal_id, None)

        for signal in signals:
            signal_id = str(signal.get("id", ""))
            if signal_id in suppressed_signal_ids or not _should_relay(signal):
                continue
            fingerprint = _fingerprint(signal)
            if delivered.get(signal_id) == fingerprint:
                continue
            delivered[signal_id] = fingerprint
            self._queue_event(
                event_id=str(signal.get("notificationId", signal_id)),
                signal_id=signal_id,
                title=str(signal.get("title", "PBXSense Signal")),
                body=str(signal.get("body", signal.get("timeLabel", ""))),
                category=str(signal.get("category", "activity")),
                importance=str(signal.get("importance", "feed")),
            )

    def _correlate_endpoint_incident(
        self,
        signals: list[dict[str, object]],
        *,
        total_phones: int,
        connection_ok: bool,
        now: float,
    ) -> set[str]:
        endpoint_signals = {
            str(signal.get("id", "")): signal
            for signal in signals
            if signal.get("state") == "active"
            and signal.get("kind") == "endpoint_unavailable"
        }
        recovery_ids = {
            str(signal.get("id", ""))
            for signal in signals
            if signal.get("state") == "active"
            and signal.get("kind") == "pbx_phone_recovered_activity"
        }
        if not connection_ok:
            return {*endpoint_signals, *recovery_ids}

        incident = self._state.get("endpoint_incident")
        if not isinstance(incident, dict):
            incident = None
        first_seen = self._state.setdefault("endpoint_outage_first_seen", {})
        if not isinstance(first_seen, dict):
            first_seen = {}
            self._state["endpoint_outage_first_seen"] = first_seen

        suppressed: set[str] = set()
        current_ids = set(endpoint_signals)
        vanished_unnotified = False
        delivered = self._state.setdefault("delivered", {})
        for signal_id in list(first_seen):
            if signal_id not in current_ids:
                if signal_id not in delivered:
                    vanished_unnotified = True
                first_seen.pop(signal_id, None)
        if vanished_unnotified:
            self._state["endpoint_recovery_suppression_until"] = (
                now + ENDPOINT_INCIDENT_RECOVERY_SECONDS
            )
        for signal_id in current_ids:
            first_seen.setdefault(signal_id, now)
        if now < float(self._state.get("endpoint_recovery_suppression_until", 0.0)):
            suppressed.update(recovery_ids)

        if total_phones <= 0 and incident is None:
            return suppressed
        if 0 < total_phones < ENDPOINT_INCIDENT_MINIMUM_PHONES and incident is None:
            suppressed.update(
                signal_id
                for signal_id in current_ids
                if now - float(first_seen.get(signal_id, now))
                < ENDPOINT_SINGLE_NOTIFICATION_DELAY_SECONDS
            )
            return suppressed

        if incident is None and current_ids:
            ordered = sorted(
                current_ids,
                key=lambda signal_id: float(first_seen.get(signal_id, now)),
            )
            oldest_at = float(first_seen.get(ordered[0], now))
            candidate_ids = {
                signal_id
                for signal_id in ordered
                if float(first_seen.get(signal_id, now)) - oldest_at
                < ENDPOINT_INCIDENT_CORRELATION_SECONDS
            }
            if len(candidate_ids) >= ENDPOINT_SHARED_CAUSE_MINIMUM_PHONES:
                incident = self._start_endpoint_incident(
                    candidate_ids, total_phones=total_phones, now=now
                )
            elif now - oldest_at < ENDPOINT_INCIDENT_CORRELATION_SECONDS:
                suppressed.update(candidate_ids)
                return suppressed
            elif len(candidate_ids) >= ENDPOINT_INCIDENT_MINIMUM_PHONES:
                incident = self._start_endpoint_incident(
                    candidate_ids, total_phones=total_phones, now=now
                )
            else:
                suppressed.update(
                    signal_id
                    for signal_id in current_ids
                    if now - float(first_seen.get(signal_id, now))
                    < ENDPOINT_INCIDENT_CORRELATION_SECONDS
                )
                return suppressed

        if incident is None:
            return suppressed

        phase = str(incident.get("phase", "active"))
        affected = {str(value) for value in incident.get("affected", [])}
        started_at = float(incident.get("started_at", now))
        affected.update(
            signal_id
            for signal_id in current_ids
            if float(first_seen.get(signal_id, now)) >= started_at
        )
        incident["affected"] = sorted(affected)
        current_affected = current_ids & affected

        if phase == "cooldown":
            recovered_at = float(incident.get("recovered_at", 0.0))
            if (
                not current_affected
                and now - recovered_at >= ENDPOINT_INCIDENT_COOLDOWN_SECONDS
            ):
                self._state.pop("endpoint_incident", None)
                return suppressed
            if current_affected:
                incident["phase"] = "active"
                incident["recovery_started_at"] = 0.0
                incident["recovered_at"] = 0.0
                incident["last_notification_at"] = 0.0
                phase = "active"

        suppressed.update(current_affected)
        suppressed.update(recovery_ids)
        incident["current"] = sorted(current_affected)

        if current_affected:
            incident["recovery_started_at"] = 0.0
            last_notified = {
                str(value) for value in incident.get("last_notified_current", [])
            }
            last_at = float(incident.get("last_notification_at", 0.0))
            if current_affected != last_notified and (
                last_at == 0.0 or now - last_at >= ENDPOINT_INCIDENT_UPDATE_SECONDS
            ):
                self._queue_endpoint_incident_event(
                    incident,
                    current_count=len(current_affected),
                    total_phones=total_phones,
                    recovered=False,
                )
                incident["last_notification_at"] = now
                incident["last_notified_current"] = sorted(current_affected)
            return suppressed

        recovery_started_at = float(incident.get("recovery_started_at", 0.0))
        if recovery_started_at == 0.0:
            incident["recovery_started_at"] = now
        elif (
            phase == "active"
            and now - recovery_started_at >= ENDPOINT_INCIDENT_RECOVERY_SECONDS
        ):
            self._queue_endpoint_incident_event(
                incident,
                current_count=0,
                total_phones=total_phones,
                recovered=True,
            )
            incident["phase"] = "cooldown"
            incident["recovered_at"] = now
            incident["last_notification_at"] = now
            incident["last_notified_current"] = []
        return suppressed

    def _start_endpoint_incident(
        self,
        affected_ids: set[str],
        *,
        total_phones: int,
        now: float,
    ) -> dict[str, object]:
        incident: dict[str, object] = {
            "episode": secrets.token_urlsafe(10),
            "phase": "active",
            "affected": sorted(affected_ids),
            "current": sorted(affected_ids),
            "started_at": now,
            "last_notification_at": 0.0,
            "last_notified_current": [],
            "recovery_started_at": 0.0,
            "recovered_at": 0.0,
            "revision": 0,
            "peak_count": len(affected_ids),
            "total_phones": total_phones,
        }
        self._state["endpoint_incident"] = incident
        return incident

    def _queue_endpoint_incident_event(
        self,
        incident: dict[str, object],
        *,
        current_count: int,
        total_phones: int,
        recovered: bool,
    ) -> None:
        revision = int(incident.get("revision", 0)) + 1
        incident["revision"] = revision
        incident["peak_count"] = max(
            int(incident.get("peak_count", 0)), current_count
        )
        episode = str(incident["episode"])
        peak_count = int(incident.get("peak_count", 0))
        initial_update = revision == 1
        if recovered:
            title = "Phone availability restored"
            body = f"All {peak_count} affected phones are reachable again."
            category = "activity"
            importance = "feed"
        elif current_count >= ENDPOINT_SHARED_CAUSE_MINIMUM_PHONES:
            title = f"{current_count} phones look unavailable"
            scope = (
                f" out of {total_phones} monitored phones"
                if total_phones > 0
                else ""
            )
            body = (
                "A shared network, power, or PBX interruption may be affecting "
                f"{current_count}{scope}."
            )
            category = "health"
            importance = "attention"
        elif current_count == 2:
            title = (
                "2 phones look unavailable"
                if initial_update
                else "2 phones still look unavailable"
            )
            body = (
                "PBXSense confirmed that both phones are currently unreachable."
                if initial_update
                else "The other affected phones recovered."
            )
            category = "health"
            importance = "attention"
        else:
            title = "1 phone still looks unavailable"
            body = "The other affected phones recovered."
            category = "health"
            importance = "attention"
        self._queue_event(
            event_id=f"endpoint_incident_{episode}_{revision}",
            signal_id="sig_endpoint_availability_incident",
            title=title,
            body=body,
            category=category,
            importance=importance,
            notification_tag="pbxsense_endpoint_availability_incident",
        )

    def _queue_event(
        self,
        *,
        event_id: str,
        signal_id: str,
        title: str,
        body: str,
        category: str,
        importance: str,
        notification_tag: str = "",
    ) -> None:
        self._emit(
            {
                "id": event_id,
                "signalId": signal_id,
                "title": title,
                "body": body,
                "category": category,
                "importance": importance,
                **({"notificationTag": notification_tag} if notification_tag else {}),
            },
        )


def _should_relay(signal: dict[str, object]) -> bool:
    if signal.get("state") != "active" or signal.get("category") == "recommendation":
        return False
    if signal.get("kind") in _FEED_ONLY_LIVE_CALL_KINDS:
        return False
    if signal.get("category") == "activity":
        return True
    return signal.get("importance") in {"attention", "important"}


def _fingerprint(signal: dict[str, object]) -> str:
    semantic_signal = dict(signal)
    # An Agent restart can reconstruct a new occurrence token for an outage
    # that never ended. Keep durable relay dedupe based on signal semantics;
    # the token is used only after the stable signal leaves and reappears.
    semantic_signal.pop("notificationId", None)
    return json.dumps(semantic_signal, sort_keys=True, separators=(",", ":"), default=str)



