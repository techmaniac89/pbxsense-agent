from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:  # Existing Agents remain usable before the optional relay is installed.
    InvalidTag = ValueError  # type: ignore[assignment,misc]
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]
    X25519PrivateKey = X25519PublicKey = AESGCM = HKDF = SHA256 = None  # type: ignore[assignment,misc]


# A 30-second cadence paired with the relay's 90-second loss timeout tolerates
# two missed requests without turning a brief network hiccup into a false alarm.
PRESENCE_HEARTBEAT_INTERVAL_SECONDS = 30
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


class RelayRequestError(OSError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status

    @property
    def retryable(self) -> bool:
        return self.status in {408, 425, 429} or self.status >= 500


def _validated_relay_url(value: str) -> str:
    url = value.rstrip("/")
    if not url:
        return ""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return url
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return url
    raise ValueError("PBXSENSE_RELAY_URL must use HTTPS (HTTP is allowed only for localhost)")


class AgentRelay:
    """Signs Agent requests and maintains a small durable relay outbox."""

    def __init__(
        self,
        *,
        url: str,
        identity_path: str,
        display_name: str,
        timeout_seconds: float = 5,
        enrollment_ticket: str = "",
        storage_secret: str = "",
        legacy_storage_secrets: tuple[str, ...] = (),
    ) -> None:
        self._url = _validated_relay_url(url)
        self._path = Path(identity_path)
        self._display_name = display_name
        self._timeout_seconds = timeout_seconds
        self._enrollment_ticket = enrollment_ticket.strip()
        self._storage_secret = storage_secret.strip()
        self._storage_secrets = tuple(
            dict.fromkeys(
                secret.strip()
                for secret in (self._storage_secret, *legacy_storage_secrets)
                if secret.strip()
            )
        )
        self._lock = threading.Lock()
        self._state = self._load()
        self._protect_storage()
        self._last_heartbeat_at = 0.0
        self._secure_devices: list[dict[str, object]] = []
        self._secure_devices_refreshed_at = 0.0

    @property
    def configured(self) -> bool:
        return bool(self._url and self._state.get("agent_id"))

    def status(self) -> dict[str, object]:
        return {
            "configured": bool(self._url),
            "enrolled": bool(self._state.get("agent_id")),
            "agentId": self._state.get("agent_id", ""),
            "queued": len(self._state.get("outbox", [])),
            "deviceRegistrationAttemptRevision": int(
                self._state.get("device_registration_attempt_revision", 0)
            ),
            "deviceRegistrationRevision": int(
                self._state.get("device_registration_revision", 0)
            ),
            "rejectedOutboxItems": len(self._state.get("rejected_outbox", [])),
            "lastOutboxError": str(self._state.get("last_outbox_error", "")),
            "lastActivationError": str(
                self._state.get("last_activation_error", "")
            ),
        }

    def activation(self) -> dict[str, str]:
        """Return a short-lived QR capability for the protected Agent page."""
        with self._lock:
            return self._activation_with_tracking_locked()

    def _activation_with_tracking_locked(self) -> dict[str, str]:
        try:
            activation = self._activation_locked()
        except (OSError, TypeError, ValueError) as exc:
            # Cloud enrollment is optional for local pairing, but the protected
            # admin page must retain the real reason it fell back to LAN.
            self._state["last_activation_error"] = str(exc)[:240]
            self._save()
            return {}
        if self._state.pop("last_activation_error", None) is not None:
            self._save()
        return activation

    def _activation_locked(self) -> dict[str, str]:
        if not self._url:
            return {}
        activation = self._state.get("activation")
        if isinstance(activation, dict) and activation.get("id") and activation.get("secret"):
            if _stored_timestamp(activation.get("expires_at")) > time.time() + 30:
                try:
                    status = self._request(
                        f"/v1/activations/{activation['id']}/status",
                        {"activationSecret": activation["secret"]},
                        signed=False,
                    )
                    if self._adopt_claimed_activation(status):
                        # The claimed activation connected one app. Continue
                        # below and issue a fresh capability for the next app,
                        # using this Agent's same long-lived signing identity.
                        pass
                    elif status.get("expired"):
                        self._state.pop("activation", None)
                        self._save()
                    else:
                        return {"id": str(activation["id"]), "secret": str(activation["secret"])}
                except RelayRequestError as exc:
                    if exc.status in {401, 404}:
                        # The relay no longer recognizes this capability. Never
                        # serve a potentially consumed QR; replace it below.
                        self._state.pop("activation", None)
                        self._save()
                    else:
                        raise
                except OSError:
                    # A capability whose state cannot be confirmed may already
                    # be consumed. Fall back locally instead of reusing it.
                    raise
            else:
                self._state.pop("activation", None)
                self._save()
        private = self._private_key()
        public_key = _encode(private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ))
        activation_payload: dict[str, object] = {
            "publicKey": public_key,
            "displayName": self._display_name,
        }
        if self._enrollment_ticket and not self._state.get("agent_id"):
            activation_payload["enrollmentTicket"] = self._enrollment_ticket
        response = self._request(
            "/v1/activations",
            activation_payload,
            signed=True,
        )
        activation = {
            "id": str(response.get("activationId", "")),
            "secret": str(response.get("activationSecret", "")),
            "expires_at": _iso_timestamp(str(response.get("expiresAt", ""))),
        }
        if not activation["id"] or not activation["secret"]:
            raise ValueError("Relay activation response is incomplete")
        self._state["activation"] = activation
        self._save()
        return {"id": str(activation["id"]), "secret": str(activation["secret"])}

    def register_device(
        self,
        *,
        fcm_token: str,
        meaningful: bool,
        activity: bool,
        muted_signal_ids: list[str] | None = None,
        platform: str = "android",
        app_version: str = "",
        device_model: str = "",
        device_name: str = "",
        os_version: str = "",
        relay_device_id: str = "",
        encryption_public_key: str = "",
    ) -> dict[str, object]:
        if not fcm_token.strip():
            return {"configured": self.configured, "queued": False, "delivered": False}
        with self._lock:
            token = fcm_token.strip()
            self._state["device_registration_attempt_revision"] = int(
                self._state.get("device_registration_attempt_revision", 0)
            ) + 1
            self._queue(
                "devices",
                {
                    "fcmToken": token,
                    "meaningfulEnabled": meaningful,
                    "activityEnabled": activity,
                    **(
                        {"mutedSignalIds": list(muted_signal_ids)}
                        if muted_signal_ids else {}
                    ),
                    "platform": platform.strip() or "android",
                    "appVersion": app_version.strip(),
                    "deviceModel": device_model.strip(),
                    "deviceName": device_name.strip(),
                    "osVersion": os_version.strip(),
                    **({"relayDeviceId": relay_device_id.strip()}
                       if relay_device_id.strip() else {}),
                    **({"encryptionPublicKey": encryption_public_key.strip()}
                       if encryption_public_key.strip() else {}),
                },
            )
            initial_registration_revision = int(
                self._state.get("device_registration_revision", 0)
            )
            enrolled = self._ensure_enrolled()
            if enrolled:
                self._flush()
            accepted = (
                enrolled
                and int(self._state.get("device_registration_revision", 0))
                > initial_registration_revision
                and not any(
                    item.get("kind") == "devices"
                    and str(item.get("payload", {}).get("fcmToken", "")) == token
                    for item in self._state.get("outbox", [])
                )
            )
            if accepted and relay_device_id.strip() and encryption_public_key.strip():
                self._secure_devices_refreshed_at = 0.0
            delivered = accepted and self._device_is_listed(
                token, relay_device_id.strip()
            )
            if accepted:
                # Prepare the next short-lived capability while the successful
                # pairing request still has a healthy relay connection. This
                # keeps "Add another app" ready instead of making the browser
                # wait for a replacement activation after the previous QR was
                # consumed.
                self._activation_with_tracking_locked()
            # Pairing claims the relay activation just before the app sends its
            # FCM token. Keep that token durably until enrollment completes
            # instead of losing the registration in this short race window.
            return {
                "configured": enrolled,
                "queued": not delivered,
                "delivered": delivered,
            }

    def _device_is_listed(self, fcm_token: str, relay_device_id: str = "") -> bool:
        """Confirm the relay can read back the registration it accepted."""
        expected_id = relay_device_id or hashlib.sha256(
            fcm_token.encode("utf-8")
        ).hexdigest()[:12]
        try:
            response = self._request(
                f"/v1/agents/{self._state['agent_id']}/devices/list",
                {},
                signed=True,
            )
        except (KeyError, OSError):
            return False
        devices = response.get("devices", [])
        return isinstance(devices, list) and any(
            isinstance(device, dict) and str(device.get("id", "")) == expected_id
            for device in devices
        )

    def devices(self) -> dict[str, object]:
        """Return relay-sanitized summaries for apps paired with this Agent."""
        with self._lock:
            if not self._ensure_enrolled():
                return {
                    "available": False,
                    "devices": [],
                    "state": "notEnrolled",
                    "error": "Relay enrollment is not ready.",
                }
            try:
                response = self._request(
                    f"/v1/agents/{self._state['agent_id']}/devices/list",
                    {},
                    signed=True,
                )
            except OSError:
                return {
                    "available": False,
                    "devices": [],
                    "state": "unavailable",
                    "error": "The push relay is unavailable.",
                }
            devices = response.get("devices", [])
            return {
                "available": True,
                "devices": devices if isinstance(devices, list) else [],
            }

    def remove_device(self, *, fcm_token: str, relay_device_id: str = "") -> bool:
        with self._lock:
            if not (fcm_token.strip() or relay_device_id.strip()) or not self._ensure_enrolled():
                return False
            try:
                self._request(
                    f"/v1/agents/{self._state['agent_id']}/devices/revoke",
                    {
                        "fcmToken": fcm_token.strip(),
                        **({"relayDeviceId": relay_device_id.strip()}
                           if relay_device_id.strip() else {}),
                    },
                    signed=True,
                )
                self._secure_devices_refreshed_at = 0.0
                # Prepare the next short-lived capability before the browser
                # opens "Add another app". If the Relay is temporarily
                # unavailable, the admin page records the exact reason it has
                # to offer LAN pairing.
                self._activation_with_tracking_locked()
                return True
            except OSError:
                return False

    def observe(
        self,
        signals: list[dict[str, object]],
        *,
        total_phones: int = 0,
        connection_ok: bool = True,
        observed_at: float | None = None,
    ) -> None:
        with self._lock:
            if not self._ensure_enrolled():
                return
            now = time.time() if observed_at is None else observed_at
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
            self._save()
            self._flush()

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
        self._queue(
            "events",
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

    def heartbeat(self) -> None:
        with self._lock:
            if (
                not self._ensure_enrolled()
                or time.monotonic() - self._last_heartbeat_at < PRESENCE_HEARTBEAT_INTERVAL_SECONDS
            ):
                return
            try:
                self._request(
                    f"/v1/agents/{self._state['agent_id']}/heartbeat",
                    {},
                    signed=True,
                )
                self._last_heartbeat_at = time.monotonic()
            except OSError:
                pass

    def secure_exchange(self, payload: dict[str, object]) -> dict[str, Any]:
        """Exchange an opaque, capability-scoped secure-relay protocol frame."""
        with self._lock:
            if not self._ensure_enrolled():
                raise OSError("Relay enrollment is not ready")
            return self._request(
                f"/v1/agents/{self._state['agent_id']}/secure/exchange",
                payload,
                signed=True,
                replay_protected=True,
            )

    def publish_secure_snapshot(self, snapshot: dict[str, object]) -> int:
        with self._lock:
            if not self._ensure_enrolled():
                raise OSError("Relay enrollment is not ready")
            projected = _secure_snapshot_projection(snapshot)
            raw = json.dumps(projected, separators=(",", ":"), sort_keys=True).encode("utf-8")
            if (
                not self._secure_devices_refreshed_at
                or time.monotonic() - self._secure_devices_refreshed_at >= 300
            ):
                response = self._request(
                    f"/v1/agents/{self._state['agent_id']}/devices/list",
                    {}, signed=True,
                )
                devices = response.get("devices", [])
                if not isinstance(devices, list):
                    return 0
                self._secure_devices = [
                    device for device in devices if isinstance(device, dict)
                ]
                self._secure_devices_refreshed_at = time.monotonic()
            devices = self._secure_devices
            recipients = sorted(
                f"{device.get('id', '')}:{device.get('encryptionPublicKey', '')}"
                for device in devices
                if isinstance(device, dict) and device.get("encryptionPublicKey")
            )
            fingerprint = hashlib.sha256(
                raw + json.dumps(recipients, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if self._state.get("secure_snapshot_fingerprint") == fingerprint:
                return 0
            sequence = int(self._state.get("secure_snapshot_sequence", 0)) + 1
            envelopes = [
                _encrypt_snapshot_for_device(
                    raw, str(self._state["agent_id"]), device, sequence
                )
                for device in devices
                if isinstance(device, dict) and device.get("encryptionPublicKey")
            ]
            if not envelopes:
                return 0
            result = self._request(
                f"/v1/agents/{self._state['agent_id']}/secure/snapshots",
                {"protocolVersion": 1, "envelopes": envelopes},
                signed=True, replay_protected=True,
            )
            stored = int(result.get("stored", 0))
            if stored:
                self._state["secure_snapshot_sequence"] = sequence
                self._state["secure_snapshot_fingerprint"] = fingerprint
                self._save()
            return stored

    def _ensure_enrolled(self) -> bool:
        if not self._url:
            return False
        if self._state.get("agent_id"):
            return True
        activation = self._state.get("activation")
        if isinstance(activation, dict) and activation.get("id") and activation.get("secret"):
            try:
                response = self._request(
                    f"/v1/activations/{activation['id']}/status",
                    {"activationSecret": activation["secret"]},
                    signed=False,
                )
            except OSError:
                return False
            if self._adopt_claimed_activation(response):
                return True
            if response.get("expired"):
                self._state.pop("activation", None)
                self._save()
            return False
        return False

    def _adopt_claimed_activation(self, response: dict[str, Any]) -> bool:
        if not response.get("claimed") or not response.get("agentId"):
            return False
        self._state["agent_id"] = str(response["agentId"])
        self._state.pop("activation", None)
        self._save()
        return True

    def _queue(self, kind: str, payload: dict[str, object]) -> None:
        outbox = self._state.setdefault("outbox", [])
        if kind == "devices":
            token = str(payload.get("fcmToken", ""))
            outbox[:] = [
                item
                for item in outbox
                if item.get("kind") != "devices"
                or str(item.get("payload", {}).get("fcmToken", "")) != token
            ]
        outbox.append({"kind": kind, "payload": payload})
        self._save()

    def _flush(self) -> None:
        outbox = self._state.setdefault("outbox", [])
        while outbox:
            item = outbox[0]
            try:
                self._request(
                    f"/v1/agents/{self._state['agent_id']}/{item['kind']}",
                    item["payload"],
                    signed=True,
                )
            except RelayRequestError as exc:
                if exc.retryable:
                    break
                outbox.pop(0)
                rejected = self._state.setdefault("rejected_outbox", [])
                rejected.append({
                    "kind": str(item.get("kind", "unknown")),
                    "status": exc.status,
                    "at": int(time.time()),
                })
                rejected[:] = rejected[-20:]
                self._state["last_outbox_error"] = str(exc)[:240]
                self._save()
                continue
            except OSError:
                break
            outbox.pop(0)
            if item.get("kind") == "devices":
                self._state["device_registration_revision"] = int(
                    self._state.get("device_registration_revision", 0)
                ) + 1
            self._save()

    def _request(
        self,
        path: str,
        payload: dict[str, object],
        *,
        signed: bool,
        replay_protected: bool = True,
    ) -> dict[str, Any]:
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if signed:
            timestamp = str(int(time.time()))
            message = f"{timestamp}\n{path}\n".encode("utf-8") + raw
            signature = _encode(self._private_key().sign(message))
            headers.update({"X-PBXSense-Timestamp": timestamp, "X-PBXSense-Signature": signature})
            if replay_protected:
                nonce = secrets.token_urlsafe(18)
                digest = hashlib.sha256(raw).hexdigest()
                v2_message = f"{timestamp}\n{nonce}\nPOST\n{path}\n{digest}".encode("utf-8")
                headers.update({
                    "X-PBXSense-Nonce": nonce,
                    "X-PBXSense-Signature-V2": _encode(
                        self._private_key().sign(v2_message)
                    ),
                })
        request = urllib.request.Request(f"{self._url}{path}", data=raw, headers=headers, method="POST")
        try:
            # __init__ accepts only HTTPS, plus explicit loopback HTTP for development.
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:  # nosec B310
                response_body = response.read(5 * 1024 * 1024 + 1)
                if len(response_body) > 5 * 1024 * 1024:
                    raise OSError("Relay response exceeds the 5 MiB safety limit")
                decoded = json.loads(response_body.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:200]
            except OSError:
                detail = ""
            message = f"Relay returned HTTP {exc.code}"
            if detail:
                message += f": {detail}"
            raise RelayRequestError(exc.code, message) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise OSError(str(exc)) from exc
        return decoded if isinstance(decoded, dict) else {}

    def _private_key(self) -> Ed25519PrivateKey:
        if Ed25519PrivateKey is None or serialization is None:
            raise OSError(
                "Cloud push needs the cryptography package. Reinstall the Agent release to enable it."
            )
        encoded = self._state.get("private_key")
        if encoded:
            return Ed25519PrivateKey.from_private_bytes(_decode(str(encoded)))
        private = Ed25519PrivateKey.generate()
        self._state["private_key"] = _encode(private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ))
        self._save()
        return private

    def _load(self) -> dict[str, Any]:
        try:
            decoded = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(decoded, dict):
                return {"outbox": [], "delivered": {}}
            if decoded.get("format") != "pbxsense-relay-state-v1":
                # Existing installations are migrated on the next save.
                return decoded
            return self._decrypt_state(decoded)
        except (OSError, json.JSONDecodeError):
            return {"outbox": [], "delivered": {}}

    def _decrypt_state(self, envelope: dict[str, Any]) -> dict[str, Any]:
        if AESGCM is None or not self._storage_secrets:
            raise RuntimeError(
                "The encrypted relay identity needs PBXSENSE_RELAY_STATE_KEY "
                "or the Agent token used when it was created"
            )
        try:
            nonce = _decode(str(envelope["nonce"]))
            ciphertext = _decode(str(envelope["ciphertext"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("The encrypted relay identity is malformed") from exc
        for secret in self._storage_secrets:
            try:
                plaintext = AESGCM(_relay_state_key(secret)).decrypt(
                    nonce, ciphertext, b"pbxsense-relay-state-v1"
                )
                decoded = json.loads(plaintext.decode("utf-8"))
                if isinstance(decoded, dict):
                    return decoded
            except (InvalidTag, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                continue
        raise RuntimeError(
            "The relay identity could not be decrypted; restore its state key "
            "instead of creating a new identity"
        )

    def _save(self) -> None:
        if AESGCM is None or not self._storage_secret:
            raise RuntimeError(
                "PBXSENSE_RELAY_STATE_KEY or PBXSENSE_AGENT_TOKEN is required "
                "to protect relay identity state"
            )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self._path.parent.chmod(0o700)
        temporary = self._path.with_suffix(".tmp")
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(_relay_state_key(self._storage_secret)).encrypt(
            nonce,
            json.dumps(self._state, sort_keys=True).encode("utf-8"),
            b"pbxsense-relay-state-v1",
        )
        envelope = {
            "format": "pbxsense-relay-state-v1",
            "nonce": _encode(nonce),
            "ciphertext": _encode(ciphertext),
        }
        temporary.write_text(json.dumps(envelope, sort_keys=True), encoding="utf-8")
        if os.name != "nt":
            temporary.chmod(0o600)
        temporary.replace(self._path)
        if os.name != "nt":
            self._path.chmod(0o600)

    def _protect_storage(self) -> None:
        if os.name == "nt":
            return
        try:
            if self._path.parent.exists():
                self._path.parent.chmod(0o700)
            if self._path.exists():
                self._path.chmod(0o600)
        except OSError:
            # A later save will retry; read-only installations still start.
            pass


def _relay_state_key(secret: str) -> bytes:
    return hashlib.sha256(
        b"pbxsense-relay-state-v1\0" + secret.encode("utf-8")
    ).digest()


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


def _secure_snapshot_projection(snapshot: dict[str, object]) -> dict[str, object]:
    projected = json.loads(json.dumps(snapshot, default=str))
    connection = projected.get("connection")
    if isinstance(connection, dict):
        for key in ("pbxHost", "pbxPort", "pushRelayAgentId"):
            connection.pop(key, None)
        connection["kind"] = "internetRelay"
        connection["label"] = "Connected securely"
    calls = projected.get("calls")
    if isinstance(calls, list):
        for call in calls:
            if isinstance(call, dict):
                call.pop("recording", None)
    relay = projected.get("internetRelay")
    if isinstance(relay, dict):
        projected["internetRelay"] = {
            "enabled": bool(relay.get("enabled")),
            "connected": bool(relay.get("connected")),
            "lastError": str(relay.get("lastError", ""))[:240],
        }
    return projected


def _encrypt_snapshot_for_device(
    plaintext: bytes,
    agent_id: str,
    device: dict[str, object],
    sequence: int,
) -> dict[str, object]:
    if any(value is None for value in (X25519PrivateKey, X25519PublicKey, AESGCM, HKDF, SHA256)):
        raise OSError("Secure Internet Relay needs the cryptography package")
    device_id = str(device.get("id", ""))
    public_key = X25519PublicKey.from_public_bytes(
        _decode(str(device["encryptionPublicKey"]))
    )
    ephemeral = X25519PrivateKey.generate()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = HKDF(algorithm=SHA256(), length=32, salt=salt, info=b"pbxsense-secure-relay-v1").derive(
        ephemeral.exchange(public_key)
    )
    from datetime import datetime, timezone
    created_at = datetime.now(timezone.utc).isoformat()
    aad = (
        f"pbxsense-relay-v1|{agent_id}|{device_id}|{sequence}|{created_at}"
    ).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    ephemeral_public = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "deviceId": device_id,
        "sequence": sequence,
        "createdAt": created_at,
        "ephemeralPublicKey": _encode(ephemeral_public),
        "salt": _encode(salt),
        "nonce": _encode(nonce),
        "ciphertext": _encode(ciphertext),
    }


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _iso_timestamp(value: str) -> float:
    try:
        from datetime import datetime

        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _stored_timestamp(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
