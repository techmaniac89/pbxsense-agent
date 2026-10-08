from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from typing import Any, Callable
from .relay_transport import RelayHttpTransport, RelayRequestError
from .relay_state_store import RelayStateStore
from .relay_notification_policy import RelayNotificationPolicy
from .relay_transport import validated_relay_url as _validated_relay_url

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:  # Existing Agents remain usable before the optional relay is installed.
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]
    X25519PrivateKey = X25519PublicKey = AESGCM = HKDF = SHA256 = None  # type: ignore[assignment,misc]


# A 30-second cadence paired with the relay's 90-second loss timeout tolerates
# two missed requests without turning a brief network hiccup into a false alarm.
PRESENCE_HEARTBEAT_INTERVAL_SECONDS = 30
MAX_RELAY_OUTBOX_ITEMS = 500
MAX_RELAY_OUTBOX_BYTES = 2 * 1024 * 1024
MAX_FLUSH_ITEMS = 10
MAX_FLUSH_SECONDS = 5


def _outbox_bytes(outbox: list[dict[str, object]]) -> int:
    return len(
        json.dumps(outbox, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )


class AgentRelay:
    """Coordinates relay identity, notification policy and durable delivery."""

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
        device_observer: Callable[[list], None] | None = None,
    ) -> None:
        self._url = _validated_relay_url(url)
        self._display_name = display_name
        self._enrollment_ticket = enrollment_ticket.strip()
        self._device_observer = device_observer
        self._store = RelayStateStore(
            identity_path, storage_secret=storage_secret,
            legacy_storage_secrets=legacy_storage_secrets,
        )
        self._lock = threading.Lock()
        self._heartbeat_lock = threading.Lock()
        self._transport = RelayHttpTransport(
            url=self._url, timeout_seconds=timeout_seconds,
            sign=lambda message: self._private_key().sign(message),
        )
        self._state = self._store.load()
        self._store.protect_storage()
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
            "droppedOutboxItems": int(self._state.get("outbox_dropped", 0)),
            "lastOutboxError": str(self._state.get("last_outbox_error", "")),
            "lastActivationError": str(
                self._state.get("last_activation_error", "")
            ),
        }

    def activation(self) -> dict[str, str]:
        """Return a short-lived QR capability for the protected Agent page."""
        with self._lock:
            return self._activation_with_tracking_locked()

    def signing_public_key(self) -> str:
        """Expose the durable Agent identity only through trusted QR pairing."""
        with self._lock:
            public = self._private_key().public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            return _encode(public)

    def _activation_with_tracking_locked(self) -> dict[str, str]:
        try:
            activation = self._activation_locked()
        except (OSError, TypeError, ValueError):
            # Cloud enrollment is optional for local pairing, but the protected
            # admin page must retain the real reason it fell back to LAN.
            self._state["last_activation_error"] = "The relay activation request failed."
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
            if isinstance(devices, list) and self._device_observer:
                self._device_observer(devices)
            return {
                "available": True,
                "devices": devices if isinstance(devices, list) else [],
            }

    def remove_device(self, *, fcm_token: str, relay_device_id: str = "") -> bool:
        with self._lock:
            outbox = self._state.setdefault("outbox", [])
            retained = [item for item in outbox if not (
                item.get("kind") == "devices" and (
                    (fcm_token and item.get("payload", {}).get("fcmToken") == fcm_token)
                    or (relay_device_id and item.get("payload", {}).get("relayDeviceId") == relay_device_id)
                    or (relay_device_id and hashlib.sha256(
                        str(item.get("payload", {}).get("fcmToken", "")).encode()
                    ).hexdigest() in {relay_device_id})
                )
            )]
            if len(retained) != len(outbox):
                self._state["outbox"] = retained
                self._save()
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
    ) -> bool | None:
        with self._lock:
            if not self._url:
                return None
            if not self._ensure_enrolled():
                return False
            now = time.time() if observed_at is None else observed_at
            RelayNotificationPolicy(
                self._state, lambda event: self._queue("events", event),
            ).observe(
                signals, total_phones=total_phones,
                connection_ok=connection_ok, now=now,
            )
            self._save()
            return self._flush()

    def heartbeat(self) -> bool | None:
        # Established identities need no outbox lock. A dedicated connection
        # keeps slow deliveries from delaying presence or sharing HTTP streams.
        with self._heartbeat_lock:
            if not self._url:
                return None
            if (
                not self.configured
                or time.monotonic() - self._last_heartbeat_at < PRESENCE_HEARTBEAT_INTERVAL_SECONDS
            ):
                return False if not self.configured else True
            with self._transport.isolated():
                try:
                    self._request(
                        f"/v1/agents/{self._state['agent_id']}/heartbeat",
                        {},
                        signed=True,
                    )
                    self._last_heartbeat_at = time.monotonic()
                    return True
                except OSError:
                    return False

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
                if self._device_observer:
                    self._device_observer(self._secure_devices)
                self._secure_devices_refreshed_at = time.monotonic()
            devices = self._secure_devices
            recipients = sorted(
                f"{device.get('id', '')}:{device.get('encryptionPublicKey', '')}"
                for device in devices
                if isinstance(device, dict) and device.get("encryptionPublicKey")
            )
            fingerprint = hashlib.sha256(
                raw + json.dumps(recipients, separators=(",", ":")).encode("utf-8")
                + b"|signed-envelope-v1"
            ).hexdigest()
            if self._state.get("secure_snapshot_fingerprint") == fingerprint:
                return 0
            sequence = int(self._state.get("secure_snapshot_sequence", 0)) + 1
            envelopes = [
                _encrypt_snapshot_for_device(
                    raw, str(self._state["agent_id"]), device, sequence,
                    self._private_key(),
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
        elif kind == "events":
            signal_id = str(payload.get("signalId", ""))
            if signal_id:
                outbox[:] = [
                    item
                    for item in outbox
                    if item.get("kind") != "events"
                    or str(item.get("payload", {}).get("signalId", ""))
                    != signal_id
                ]
        outbox.append({"kind": kind, "payload": payload})
        self._trim_outbox(outbox)
        self._save()

    def _trim_outbox(self, outbox: list[dict[str, object]]) -> None:
        dropped = 0
        while len(outbox) > MAX_RELAY_OUTBOX_ITEMS or _outbox_bytes(outbox) > MAX_RELAY_OUTBOX_BYTES:
            event_index = next(
                (index for index, item in enumerate(outbox) if item.get("kind") == "events"),
                0,
            )
            outbox.pop(event_index)
            dropped += 1
        if dropped:
            self._state["outbox_dropped"] = int(
                self._state.get("outbox_dropped", 0)
            ) + dropped
            self._state["last_outbox_error"] = (
                "The oldest queued relay updates were discarded after the durable "
                "outbox reached its safety limit."
            )

    def _flush(self) -> bool:
        outbox = self._state.setdefault("outbox", [])
        started = time.monotonic()
        attempted = 0
        success = True
        while outbox and attempted < MAX_FLUSH_ITEMS and time.monotonic() - started < MAX_FLUSH_SECONDS:
            attempted += 1
            item = outbox[0]
            try:
                self._request(
                    f"/v1/agents/{self._state['agent_id']}/{item['kind']}",
                    item["payload"],
                    signed=True,
                )
            except RelayRequestError as exc:
                success = False
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
                self._state["last_outbox_error"] = (
                    f"The relay rejected a queued item with HTTP {exc.status}."
                )
                self._save()
                continue
            except OSError:
                success = False
                break
            outbox.pop(0)
            if item.get("kind") == "devices":
                self._state["device_registration_revision"] = int(
                    self._state.get("device_registration_revision", 0)
                ) + 1
            self._save()
        return success

    def _request(
        self,
        path: str,
        payload: dict[str, object],
        *,
        signed: bool,
        replay_protected: bool = True,
    ) -> dict[str, Any]:
        return self._transport.request(
            path, payload, signed=signed, replay_protected=replay_protected,
        )


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

    def _save(self) -> None:
        self._store.save(self._state)

def _secure_snapshot_projection(snapshot: dict[str, object]) -> dict[str, object]:
    projected = json.loads(json.dumps(snapshot, default=str))
    connection = projected.get("connection")
    if isinstance(connection, dict):
        for key in ("pbxHost", "pbxPort", "pushRelayAgentId"):
            connection.pop(key, None)
        connection["transport"] = "internetRelay"
        connection["pbxReachable"] = connection.get("kind") != "reconnecting"
        if connection["pbxReachable"]:
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
    signing_key: Ed25519PrivateKey,
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
    envelope = {
        "deviceId": device_id,
        "sequence": sequence,
        "createdAt": created_at,
        "ephemeralPublicKey": _encode(ephemeral_public),
        "salt": _encode(salt),
        "nonce": _encode(nonce),
        "ciphertext": _encode(ciphertext),
    }
    message = "\n".join([
        "pbxsense-relay-envelope-signature-v1", agent_id, device_id,
        str(sequence), created_at, str(envelope["ephemeralPublicKey"]),
        str(envelope["salt"]), str(envelope["nonce"]), str(envelope["ciphertext"]),
    ]).encode("utf-8")
    envelope["signature"] = _encode(signing_key.sign(message))
    return envelope


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
