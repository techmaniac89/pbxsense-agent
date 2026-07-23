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
    ) -> None:
        self._url = _validated_relay_url(url)
        self._path = Path(identity_path)
        self._display_name = display_name
        self._timeout_seconds = timeout_seconds
        self._enrollment_ticket = enrollment_ticket.strip()
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
        }

    def activation(self) -> dict[str, str]:
        """Return a short-lived QR capability for the protected Agent page."""
        with self._lock:
            try:
                return self._activation_locked()
            except (OSError, TypeError, ValueError):
                # Cloud enrollment is optional for local pairing. A stale
                # identity file, read-only volume, missing crypto package, or
                # temporary relay failure must never turn /pair into HTTP 500.
                return {}

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
                except OSError:
                    # Keep the still-valid QR during a temporary relay outage.
                    return {"id": str(activation["id"]), "secret": str(activation["secret"])}
            else:
                self._state.pop("activation", None)
                self._save()
        private = self._private_key()
        public_key = _encode(private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ))
        try:
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
        except OSError:
            return {}
        activation = {
            "id": str(response.get("activationId", "")),
            "secret": str(response.get("activationSecret", "")),
            "expires_at": _iso_timestamp(str(response.get("expiresAt", ""))),
        }
        if not activation["id"] or not activation["secret"]:
            return {}
        self._state["activation"] = activation
        self._save()
        return {"id": str(activation["id"]), "secret": str(activation["secret"])}

    def register_device(
        self,
        *,
        fcm_token: str,
        meaningful: bool,
        activity: bool,
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
            enrolled = self._ensure_enrolled()
            if enrolled:
                self._flush()
            accepted = enrolled and not any(
                item.get("kind") == "devices"
                and str(item.get("payload", {}).get("fcmToken", "")) == token
                for item in self._state.get("outbox", [])
            )
            if accepted and relay_device_id.strip() and encryption_public_key.strip():
                self._secure_devices_refreshed_at = 0.0
            delivered = accepted and self._device_is_listed(
                token, relay_device_id.strip()
            )
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
                return True
            except OSError:
                return False

    def observe(self, signals: list[dict[str, object]]) -> None:
        with self._lock:
            if not self._ensure_enrolled():
                return
            active_ids = {
                str(signal.get("id", ""))
                for signal in signals
                if signal.get("state") == "active"
            }
            delivered = self._state.setdefault("delivered", {})
            for signal_id in list(delivered):
                if signal_id not in active_ids:
                    delivered.pop(signal_id, None)

            for signal in signals:
                if not _should_relay(signal):
                    continue
                signal_id = str(signal["id"])
                fingerprint = _fingerprint(signal)
                if delivered.get(signal_id) == fingerprint:
                    continue
                delivered[signal_id] = fingerprint
                self._queue(
                    "events",
                    {
                        "id": str(signal.get("notificationId", signal_id)),
                        "signalId": signal_id,
                        "title": str(signal.get("title", "PBXSense Signal")),
                        "body": str(signal.get("body", signal.get("timeLabel", ""))),
                        "category": str(signal.get("category", "activity")),
                        "importance": str(signal.get("importance", "feed")),
                    },
                )
            self._save()
            self._flush()

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
        replay_protected: bool = False,
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
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                decoded = json.loads(response.read().decode("utf-8"))
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
            return decoded if isinstance(decoded, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {"outbox": [], "delivered": {}}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self._path.parent.chmod(0o700)
        temporary = self._path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._state, sort_keys=True), encoding="utf-8")
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
