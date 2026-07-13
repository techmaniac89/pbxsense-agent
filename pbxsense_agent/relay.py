from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # Existing Agents remain usable before the optional relay is installed.
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]


# A 15-second cadence paired with the relay's 60-second loss timeout tolerates
# one missed request without turning a brief network hiccup into a false alarm.
PRESENCE_HEARTBEAT_INTERVAL_SECONDS = 15
_FEED_ONLY_LIVE_CALL_KINDS = {
    "call_active",
    "pbx_live_calls_activity",
    "trunk_active",
    "trunk_call_active",
}


class AgentRelay:
    """Signs Agent requests and maintains a small durable relay outbox."""

    def __init__(
        self,
        *,
        url: str,
        identity_path: str,
        display_name: str,
        timeout_seconds: float = 5,
    ) -> None:
        self._url = url.rstrip("/")
        self._path = Path(identity_path)
        self._display_name = display_name
        self._timeout_seconds = timeout_seconds
        self._lock = threading.Lock()
        self._state = self._load()
        self._protect_storage()
        self._last_heartbeat_at = 0.0

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
        if not self._url or self._state.get("agent_id"):
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
                        return {}
                    if status.get("expired"):
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
            response = self._request(
                "/v1/activations",
                {"publicKey": public_key, "displayName": self._display_name},
                signed=False,
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
            delivered = accepted and self._device_is_listed(token)
            # Pairing claims the relay activation just before the app sends its
            # FCM token. Keep that token durably until enrollment completes
            # instead of losing the registration in this short race window.
            return {
                "configured": enrolled,
                "queued": not delivered,
                "delivered": delivered,
            }

    def _device_is_listed(self, fcm_token: str) -> bool:
        """Confirm the relay can read back the registration it accepted."""
        expected_id = hashlib.sha256(fcm_token.encode("utf-8")).hexdigest()[:12]
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

    def remove_device(self, *, fcm_token: str) -> bool:
        with self._lock:
            if not fcm_token.strip() or not self._ensure_enrolled():
                return False
            try:
                self._request(
                    f"/v1/agents/{self._state['agent_id']}/devices/revoke",
                    {"fcmToken": fcm_token.strip()},
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
                        "id": signal_id,
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
            except OSError:
                break
            outbox.pop(0)
            if item.get("kind") == "devices":
                self._state["device_registration_revision"] = int(
                    self._state.get("device_registration_revision", 0)
                ) + 1
            self._save()

    def _request(self, path: str, payload: dict[str, object], *, signed: bool) -> dict[str, Any]:
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if signed:
            timestamp = str(int(time.time()))
            message = f"{timestamp}\n{path}\n".encode("utf-8") + raw
            signature = _encode(self._private_key().sign(message))
            headers.update({"X-PBXSense-Timestamp": timestamp, "X-PBXSense-Signature": signature})
        request = urllib.request.Request(f"{self._url}{path}", data=raw, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
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
    return json.dumps(signal, sort_keys=True, separators=(",", ":"), default=str)


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
