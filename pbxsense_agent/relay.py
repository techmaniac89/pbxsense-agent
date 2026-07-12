from __future__ import annotations

import base64
import json
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


class AgentRelay:
    """Signs Agent requests and maintains a small durable relay outbox."""

    def __init__(
        self,
        *,
        url: str,
        claim_code: str,
        identity_path: str,
        display_name: str,
        timeout_seconds: float = 5,
    ) -> None:
        self._url = url.rstrip("/")
        self._claim_code = claim_code  # Legacy compatibility; QR activation is preferred.
        self._path = Path(identity_path)
        self._display_name = display_name
        self._timeout_seconds = timeout_seconds
        self._lock = threading.Lock()
        self._state = self._load()

    @property
    def configured(self) -> bool:
        return bool(self._url and self._state.get("agent_id"))

    def status(self) -> dict[str, object]:
        return {
            "configured": bool(self._url),
            "enrolled": bool(self._state.get("agent_id")),
            "agentId": self._state.get("agent_id", ""),
            "queued": len(self._state.get("outbox", [])),
        }

    def activation(self) -> dict[str, str]:
        """Return a short-lived QR capability for the protected Agent page."""
        with self._lock:
            if not self._url or self._state.get("agent_id"):
                return {}
            activation = self._state.get("activation")
            if isinstance(activation, dict) and activation.get("id") and activation.get("secret"):
                return {"id": str(activation["id"]), "secret": str(activation["secret"])}
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
            activation = {"id": str(response.get("activationId", "")), "secret": str(response.get("activationSecret", ""))}
            if not activation["id"] or not activation["secret"]:
                return {}
            self._state["activation"] = activation
            self._save()
            return activation

    def register_device(self, *, fcm_token: str, meaningful: bool, activity: bool) -> dict[str, object]:
        if not fcm_token.strip():
            return {"configured": self.configured, "queued": False}
        with self._lock:
            if not self._ensure_enrolled():
                return {"configured": False, "queued": False}
            self._queue(
                "devices",
                {
                    "fcmToken": fcm_token.strip(),
                    "meaningfulEnabled": meaningful,
                    "activityEnabled": activity,
                    "platform": "android",
                },
            )
            self._flush()
            return {"configured": True, "queued": True}

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
            if response.get("claimed") and response.get("agentId"):
                self._state["agent_id"] = str(response["agentId"])
                self._state.pop("activation", None)
                self._save()
                return True
            return False
        if not self._claim_code:
            return False
        private = self._private_key()
        public_key = _encode(private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ))
        try:
            response = self._request(
                "/v1/agents/enroll",
                {
                    "claimCode": self._claim_code,
                    "publicKey": public_key,
                    "displayName": self._display_name,
                },
                signed=False,
            )
        except OSError:
            return False
        self._state["agent_id"] = str(response["agentId"])
        self._save()
        return True

    def _queue(self, kind: str, payload: dict[str, object]) -> None:
        outbox = self._state.setdefault("outbox", [])
        if kind == "devices":
            outbox[:] = [item for item in outbox if item.get("kind") != "devices"]
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
        temporary = self._path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._state, sort_keys=True), encoding="utf-8")
        temporary.replace(self._path)


def _should_relay(signal: dict[str, object]) -> bool:
    if signal.get("state") != "active" or signal.get("category") == "recommendation":
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
