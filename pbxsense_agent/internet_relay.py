from __future__ import annotations

import re
import secrets
import time
from typing import Any, Callable


_COMMAND_ID = re.compile(r"^[A-Za-z0-9_-]{1,96}$")
SECURE_RELAY_PROTOCOL_VERSION = 1
CONTROL_EXCHANGE_INTERVAL_SECONDS = 300


class SecureInternetRelay:
    """Outbound-only, capability-scoped relay session.

    Control messages are deliberately capability-scoped. PBX snapshots travel
    separately as per-device, end-to-end encrypted envelopes.
    """

    def __init__(
        self,
        *,
        enabled: bool,
        exchange: Callable[[dict[str, object]], dict[str, Any]],
        agent_version: str,
        snapshot_provider: Callable[[], dict[str, object]] | None = None,
        snapshot_publisher: Callable[[dict[str, object]], int] | None = None,
    ) -> None:
        self._enabled = enabled
        self._exchange = exchange
        self._agent_version = agent_version
        self._snapshot_provider = snapshot_provider
        self._snapshot_publisher = snapshot_publisher
        self._session_id = secrets.token_urlsafe(18)
        self._pending_responses: list[dict[str, object]] = []
        self._connected = False
        self._last_exchange_at = 0.0
        self._last_error = ""
        self._control_exchange_seconds = CONTROL_EXCHANGE_INTERVAL_SECONDS

    def status(self) -> dict[str, object]:
        return {
            "enabled": self._enabled,
            "connected": self._connected,
            "protocolVersion": SECURE_RELAY_PROTOCOL_VERSION,
            "sessionId": self._session_id if self._enabled else "",
            "lastExchangeAt": self._last_exchange_at,
            "lastError": self._last_error,
            "capabilities": ["ping", "encryptedSnapshotV1"],
            "controlExchangeSeconds": self._control_exchange_seconds,
        }

    def poll(self) -> None:
        if not self._enabled:
            return
        try:
            now = time.time()
            if (
                not self._last_exchange_at
                or now - self._last_exchange_at >= self._control_exchange_seconds
                or self._pending_responses
            ):
                payload: dict[str, object] = {
                    "protocolVersion": SECURE_RELAY_PROTOCOL_VERSION,
                    "sessionId": self._session_id,
                    "agentVersion": self._agent_version,
                    "capabilities": ["ping", "encryptedSnapshotV1"],
                    "responses": self._pending_responses[:20],
                }
                result = self._exchange(payload)
                self._pending_responses = []
                self._accept_commands(result.get("commands", []))
                self._accept_policy(result.get("policy"))
                self._last_exchange_at = now
            if self._snapshot_provider is not None and self._snapshot_publisher is not None:
                self._snapshot_publisher(self._snapshot_provider())
            self._connected = True
            self._last_error = ""
        except (OSError, TypeError, ValueError) as exc:
            self._connected = False
            self._last_error = str(exc)[:240]

    def _accept_policy(self, raw_policy: object) -> None:
        if not isinstance(raw_policy, dict):
            return
        seconds = _integer(raw_policy.get("controlExchangeSeconds"))
        if 60 <= seconds <= 900:
            self._control_exchange_seconds = seconds

    def _accept_commands(self, raw_commands: object) -> None:
        if not isinstance(raw_commands, list):
            raise ValueError("Secure relay commands must be a list")
        if len(raw_commands) > 20:
            raise ValueError("Secure relay returned too many commands")
        now = int(time.time())
        for raw in raw_commands:
            if not isinstance(raw, dict):
                continue
            command_id = str(raw.get("id", ""))
            command_type = str(raw.get("type", ""))
            expires_at = _integer(raw.get("expiresAt"))
            if not _COMMAND_ID.fullmatch(command_id) or expires_at < now:
                continue
            if command_type == "ping":
                self._pending_responses.append(
                    {"id": command_id, "status": "ok", "kind": "pong"}
                )
            else:
                self._pending_responses.append(
                    {"id": command_id, "status": "unsupported"}
                )


def _integer(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
