"""Relay authentication coordination with injected identity and replay storage."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from fastapi import HTTPException, Request
try:
    from .request_auth import verify_agent_signature, verify_secure_agent_signature, verify_activation_signatures
except ImportError:
    from request_auth import verify_agent_signature, verify_secure_agent_signature, verify_activation_signatures


class RelayAuthentication:
    def __init__(
        self, *, db: Any, server_timestamp: Any, already_exists: type[Exception],
        identifier: Callable[[object, str], str], max_snapshot_bytes: int,
        admin_token: str, ticket_secret: str, admin_cookie: str,
        admin_cookie_ttl: int, clock: Callable[[], float], now: Callable[[], datetime],
    ) -> None:
        self._db = db
        self._server_timestamp = server_timestamp
        self._already_exists = already_exists
        self._identifier = identifier
        self._max_snapshot_bytes = max_snapshot_bytes
        self._admin_token = admin_token
        self._ticket_secret = ticket_secret
        self._admin_cookie = admin_cookie
        self._admin_cookie_ttl = admin_cookie_ttl
        self._clock = clock
        self._now = now

    async def authenticate_agent(self,
        agent_id: str,
        request: Request,
        *,
        touch_presence: bool = True,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        agent_id = self._identifier(agent_id, "agentId")
        raw_body = await request.body()
        max_bytes = (
            self._max_snapshot_bytes
            if request.url.path.endswith("/secure/snapshots")
            else 1024 * 1024
        )
        if len(raw_body) > max_bytes:
            raise HTTPException(status_code=413, detail="Request body is too large")
        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="JSON body required") from exc
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON object required")
        agent_snapshot = self._db.collection("agents").document(agent_id).get()
        if not agent_snapshot.exists:
            raise HTTPException(status_code=401, detail="Unknown Agent")
        agent = agent_snapshot.to_dict() or {}
        if agent.get("revoked"):
            raise HTTPException(status_code=401, detail="Agent has been revoked")
        verify_agent_signature(
            agent.get("publicKey", ""), request, raw_body, now=self._clock(),
        )
        await self.require_replay_protected_signature(agent_id, agent, request)
        if touch_presence:
            self._db.collection("agents").document(agent_id).update(
                {"lastSeenAt": self._server_timestamp}
            )
        return body, agent


    async def require_replay_protected_signature(self,
        agent_id: str,
        agent: dict[str, Any],
        request: Request,
    ) -> None:
        nonce = verify_secure_agent_signature(
            agent.get("publicKey", ""), request, await request.body(),
        )
        nonce_ref = (
            self._db.collection("agents").document(agent_id)
            .collection("secureNonces").document(nonce)
        )
        try:
            nonce_ref.create({
                "createdAt": self._server_timestamp,
                "expiresAt": self._now() + timedelta(minutes=10),
            })
        except self._already_exists as exc:
            raise HTTPException(status_code=409, detail="Replayed secure Agent request") from exc


    def verify_public_key_request(self, public_key: str, request: Request) -> None:
        nonce = verify_activation_signatures(
            public_key, request, getattr(request, "_body", b""), now=self._clock(),
        )
        nonce_id = hashlib.sha256(f"{public_key}:{nonce}".encode("utf-8")).hexdigest()
        try:
            self._db.collection("activationNonces").document(nonce_id).create({
                "createdAt": self._server_timestamp,
                "expiresAt": self._now() + timedelta(minutes=10),
            })
        except self._already_exists as exc:
            raise HTTPException(status_code=409, detail="Replayed activation request") from exc


    def sign_enrollment_ticket(self, payload: dict[str, object]) -> str:
        if not self._ticket_secret:
            raise HTTPException(
                status_code=503, detail="Enrollment ticket signing is unavailable"
            )
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).decode("ascii").rstrip("=")
        signature = base64.urlsafe_b64encode(
            hmac.new(
                self._ticket_secret.encode("utf-8"),
                encoded.encode("ascii"),
                hashlib.sha256,
            ).digest()
        ).decode("ascii").rstrip("=")
        return f"{encoded}.{signature}"


    def verify_enrollment_ticket(self, ticket: str) -> dict[str, object]:
        if not self._ticket_secret:
            raise HTTPException(
                status_code=503, detail="Enrollment ticket validation is unavailable"
            )
        try:
            encoded, supplied = ticket.split(".", 1)
            expected = base64.urlsafe_b64encode(
                hmac.new(
                    self._ticket_secret.encode("utf-8"),
                    encoded.encode("ascii"),
                    hashlib.sha256,
                ).digest()
            ).decode("ascii").rstrip("=")
            if not hmac.compare_digest(supplied, expected):
                raise ValueError("signature")
            payload = json.loads(
                base64.urlsafe_b64decode(_padding(encoded)).decode("utf-8")
            )
            ticket_id = self._identifier(payload.get("id"), "ticketId")
            account_id = self._identifier(payload.get("accountId"), "accountId")
            expires_at = int(payload.get("expiresAt", 0))
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(
                status_code=401, detail="Invalid enrollment ticket"
            ) from exc
        if expires_at <= int(self._clock()):
            raise HTTPException(status_code=401, detail="Enrollment ticket expired")
        return {
            "id": ticket_id,
            "accountId": account_id,
            "expiresAt": expires_at,
        }


    def authenticate_relay_device(self,
        agent_id: str, device_id: str, request: Request
    ) -> tuple[Any, dict[str, Any]]:
        agent_id = self._identifier(agent_id, "agentId")
        device_id = self._identifier(device_id, "deviceId")
        device_ref = (
            self._db.collection("agents").document(agent_id)
            .collection("devices").document(device_id)
        )
        snapshot = device_ref.get()
        if not snapshot.exists:
            raise HTTPException(status_code=401, detail="Unknown device")
        device = snapshot.to_dict() or {}
        expires_at = device.get("expiresAt")
        if isinstance(expires_at, datetime) and expires_at < self._now():
            raise HTTPException(status_code=401, detail="Device credential expired")
        supplied = request.headers.get("authorization", "")
        token = supplied[7:].strip() if supplied.lower().startswith("bearer ") else ""
        expected = str(device.get("accessTokenHash", ""))
        if not token or not expected or not hmac.compare_digest(
            hashlib.sha256(token.encode("utf-8")).hexdigest(), expected
        ):
            raise HTTPException(status_code=401, detail="Invalid device credential")
        return device_ref, device


    def admin_authenticated(self, request: Request) -> bool:
        header_token = request.headers.get("x-pbxsense-admin-token", "")
        cookie_token = request.cookies.get(self._admin_cookie, "")
        return bool(self._admin_token) and (
            hmac.compare_digest(header_token, self._admin_token)
            or self.admin_cookie_valid(cookie_token)
        )


    def admin_cookie_value(self, expires_at: int | None = None) -> str:
        if not self._admin_token:
            return ""
        expiry = expires_at or int(self._clock()) + self._admin_cookie_ttl
        signature = hmac.new(
            self._admin_token.encode("utf-8"),
            f"pbxsense-relay-admin-cookie-v2:{expiry}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{expiry}.{signature}"


    def admin_cookie_valid(self, value: str, now: int | None = None) -> bool:
        if not self._admin_token:
            return False
        try:
            expiry_text, _ = value.split(".", 1)
            expiry = int(expiry_text)
        except (AttributeError, TypeError, ValueError):
            return False
        if expiry <= (int(self._clock()) if now is None else now):
            return False
        return hmac.compare_digest(value, self.admin_cookie_value(expiry))


    def require_admin(self, request: Request) -> None:
        supplied = request.headers.get("x-pbxsense-admin-token", "")
        if not self._admin_token or not hmac.compare_digest(supplied, self._admin_token):
            raise HTTPException(status_code=401, detail="Relay administrator token required")


def _padding(value: str) -> str:
    return value + "=" * (-len(value) % 4)

