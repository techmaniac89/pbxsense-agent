"""PBXSense's keyless, multi-site FCM relay for Cloud Run.

Cloud Run obtains Google credentials from its attached service account. Agents
authenticate with per-installation Ed25519 keys and never hold Firebase or
Google service-account credentials.
"""
from __future__ import annotations

import base64
import hashlib
import html
import hmac
import ipaddress
import json
import logging
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs

import firebase_admin
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from firebase_admin import firestore, messaging
from google.api_core.exceptions import AlreadyExists
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse


RELAY_VERSION = "0.5.5"
app = FastAPI(title="PBXSense Push Relay", version=RELAY_VERSION)
firebase_admin.initialize_app(options={"projectId": os.getenv("GOOGLE_CLOUD_PROJECT")})
db = firestore.client()
_admin_token = os.getenv("PBXSENSE_RELAY_ADMIN_TOKEN", "").strip()
_ticket_secret = os.getenv("PBXSENSE_RELAY_TICKET_SECRET", "").strip()
_enrollment_mode = os.getenv(
    "PBXSENSE_RELAY_ENROLLMENT_MODE", "open"
).strip().lower()
if _enrollment_mode not in {"open", "ticket", "closed"}:
    raise RuntimeError(
        "PBXSENSE_RELAY_ENROLLMENT_MODE must be open, ticket, or closed"
    )
if _enrollment_mode == "ticket" and not _ticket_secret:
    raise RuntimeError(
        "PBXSENSE_RELAY_TICKET_SECRET is required when ticket enrollment is enabled"
    )
if _ticket_secret and _admin_token and hmac.compare_digest(
    _ticket_secret, _admin_token
):
    raise RuntimeError(
        "PBXSENSE_RELAY_TICKET_SECRET must differ from PBXSENSE_RELAY_ADMIN_TOKEN"
    )
AGENT_LOSS_TIMEOUT_SECONDS = 90
MAX_DEVICES_PER_AGENT = max(
    1, min(50, int(os.getenv("PBXSENSE_RELAY_MAX_DEVICES_PER_AGENT", "10")))
)
MAX_SECURE_SNAPSHOT_BYTES = max(
    64 * 1024,
    min(
        5 * 1024 * 1024,
        int(os.getenv("PBXSENSE_RELAY_MAX_SNAPSHOT_BYTES", str(2 * 1024 * 1024))),
    ),
)
MAX_EVENTS_PER_AGENT_PER_HOUR = max(
    1, min(1000, int(os.getenv("PBXSENSE_RELAY_MAX_EVENTS_PER_AGENT_HOUR", "60")))
)
REMOTE_APP_POLL_SECONDS = max(
    15, min(300, int(os.getenv("PBXSENSE_RELAY_REMOTE_APP_POLL_SECONDS", "60")))
)
CONTROL_EXCHANGE_SECONDS = max(
    60, min(900, int(os.getenv("PBXSENSE_RELAY_CONTROL_EXCHANGE_SECONDS", "300")))
)
_request_windows: dict[str, deque[float]] = defaultdict(deque)
_event_windows: dict[str, deque[float]] = defaultdict(deque)
logger = logging.getLogger(__name__)
_admin_cookie = "pbxsense_relay_admin"
_trust_forwarded_for = bool(os.getenv("K_SERVICE")) or os.getenv(
    "PBXSENSE_RELAY_TRUST_PROXY", "false"
).strip().lower() in {"1", "true", "yes", "on"}


@app.middleware("http")
async def bound_public_requests(request: Request, call_next: Any) -> Any:
    """Bound request memory and floods before they generate backend work."""
    maximum = (
        MAX_SECURE_SNAPSHOT_BYTES
        if request.url.path.endswith("/secure/snapshots")
        else 1024 * 1024
    )
    content_length = request.headers.get("content-length", "")
    if content_length.isdigit() and int(content_length) > maximum:
        return JSONResponse(
            status_code=413, content={"detail": "Request body is too large"}
        )
    if request.method.upper() in {"POST", "PUT", "PATCH"}:
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > maximum:
                return JSONResponse(
                    status_code=413, content={"detail": "Request body is too large"}
                )
        request._body = bytes(body)
    client = _client_key(request)
    is_activation = request.url.path == "/v1/activations"
    if is_activation:
        # Agents behind one customer NAT should not share a tiny QR allowance.
        # Keep a broad source-IP ceiling, then limit each Agent key separately.
        if not _consume_window(
            _client_window(client), limit=60, seconds=60
        ):
            return JSONResponse(
                status_code=429, content={"detail": "Request rate limit exceeded"}
            )
        try:
            activation_body = json.loads(await request.body())
        except (json.JSONDecodeError, UnicodeDecodeError):
            activation_body = {}
        public_key = (
            str(activation_body.get("publicKey", ""))[:200]
            if isinstance(activation_body, dict)
            else ""
        )
        activation_client = (
            "activation:"
            + hashlib.sha256(public_key.encode("utf-8")).hexdigest()
            if public_key
            else f"activation-source:{client}"
        )
        allowed = _consume_window(
            _client_window(activation_client), limit=12, seconds=60
        )
    else:
        allowed = _consume_window(
            _client_window(client), limit=120, seconds=60
        )
    if not allowed:
        return JSONResponse(
            status_code=429, content={"detail": "Request rate limit exceeded"}
        )
    return await call_next(request)


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "pbxsense-push-relay",
        "version": RELAY_VERSION,
        "enrollmentMode": _enrollment_mode,
    }


@app.get("/v1/internal/usage")
async def relay_usage(request: Request) -> dict[str, object]:
    """Return privacy-safe fleet usage and durable daily rollups."""
    _require_admin(request)
    return _usage_report()


@app.get("/admin/usage", response_class=HTMLResponse)
async def usage_dashboard(request: Request) -> HTMLResponse:
    """Render the private operator dashboard without exposing PBX content."""
    if not _admin_authenticated(request):
        return HTMLResponse(
            _usage_login_page(),
            status_code=401,
            headers=_admin_page_headers(),
        )
    return HTMLResponse(
        _usage_dashboard_page(_usage_report()),
        headers=_admin_page_headers(),
    )


@app.post("/admin/usage")
async def usage_dashboard_login(request: Request) -> Any:
    body = (await request.body()).decode("utf-8", errors="replace")
    supplied = parse_qs(body).get("token", [""])[0]
    if not _admin_token or not hmac.compare_digest(supplied, _admin_token):
        return HTMLResponse(
            _usage_login_page("That administrator token was not accepted."),
            status_code=401,
            headers=_admin_page_headers(),
        )
    response = RedirectResponse(
        "/admin/usage",
        status_code=303,
        headers=_admin_page_headers(),
    )
    response.set_cookie(
        _admin_cookie,
        _admin_cookie_value(),
        max_age=8 * 60 * 60,
        httponly=True,
        secure=True,
        samesite="strict",
    )
    return response


@app.post("/v1/internal/enrollment-tickets")
async def create_enrollment_ticket(request: Request) -> dict[str, str]:
    """Issue a short-lived bootstrap capability from trusted billing/admin code."""
    _require_admin(request)
    body = await _json_body(request)
    account_id = _bounded_identifier(body.get("accountId"), "accountId")
    lifetime_minutes = int(body.get("lifetimeMinutes", 30))
    lifetime_minutes = max(5, min(24 * 60, lifetime_minutes))
    payload = {
        "accountId": account_id,
        "expiresAt": int(time.time()) + lifetime_minutes * 60,
        "id": f"ticket_{secrets.token_urlsafe(12)}",
    }
    return {
        "ticket": _sign_enrollment_ticket(payload),
        "expiresAt": datetime.fromtimestamp(
            payload["expiresAt"], timezone.utc
        ).isoformat(),
    }


@app.post("/v1/activations")
async def create_activation(request: Request) -> dict[str, str]:
    """Create the opaque, short-lived capability embedded in the Agent QR."""
    body = await _json_body(request)
    public_key = _bounded_text(body.get("publicKey"), "publicKey", 200)
    display_name = _bounded_text(body.get("displayName"), "displayName", 120)
    _decode_public_key(public_key)
    existing_agents = list(
        db.collection("agents")
        .where("publicKey", "==", public_key)
        .limit(1)
        .stream()
    )
    ticket_payload: dict[str, object] | None = None
    if existing_agents:
        _verify_public_key_request(public_key, request)
    elif _enrollment_mode == "closed":
        raise HTTPException(status_code=503, detail="New relay enrollment is paused")
    elif _enrollment_mode == "ticket":
        ticket = _bounded_text(
            body.get("enrollmentTicket"), "enrollmentTicket", 2048
        )
        ticket_payload = _verify_enrollment_ticket(ticket)
    activation_id = f"activate_{secrets.token_urlsafe(12)}"
    activation_secret = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.collection("activations").document(activation_id).create(
        {
            "secretHash": hashlib.sha256(activation_secret.encode("utf-8")).hexdigest(),
            "publicKey": public_key,
            "displayName": display_name,
            "expiresAt": expires_at,
            "claimedAt": None,
            **(
                {
                    "enrollmentTicketId": ticket_payload["id"],
                    "accountId": ticket_payload["accountId"],
                    "enrollmentTicketExpiresAt": datetime.fromtimestamp(
                        int(ticket_payload["expiresAt"]), timezone.utc
                    ),
                }
                if ticket_payload
                else {}
            ),
        }
    )
    return {"activationId": activation_id, "activationSecret": activation_secret, "expiresAt": expires_at.isoformat()}


@app.post("/v1/activations/{activation_id}/claim")
async def claim_activation(activation_id: str, request: Request) -> dict[str, str]:
    body = await _json_body(request)
    secret = _bounded_text(body.get("activationSecret"), "activationSecret", 200)
    activation_id = _bounded_identifier(activation_id, "activationId")
    activation_ref = db.collection("activations").document(activation_id)
    encryption_public_key = _optional_text(
        body.get("encryptionPublicKey"), limit=100
    )
    if encryption_public_key and len(_decode_bytes(encryption_public_key)) != 32:
        raise HTTPException(status_code=400, detail="Invalid encryptionPublicKey")
    # Every app receives a scoped device credential so it can revoke its own
    # push registration even while the Agent is offline or being rebuilt.
    # Encryption remains opt-in and is represented only by the optional key.
    relay_device_id = f"device_{secrets.token_urlsafe(12)}"
    relay_access_token = secrets.token_urlsafe(32)
    site_name = _optional_text(body.get("siteName"), limit=120)
    transaction = db.transaction()
    try:
        claim = _claim_activation_transaction(
            transaction,
            activation_ref=activation_ref,
            supplied_secret_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            requested_site_name=site_name,
            relay_device_id=relay_device_id,
            relay_access_token=relay_access_token,
            encryption_public_key=encryption_public_key,
        )
    except AlreadyExists as exc:
        raise HTTPException(
            status_code=401, detail="Activation or enrollment ticket was already used"
        ) from exc
    agent_id = str(claim["agentId"])
    site_id = str(claim["siteId"])
    logger.info("activation_claimed agent_id=%s reused=%s", agent_id, claim["reusedAgent"])
    result = {"status": "claimed", "agentId": agent_id, "siteId": site_id}
    result.update({"deviceId": relay_device_id, "deviceAccessToken": relay_access_token})
    return result


@firestore.transactional
def _claim_activation_transaction(
    transaction: Any,
    *,
    activation_ref: Any,
    supplied_secret_hash: str,
    requested_site_name: str,
    relay_device_id: str,
    relay_access_token: str,
    encryption_public_key: str,
) -> dict[str, object]:
    """Consume one QR capability and create its app registration atomically."""
    now = datetime.now(timezone.utc)
    snapshot = activation_ref.get(transaction=transaction)
    if not snapshot.exists:
        raise HTTPException(status_code=401, detail="Unknown activation")
    activation = snapshot.to_dict() or {}
    expires_at = activation.get("expiresAt")
    if (
        not hmac.compare_digest(str(activation.get("secretHash", "")), supplied_secret_hash)
        or activation.get("claimedAt")
        or not isinstance(expires_at, datetime)
        or expires_at < now
    ):
        raise HTTPException(status_code=401, detail="Expired or used activation")

    existing_agents = (
        db.collection("agents")
        .where("publicKey", "==", activation["publicKey"])
        .limit(1)
        .get(transaction=transaction)
    )
    reused = bool(existing_agents)
    if reused:
        existing = existing_agents[0]
        agent = existing.to_dict() or {}
        if agent.get("revoked"):
            raise HTTPException(status_code=403, detail="This Agent identity has been revoked")
        agent_id = existing.id
        site_id = str(agent.get("siteId", ""))
        if not site_id:
            raise HTTPException(status_code=500, detail="Existing Agent has no site identity")
    else:
        site_name = _bounded_text(
            requested_site_name or activation.get("displayName"), "siteName", 120
        )
        site_id = f"site_{secrets.token_urlsafe(10)}"
        agent_id = f"agent_{secrets.token_urlsafe(12)}"

    devices_ref = db.collection("agents").document(agent_id).collection("devices")
    if len(devices_ref.limit(MAX_DEVICES_PER_AGENT).get(transaction=transaction)) >= MAX_DEVICES_PER_AGENT:
        raise HTTPException(
            status_code=409,
            detail=f"This Agent has reached its {MAX_DEVICES_PER_AGENT}-app limit",
        )

    if not reused:
        transaction.create(
            db.collection("sites").document(site_id),
            {"name": site_name, "createdAt": firestore.SERVER_TIMESTAMP},
        )
        transaction.create(
            db.collection("agents").document(agent_id),
            {
                "tenantId": site_id,
                "siteId": site_id,
                "siteName": site_name,
                "displayName": activation["displayName"],
                "publicKey": activation["publicKey"],
                "enrolledAt": firestore.SERVER_TIMESTAMP,
                "lastSeenAt": firestore.SERVER_TIMESTAMP,
                "revoked": False,
                **({"accountId": activation["accountId"]} if activation.get("accountId") else {}),
            },
        )
    ticket_id = str(activation.get("enrollmentTicketId", ""))
    if _enrollment_mode == "ticket":
        ticket_expires_at = activation.get("enrollmentTicketExpiresAt")
        if not ticket_id or not isinstance(ticket_expires_at, datetime) or ticket_expires_at < now:
            raise HTTPException(status_code=401, detail="Enrollment ticket expired")
        transaction.create(
            db.collection("enrollmentTickets").document(ticket_id),
            {
                "accountId": activation.get("accountId", ""),
                "usedAt": firestore.SERVER_TIMESTAMP,
                "expiresAt": ticket_expires_at,
            },
        )
    transaction.create(
        devices_ref.document(relay_device_id),
        {
            "siteId": site_id,
            "accessTokenHash": hashlib.sha256(relay_access_token.encode("utf-8")).hexdigest(),
            **({"encryptionPublicKey": encryption_public_key} if encryption_public_key else {}),
            "createdAt": firestore.SERVER_TIMESTAMP,
            "updatedAt": firestore.SERVER_TIMESTAMP,
            "lastConnectedAt": firestore.SERVER_TIMESTAMP,
            "expiresAt": now + timedelta(days=30),
            "meaningfulEnabled": True,
            "activityEnabled": True,
        },
    )
    transaction.update(
        activation_ref,
        {
            "claimedAt": firestore.SERVER_TIMESTAMP,
            "agentId": agent_id,
            "siteId": site_id,
            "reusedAgent": reused,
        },
    )
    return {"agentId": agent_id, "siteId": site_id, "reusedAgent": reused}


@app.post("/v1/activations/{activation_id}/status")
async def activation_status(activation_id: str, request: Request) -> dict[str, object]:
    body = await _json_body(request)
    secret = _bounded_text(body.get("activationSecret"), "activationSecret", 200)
    snapshot = db.collection("activations").document(activation_id).get()
    activation = snapshot.to_dict() if snapshot.exists else None
    if not activation or not hmac.compare_digest(
        str(activation.get("secretHash", "")), hashlib.sha256(secret.encode("utf-8")).hexdigest()
    ):
        raise HTTPException(status_code=401, detail="Unknown activation")
    expires_at = activation.get("expiresAt")
    expired = isinstance(expires_at, datetime) and expires_at < datetime.now(timezone.utc)
    return {
        "claimed": bool(activation.get("claimedAt")),
        "agentId": activation.get("agentId", ""),
        "expired": expired,
    }


@app.post("/v1/agents/{agent_id}/devices")
async def register_device(agent_id: str, request: Request) -> dict[str, str]:
    body, agent = await _authenticate_agent(agent_id, request)
    fcm_token = _bounded_text(body.get("fcmToken"), "fcmToken", 4096)
    requested_device_id = _optional_identifier(body.get("relayDeviceId"))
    device_id = requested_device_id or hashlib.sha256(fcm_token.encode("utf-8")).hexdigest()
    encryption_public_key = _optional_text(body.get("encryptionPublicKey"), limit=100)
    devices_ref = db.collection("agents").document(agent_id).collection("devices")
    _register_agent_device_transaction(
        db.transaction(),
        device_ref=devices_ref.document(device_id),
        devices_ref=devices_ref,
        values={
            "fcmToken": fcm_token,
            "meaningfulEnabled": bool(body.get("meaningfulEnabled", True)),
            "activityEnabled": bool(body.get("activityEnabled", True)),
            "platform": _bounded_text(
                body.get("platform", "android"), "platform", 32
            ),
            "appVersion": _optional_text(body.get("appVersion")),
            "deviceModel": _optional_text(body.get("deviceModel")),
            "deviceName": _optional_text(body.get("deviceName")),
            "osVersion": _optional_text(body.get("osVersion")),
            "siteId": agent["siteId"],
            "updatedAt": firestore.SERVER_TIMESTAMP,
            "lastConnectedAt": firestore.SERVER_TIMESTAMP,
            "expiresAt": datetime.now(timezone.utc) + timedelta(days=30),
            **({"encryptionPublicKey": encryption_public_key} if encryption_public_key else {}),
        },
    )
    _assign_device_token_transaction(
        db.transaction(), devices_ref.document(device_id), fcm_token
    )
    return {"status": "registered", "deviceId": device_id}


@firestore.transactional
def _register_agent_device_transaction(
    transaction: Any,
    *,
    device_ref: Any,
    devices_ref: Any,
    values: dict[str, object],
) -> None:
    existing = device_ref.get(transaction=transaction)
    if not existing.exists and len(
        devices_ref.limit(MAX_DEVICES_PER_AGENT).get(transaction=transaction)
    ) >= MAX_DEVICES_PER_AGENT:
        raise HTTPException(
            status_code=409,
            detail=f"This Agent has reached its {MAX_DEVICES_PER_AGENT}-app limit",
        )
    transaction.set(
        device_ref,
        {
            **values,
        },
        merge=True,
    )


@firestore.transactional
def _assign_device_token_transaction(
    transaction: Any, device_ref: Any, fcm_token: str
) -> None:
    """Give one FCM token one owner, atomically across Agent rebuilds."""
    device_snapshot = device_ref.get(transaction=transaction)
    if not device_snapshot.exists:
        raise HTTPException(status_code=404, detail="Paired app no longer exists")
    device = device_snapshot.to_dict() or {}
    previous_token = str(device.get("fcmToken", ""))
    token_ref = db.collection("deviceTokens").document(
        hashlib.sha256(fcm_token.encode("utf-8")).hexdigest()
    )
    token_snapshot = token_ref.get(transaction=transaction)
    previous_owner_path = str(
        (token_snapshot.to_dict() or {}).get("devicePath", "")
    ) if token_snapshot.exists else ""
    previous_owner_ref = (
        _device_path_reference(previous_owner_path)
        if previous_owner_path and previous_owner_path != device_ref.path
        else None
    )
    if previous_owner_ref is not None:
        previous_owner_ref.get(transaction=transaction)
    old_token_ref = None
    old_token_snapshot = None
    if previous_token and previous_token != fcm_token:
        old_token_ref = db.collection("deviceTokens").document(
            hashlib.sha256(previous_token.encode("utf-8")).hexdigest()
        )
        old_token_snapshot = old_token_ref.get(transaction=transaction)

    if previous_owner_ref is not None:
        transaction.delete(previous_owner_ref)
    if old_token_ref is not None and old_token_snapshot is not None:
        old_path = str((old_token_snapshot.to_dict() or {}).get("devicePath", "")) \
            if old_token_snapshot.exists else ""
        if old_path == device_ref.path:
            transaction.delete(old_token_ref)
    transaction.set(
        device_ref,
        {"fcmToken": fcm_token, "updatedAt": firestore.SERVER_TIMESTAMP},
        merge=True,
    )
    transaction.set(
        token_ref,
        {"devicePath": device_ref.path, "updatedAt": firestore.SERVER_TIMESTAMP},
    )


def _device_path_reference(path: str) -> Any | None:
    parts = path.split("/")
    if (
        len(parts) != 4
        or parts[0] != "agents"
        or parts[2] != "devices"
        or not _optional_identifier(parts[1])
        or not _optional_identifier(parts[3])
    ):
        return None
    return db.document(path)


@app.post("/v1/agents/{agent_id}/devices/list")
async def list_devices(agent_id: str, request: Request) -> dict[str, object]:
    """Return device metadata to its owning Agent without exposing FCM tokens."""
    _, _ = await _authenticate_agent(agent_id, request, touch_presence=False)
    devices: list[dict[str, object]] = []
    connected_cutoff = datetime.now(timezone.utc) - timedelta(seconds=90)
    for snapshot in db.collection("agents").document(agent_id).collection("devices").stream():
        device = snapshot.to_dict() or {}
        last_connected_at = device.get("lastConnectedAt")
        devices.append(
            {
                "id": snapshot.id if device.get("accessTokenHash") else snapshot.id[:12],
                "revokeId": snapshot.id,
                "platform": str(device.get("platform", "unknown")),
                "appVersion": str(device.get("appVersion", "")),
                "deviceModel": str(device.get("deviceModel", "")),
                "deviceName": str(device.get("deviceName", "")),
                "osVersion": str(device.get("osVersion", "")),
                "meaningfulEnabled": bool(device.get("meaningfulEnabled", True)),
                "activityEnabled": bool(device.get("activityEnabled", True)),
                "updatedAt": _timestamp_text(device.get("updatedAt")),
                "lastConnectedAt": _timestamp_text(last_connected_at),
                "connectedNow": (
                    isinstance(last_connected_at, datetime)
                    and last_connected_at >= connected_cutoff
                ),
                "expiresAt": _timestamp_text(device.get("expiresAt")),
                "encryptionPublicKey": str(device.get("encryptionPublicKey", "")),
            }
        )
    devices.sort(key=lambda item: str(item.get("updatedAt", "")), reverse=True)
    return {"devices": devices}


@app.post("/v1/agents/{agent_id}/devices/revoke")
async def revoke_device(agent_id: str, request: Request) -> dict[str, str]:
    body, _ = await _authenticate_agent(agent_id, request)
    requested_device_id = _optional_identifier(body.get("relayDeviceId"))
    token = _optional_text(body.get("fcmToken"))
    if not requested_device_id and not token:
        raise HTTPException(status_code=400, detail="Device identity is required")
    device_id = requested_device_id or hashlib.sha256(token.encode("utf-8")).hexdigest()
    _delete_device_registration(agent_id, device_id)
    return {"status": "revoked"}


@app.post("/v1/agents/{agent_id}/heartbeat")
async def heartbeat(agent_id: str, request: Request) -> dict[str, object]:
    _, agent = await _authenticate_agent(agent_id, request, touch_presence=False)
    agent_ref = db.collection("agents").document(agent_id)
    was_lost = bool(agent.get("lostAt"))
    if was_lost:
        _send_agent_status(agent_id, "PBXSense Agent is reachable again.", "Live PBX updates have resumed.")
    agent_ref.update({
        "lastSeenAt": firestore.SERVER_TIMESTAMP,
        "lostAt": None,
        **_usage_update(agent_ref, agent, "agent", agent_id, heartbeats=1),
    })
    return {"status": "ok", "policy": _relay_policy()}


@app.post("/v1/agents/{agent_id}/secure/exchange")
async def secure_exchange(agent_id: str, request: Request) -> dict[str, object]:
    """Exchange bounded control frames over an outbound-only Agent session."""
    body, agent = await _authenticate_agent(agent_id, request, touch_presence=False)
    if body.get("protocolVersion") != 1:
        raise HTTPException(status_code=400, detail="Unsupported secure relay protocol")
    session_id = _bounded_identifier(body.get("sessionId"), "sessionId")
    capabilities = body.get("capabilities", [])
    responses = body.get("responses", [])
    if not isinstance(capabilities, list) or len(capabilities) > 20:
        raise HTTPException(status_code=400, detail="Invalid capabilities")
    if not isinstance(responses, list) or len(responses) > 20:
        raise HTTPException(status_code=400, detail="Invalid responses")
    safe_capabilities = [
        _bounded_identifier(value, "capability") for value in capabilities
    ]
    agent_ref = db.collection("agents").document(agent_id)
    agent_ref.update({
        "secureRelaySessionId": session_id,
        "secureRelayProtocolVersion": 1,
        "secureRelayCapabilities": safe_capabilities,
        "secureRelayLastSeenAt": firestore.SERVER_TIMESTAMP,
        **_usage_update(
            agent_ref,
            agent,
            "agent",
            agent_id,
            controlExchanges=1,
        ),
    })
    commands_ref = agent_ref.collection("secureCommands")
    for response in responses:
        if not isinstance(response, dict):
            continue
        response_id = _optional_identifier(response.get("id"))
        if not response_id:
            continue
        commands_ref.document(response_id).set({
            "state": "completed",
            "responseStatus": _optional_text(response.get("status"))[:32],
            "responseKind": _optional_text(response.get("kind"))[:32],
            "completedAt": firestore.SERVER_TIMESTAMP,
        }, merge=True)

    commands: list[dict[str, object]] = []
    now = datetime.now(timezone.utc)
    for snapshot in commands_ref.where("state", "==", "queued").limit(20).stream():
        command = snapshot.to_dict() or {}
        expires_at = command.get("expiresAt")
        if not isinstance(expires_at, datetime) or expires_at <= now:
            snapshot.reference.set({"state": "expired"}, merge=True)
            continue
        command_type = _optional_identifier(command.get("type"))
        if not command_type:
            continue
        commands.append({
            "id": snapshot.id,
            "type": command_type,
            "expiresAt": int(expires_at.timestamp()),
        })
        snapshot.reference.set({
            "deliveredAt": firestore.SERVER_TIMESTAMP,
            "sessionId": session_id,
        }, merge=True)
    return {
        "protocolVersion": 1,
        "commands": commands,
        "policy": _relay_policy(),
    }


@app.post("/v1/agents/{agent_id}/secure/snapshots")
async def publish_secure_snapshots(agent_id: str, request: Request) -> dict[str, int]:
    body, agent = await _authenticate_agent(agent_id, request, touch_presence=False)
    envelopes = body.get("envelopes", [])
    if not isinstance(envelopes, list) or len(envelopes) > 20:
        raise HTTPException(status_code=400, detail="Invalid secure envelopes")
    stored = 0
    devices_ref = db.collection("agents").document(agent_id).collection("devices")
    for envelope in envelopes:
        if not isinstance(envelope, dict):
            continue
        device_id = _bounded_identifier(envelope.get("deviceId"), "deviceId")
        device_snapshot = devices_ref.document(device_id).get()
        if not device_snapshot.exists:
            continue
        device = device_snapshot.to_dict() or {}
        ciphertext = _clean_text(envelope.get("ciphertext"), "ciphertext")
        if len(ciphertext) > 900_000:
            raise HTTPException(status_code=413, detail="Encrypted snapshot is too large")
        safe_envelope = {
            "protocolVersion": 1,
            "sequence": int(envelope.get("sequence", 0)),
            "createdAt": _clean_text(envelope.get("createdAt"), "createdAt")[:40],
            "ephemeralPublicKey": _bounded_base64(envelope.get("ephemeralPublicKey"), "ephemeralPublicKey", 100),
            "salt": _bounded_base64(envelope.get("salt"), "salt", 80),
            "nonce": _bounded_base64(envelope.get("nonce"), "nonce", 80),
            "ciphertext": ciphertext,
            "updatedAt": firestore.SERVER_TIMESTAMP,
        }
        devices_ref.document(device_id).collection("secureSnapshots").document("latest").set(safe_envelope)
        devices_ref.document(device_id).update(
            _usage_update(
                devices_ref.document(device_id),
                device,
                "app",
                f"{agent_id}/{device_id}",
                encryptedSnapshotsPublished=1,
                encryptedSnapshotBytes=len(ciphertext),
            )
        )
        stored += 1
    return {"stored": stored}


@app.post("/v1/agents/{agent_id}/devices/{device_id}/secure-snapshot")
async def read_secure_snapshot(agent_id: str, device_id: str, request: Request) -> dict[str, object]:
    device_ref, device = _authenticate_relay_device(agent_id, device_id, request)
    device_ref.update({
        "lastConnectedAt": firestore.SERVER_TIMESTAMP,
        **_usage_update(
            device_ref,
            device,
            "app",
            f"{agent_id}/{device_id}",
            remoteSnapshotReads=1,
        ),
    })
    agent_snapshot = db.collection("agents").document(agent_id).get()
    agent = agent_snapshot.to_dict() if agent_snapshot.exists else None
    last_seen_at = agent.get("lastSeenAt") if agent else None
    if (
        not isinstance(last_seen_at, datetime)
        or last_seen_at < datetime.now(timezone.utc) - timedelta(seconds=AGENT_LOSS_TIMEOUT_SECONDS)
    ):
        return {"available": False, "reason": "agentOffline"}
    snapshot = device_ref.collection("secureSnapshots").document("latest").get()
    if not snapshot.exists:
        return {"available": False}
    envelope = snapshot.to_dict() or {}
    envelope.pop("updatedAt", None)
    return {
        "available": True,
        "agentLastSeenAt": last_seen_at.isoformat(),
        "envelope": envelope,
        "policy": _relay_policy(),
    }


@app.post("/v1/agents/{agent_id}/devices/{device_id}/registration")
async def register_own_device(
    agent_id: str, device_id: str, request: Request
) -> dict[str, object]:
    """Let a paired app register push without reaching the Agent's LAN URL."""
    device_ref, _ = _authenticate_relay_device(agent_id, device_id, request)
    body = await _json_body(request)
    fcm_token = _bounded_text(body.get("fcmToken"), "fcmToken", 4096)
    device_ref.set(
        {
            "meaningfulEnabled": bool(body.get("meaningfulEnabled", True)),
            "activityEnabled": bool(body.get("activityEnabled", True)),
            "platform": _bounded_text(
                body.get("platform", "android"), "platform", 32
            ),
            "appVersion": _optional_text(body.get("appVersion")),
            "deviceModel": _optional_text(body.get("deviceModel")),
            "deviceName": _optional_text(body.get("deviceName")),
            "osVersion": _optional_text(body.get("osVersion")),
            "updatedAt": firestore.SERVER_TIMESTAMP,
            "lastConnectedAt": firestore.SERVER_TIMESTAMP,
            "expiresAt": datetime.now(timezone.utc) + timedelta(days=30),
        },
        merge=True,
    )
    _assign_device_token_transaction(db.transaction(), device_ref, fcm_token)
    logger.info("device_self_registered agent_id=%s device_id=%s", agent_id, device_id)
    return {"delivered": True, "deviceId": device_id}


@app.delete("/v1/agents/{agent_id}/devices/{device_id}")
async def revoke_own_device(
    agent_id: str, device_id: str, request: Request
) -> dict[str, str]:
    """Allow an app to revoke only the relay device its bearer token owns."""
    device_ref = db.collection("agents").document(agent_id).collection("devices").document(device_id)
    snapshot = device_ref.get()
    if not snapshot.exists:
        # A repeated reset is already in the desired state.
        return {"status": "removed"}
    device = snapshot.to_dict() or {}
    supplied = request.headers.get("authorization", "")
    token = supplied[7:].strip() if supplied.lower().startswith("bearer ") else ""
    expected = str(device.get("accessTokenHash", ""))
    if not token or not expected or not hmac.compare_digest(
        hashlib.sha256(token.encode("utf-8")).hexdigest(), expected
    ):
        raise HTTPException(status_code=401, detail="Invalid device credential")
    _delete_device_registration(
        agent_id, device_id, expected_access_token_hash=expected
    )
    return {"status": "removed"}


@app.post("/v1/internal/agents/{agent_id}/secure/ping")
async def queue_secure_ping(agent_id: str, request: Request) -> dict[str, str]:
    """Operator smoke test for the outbound secure session."""
    _require_admin(request)
    agent_ref = db.collection("agents").document(agent_id)
    snapshot = agent_ref.get()
    if not snapshot.exists or (snapshot.to_dict() or {}).get("revoked"):
        raise HTTPException(status_code=404, detail="Unknown Agent")
    command_id = f"ping_{secrets.token_urlsafe(12)}"
    agent_ref.collection("secureCommands").document(command_id).create({
        "type": "ping",
        "state": "queued",
        "createdAt": firestore.SERVER_TIMESTAMP,
        "expiresAt": datetime.now(timezone.utc) + timedelta(minutes=1),
    })
    return {"status": "queued", "commandId": command_id}


@app.post("/v1/internal/sweep-agent-heartbeats")
async def sweep_agent_heartbeats(request: Request) -> dict[str, int]:
    """Invoke every minute from Cloud Scheduler with the admin secret."""
    _require_admin(request)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=AGENT_LOSS_TIMEOUT_SECONDS)
    lost = 0
    for snapshot in db.collection("agents").where("lastSeenAt", "<", cutoff).stream():
        agent = snapshot.to_dict() or {}
        if agent.get("revoked") or agent.get("lostAt"):
            continue
        _send_agent_status(
            snapshot.id,
            "PBXSense lost the Agent.",
            "Live PBX updates are paused until the Agent is reachable again.",
        )
        snapshot.reference.update({"lostAt": firestore.SERVER_TIMESTAMP})
        lost += 1
    return {"lost": lost}


@app.delete("/v1/agents/{agent_id}/devices")
async def remove_device(agent_id: str, request: Request) -> dict[str, str]:
    body, _ = await _authenticate_agent(agent_id, request, touch_presence=False)
    fcm_token = _bounded_text(body.get("fcmToken"), "fcmToken", 4096)
    device_id = hashlib.sha256(fcm_token.encode("utf-8")).hexdigest()
    _delete_device_registration(agent_id, device_id)
    return {"status": "removed"}


@app.post("/v1/agents/{agent_id}/events")
async def publish_event(agent_id: str, request: Request) -> dict[str, Any]:
    event, agent = await _authenticate_agent(agent_id, request, touch_presence=False)
    if not _consume_window(
        _event_windows[agent_id],
        limit=MAX_EVENTS_PER_AGENT_PER_HOUR,
        seconds=60 * 60,
    ):
        raise HTTPException(
            status_code=429, detail="Agent notification rate limit exceeded"
        )
    event_id = _bounded_identifier(event.get("id"), "id")
    signal_id = _bounded_identifier(event.get("signalId", event_id), "signalId")
    title = _bounded_text(event.get("title"), "title", 256)
    body = _bounded_text(event.get("body"), "body", 2048)
    category = _bounded_text(event.get("category"), "category", 64)
    importance = _bounded_text(event.get("importance"), "importance", 32)
    notification_tag = _optional_identifier(event.get("notificationTag")) or event_id
    if category == "recommendation":
        return {"status": "ignored", "reason": "tips_are_feed_only"}

    event_ref = db.collection("sites").document(agent["siteId"]).collection("events").document(event_id)
    try:
        event_ref.create(
            {
                "agentId": agent_id,
                "category": category,
                "importance": importance,
                "createdAt": firestore.SERVER_TIMESTAMP,
                "expiresAt": datetime.now(timezone.utc) + timedelta(days=2),
            }
        )
    except AlreadyExists:
        return {"status": "duplicate", "sent": 0}

    devices = [_device_record(document) for document in
        db.collection("agents").document(agent_id).collection("devices").stream()]
    now = datetime.now(timezone.utc)
    eligible_devices = _unique_devices_by_token([
        device
        for device in devices
        if _device_wants_event(device, category, importance)
        and device.get("expiresAt", now) >= now
        and device.get("fcmToken")
    ])
    tokens = [str(device["fcmToken"]) for device in eligible_devices]
    if not tokens:
        return {"status": "accepted", "sent": 0}

    message = messaging.MulticastMessage(
        tokens=tokens,
        notification=messaging.Notification(title=title, body=body),
        data={
            "signalId": signal_id,
            "notificationId": event_id,
            "siteId": agent["siteId"],
            "category": category,
            "importance": importance,
        },
        android=messaging.AndroidConfig(
            priority="high",
            notification=messaging.AndroidNotification(tag=notification_tag),
        ),
    )
    try:
        response = messaging.send_each_for_multicast(message)
    except Exception:
        # Do not let the idempotency record turn a temporary FCM outage into a
        # permanently dropped event. The Agent's durable outbox will retry it.
        event_ref.delete()
        raise
    invalid_tokens = _remove_invalid_tokens(agent_id, eligible_devices, response.responses)
    logger.info(
        "fcm_signal agent_id=%s eligible=%d accepted=%d failed=%d invalid_removed=%d",
        agent_id,
        len(eligible_devices),
        response.success_count,
        response.failure_count,
        invalid_tokens,
    )
    return {"status": "accepted", "sent": response.success_count, "failed": response.failure_count}


async def _authenticate_agent(
    agent_id: str,
    request: Request,
    *,
    touch_presence: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    agent_id = _bounded_identifier(agent_id, "agentId")
    raw_body = await request.body()
    max_bytes = (
        MAX_SECURE_SNAPSHOT_BYTES
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
    agent_snapshot = db.collection("agents").document(agent_id).get()
    if not agent_snapshot.exists:
        raise HTTPException(status_code=401, detail="Unknown Agent")
    agent = agent_snapshot.to_dict() or {}
    if agent.get("revoked"):
        raise HTTPException(status_code=401, detail="Agent has been revoked")
    timestamp = request.headers.get("x-pbxsense-timestamp", "")
    signature = request.headers.get("x-pbxsense-signature", "")
    try:
        issued_at = int(timestamp)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid request timestamp") from exc
    if abs(time.time() - issued_at) > 300:
        raise HTTPException(status_code=401, detail="Expired signed request")
    message = f"{timestamp}\n{request.url.path}\n".encode("utf-8") + raw_body
    try:
        _decode_public_key(agent["publicKey"]).verify(_decode_signature(signature), message)
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise HTTPException(status_code=401, detail="Invalid Agent signature") from exc
    await _require_replay_protected_signature(agent_id, agent, request)
    if touch_presence:
        db.collection("agents").document(agent_id).update(
            {"lastSeenAt": firestore.SERVER_TIMESTAMP}
        )
    return body, agent


async def _require_replay_protected_signature(
    agent_id: str,
    agent: dict[str, Any],
    request: Request,
) -> None:
    timestamp = request.headers.get("x-pbxsense-timestamp", "")
    nonce = request.headers.get("x-pbxsense-nonce", "")
    signature = request.headers.get("x-pbxsense-signature-v2", "")
    if not 16 <= len(nonce) <= 96 or not nonce.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(status_code=401, detail="Invalid secure request nonce")
    raw_body = await request.body()
    digest = hashlib.sha256(raw_body).hexdigest()
    message = (
        f"{timestamp}\n{nonce}\n{request.method.upper()}\n{request.url.path}\n{digest}"
    ).encode("utf-8")
    try:
        _decode_public_key(agent["publicKey"]).verify(
            _decode_signature(signature), message
        )
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise HTTPException(status_code=401, detail="Invalid secure Agent signature") from exc
    nonce_ref = (
        db.collection("agents").document(agent_id)
        .collection("secureNonces").document(nonce)
    )
    try:
        nonce_ref.create({
            "createdAt": firestore.SERVER_TIMESTAMP,
            "expiresAt": datetime.now(timezone.utc) + timedelta(minutes=10),
        })
    except AlreadyExists as exc:
        raise HTTPException(status_code=409, detail="Replayed secure Agent request") from exc


def _bounded_identifier(value: object, field: str) -> str:
    text = _clean_text(value, field)
    if len(text) > 96 or not text.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise HTTPException(status_code=400, detail=f"Invalid {field}")
    return text


def _optional_identifier(value: object) -> str:
    try:
        return _bounded_identifier(value, "identifier")
    except HTTPException:
        return ""


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    hops = (
        [item.strip() for item in forwarded.split(",") if item.strip()]
        if _trust_forwarded_for else []
    )
    # Cloud Run appends its proxy hop. The first value is caller-controlled;
    # use the address immediately before the trusted proxy when available.
    candidate = hops[-2] if len(hops) >= 2 else str(
        request.client.host if request.client else "unknown"
    )
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return "unknown"


def _consume_window(
    window: deque[float], *, limit: int, seconds: int
) -> bool:
    now = time.monotonic()
    cutoff = now - seconds
    while window and window[0] <= cutoff:
        window.popleft()
    if len(window) >= limit:
        return False
    window.append(now)
    return True


def _client_window(client: str) -> deque[float]:
    # Bound attacker-controlled source keys so spoofed forwarding metadata
    # cannot turn the lightweight limiter itself into an unbounded allocation.
    if client not in _request_windows and len(_request_windows) >= 10_000:
        now = time.monotonic()
        expired = [
            key
            for key, window in _request_windows.items()
            if not window or window[-1] <= now - 60
        ]
        for key in expired[:2_000]:
            _request_windows.pop(key, None)
        if len(_request_windows) >= 10_000:
            return _request_windows["overflow"]
    return _request_windows[client]


def _verify_public_key_request(public_key: str, request: Request) -> None:
    timestamp = request.headers.get("x-pbxsense-timestamp", "")
    signature = request.headers.get("x-pbxsense-signature", "")
    try:
        issued_at = int(timestamp)
    except ValueError as exc:
        raise HTTPException(
            status_code=401, detail="Signed activation request required"
        ) from exc
    if abs(time.time() - issued_at) > 300:
        raise HTTPException(status_code=401, detail="Expired activation request")
    raw_body = getattr(request, "_body", b"")
    message = (
        f"{timestamp}\n{request.url.path}\n".encode("utf-8") + raw_body
    )
    try:
        _decode_public_key(public_key).verify(
            _decode_signature(signature), message
        )
    except (InvalidSignature, ValueError) as exc:
        raise HTTPException(
            status_code=401, detail="Invalid activation signature"
        ) from exc
    nonce = request.headers.get("x-pbxsense-nonce", "")
    signature_v2 = request.headers.get("x-pbxsense-signature-v2", "")
    if not 16 <= len(nonce) <= 96 or not nonce.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(status_code=401, detail="Invalid activation nonce")
    digest = hashlib.sha256(raw_body).hexdigest()
    v2_message = (
        f"{timestamp}\n{nonce}\n{request.method.upper()}\n{request.url.path}\n{digest}"
    ).encode("utf-8")
    try:
        _decode_public_key(public_key).verify(
            _decode_signature(signature_v2), v2_message
        )
    except (InvalidSignature, ValueError) as exc:
        raise HTTPException(
            status_code=401, detail="Invalid secure activation signature"
        ) from exc
    nonce_id = hashlib.sha256(f"{public_key}:{nonce}".encode("utf-8")).hexdigest()
    try:
        db.collection("activationNonces").document(nonce_id).create({
            "createdAt": firestore.SERVER_TIMESTAMP,
            "expiresAt": datetime.now(timezone.utc) + timedelta(minutes=10),
        })
    except AlreadyExists as exc:
        raise HTTPException(status_code=409, detail="Replayed activation request") from exc


def _sign_enrollment_ticket(payload: dict[str, object]) -> str:
    if not _ticket_secret:
        raise HTTPException(
            status_code=503, detail="Enrollment ticket signing is unavailable"
        )
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii").rstrip("=")
    signature = base64.urlsafe_b64encode(
        hmac.new(
            _ticket_secret.encode("utf-8"),
            encoded.encode("ascii"),
            hashlib.sha256,
        ).digest()
    ).decode("ascii").rstrip("=")
    return f"{encoded}.{signature}"


def _verify_enrollment_ticket(ticket: str) -> dict[str, object]:
    if not _ticket_secret:
        raise HTTPException(
            status_code=503, detail="Enrollment ticket validation is unavailable"
        )
    try:
        encoded, supplied = ticket.split(".", 1)
        expected = base64.urlsafe_b64encode(
            hmac.new(
                _ticket_secret.encode("utf-8"),
                encoded.encode("ascii"),
                hashlib.sha256,
            ).digest()
        ).decode("ascii").rstrip("=")
        if not hmac.compare_digest(supplied, expected):
            raise ValueError("signature")
        payload = json.loads(
            base64.urlsafe_b64decode(_padding(encoded)).decode("utf-8")
        )
        ticket_id = _bounded_identifier(payload.get("id"), "ticketId")
        account_id = _bounded_identifier(payload.get("accountId"), "accountId")
        expires_at = int(payload.get("expiresAt", 0))
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=401, detail="Invalid enrollment ticket"
        ) from exc
    if expires_at <= int(time.time()):
        raise HTTPException(status_code=401, detail="Enrollment ticket expired")
    return {
        "id": ticket_id,
        "accountId": account_id,
        "expiresAt": expires_at,
    }


def _delete_device_registration(
    agent_id: str,
    device_id: str,
    *,
    expected_access_token_hash: str = "",
) -> None:
    device_ref = (
        db.collection("agents").document(agent_id)
        .collection("devices").document(device_id)
    )
    _delete_device_registration_transaction(
        db.transaction(), device_ref, expected_access_token_hash
    )


@firestore.transactional
def _delete_device_registration_transaction(
    transaction: Any, device_ref: Any, expected_access_token_hash: str
) -> None:
    snapshot = device_ref.get(transaction=transaction)
    if not snapshot.exists:
        return
    device = snapshot.to_dict() or {}
    if expected_access_token_hash and not hmac.compare_digest(
        str(device.get("accessTokenHash", "")), expected_access_token_hash
    ):
        raise HTTPException(status_code=409, detail="Paired app changed; retry removal")
    fcm_token = str(device.get("fcmToken", ""))
    token_ref = (
        db.collection("deviceTokens").document(
            hashlib.sha256(fcm_token.encode("utf-8")).hexdigest()
        )
        if fcm_token else None
    )
    pointer = token_ref.get(transaction=transaction) if token_ref else None
    transaction.delete(device_ref)
    if (
        token_ref is not None
        and pointer is not None
        and pointer.exists
        and str((pointer.to_dict() or {}).get("devicePath", "")) == device_ref.path
    ):
        transaction.delete(token_ref)


def _remove_invalid_tokens(agent_id: str, devices: list[dict[str, Any]], responses: list[Any]) -> int:
    removed = 0
    for device, response in zip(devices, responses, strict=True):
        if response.success or not isinstance(response.exception, messaging.UnregisteredError):
            continue
        device_id = str(device.get("_documentId", ""))
        if device_id:
            _delete_device_registration(agent_id, device_id)
            removed += 1
    return removed


def _device_wants_event(device: dict[str, Any], category: str, importance: str) -> bool:
    if not device.get("meaningfulEnabled", True):
        return False
    if category == "activity":
        return bool(device.get("activityEnabled", True))
    return importance in {"attention", "important"}


def _send_agent_status(agent_id: str, title: str, body: str) -> None:
    now = datetime.now(timezone.utc)
    devices = [_device_record(document) for document in
        db.collection("agents").document(agent_id).collection("devices").stream()]
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
        logger.info("fcm_agent_status agent_id=%s eligible=0 accepted=0 failed=0 invalid_removed=0", agent_id)
        return
    response = messaging.send_each_for_multicast(
        messaging.MulticastMessage(
            tokens=tokens,
            notification=messaging.Notification(title=title, body=body),
            data={"kind": "agent_connection", "agentId": agent_id},
            android=messaging.AndroidConfig(priority="high"),
        )
    )
    invalid_tokens = _remove_invalid_tokens(agent_id, eligible_devices, response.responses)
    logger.info(
        "fcm_agent_status agent_id=%s eligible=%d accepted=%d failed=%d invalid_removed=%d",
        agent_id,
        len(eligible_devices),
        response.success_count,
        response.failure_count,
        invalid_tokens,
    )


def _device_record(document: Any) -> dict[str, Any]:
    device = document.to_dict() or {}
    device["_documentId"] = document.id
    return device


def _unique_devices_by_token(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Never send the same multicast message twice to one FCM token."""
    unique: dict[str, dict[str, Any]] = {}
    for device in devices:
        token = str(device.get("fcmToken", ""))
        if token:
            unique[token] = device
    return list(unique.values())


def _authenticate_relay_device(
    agent_id: str, device_id: str, request: Request
) -> tuple[Any, dict[str, Any]]:
    agent_id = _bounded_identifier(agent_id, "agentId")
    device_id = _bounded_identifier(device_id, "deviceId")
    device_ref = (
        db.collection("agents").document(agent_id)
        .collection("devices").document(device_id)
    )
    snapshot = device_ref.get()
    if not snapshot.exists:
        raise HTTPException(status_code=401, detail="Unknown device")
    device = snapshot.to_dict() or {}
    expires_at = device.get("expiresAt")
    if isinstance(expires_at, datetime) and expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Device credential expired")
    supplied = request.headers.get("authorization", "")
    token = supplied[7:].strip() if supplied.lower().startswith("bearer ") else ""
    expected = str(device.get("accessTokenHash", ""))
    if not token or not expected or not hmac.compare_digest(
        hashlib.sha256(token.encode("utf-8")).hexdigest(), expected
    ):
        raise HTTPException(status_code=401, detail="Invalid device credential")
    return device_ref, device


async def _json_body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > 64 * 1024:
        raise HTTPException(status_code=413, detail="Request body is too large")
    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="JSON body required") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="JSON object required")
    return body


def _admin_authenticated(request: Request) -> bool:
    header_token = request.headers.get("x-pbxsense-admin-token", "")
    cookie_token = request.cookies.get(_admin_cookie, "")
    return bool(_admin_token) and (
        hmac.compare_digest(header_token, _admin_token)
        or hmac.compare_digest(cookie_token, _admin_cookie_value())
    )


def _admin_cookie_value() -> str:
    if not _admin_token:
        return ""
    return hmac.new(
        _admin_token.encode("utf-8"),
        b"pbxsense-relay-admin-cookie-v1",
        hashlib.sha256,
    ).hexdigest()


def _require_admin(request: Request) -> None:
    supplied = request.headers.get("x-pbxsense-admin-token", "")
    if not _admin_token or not hmac.compare_digest(supplied, _admin_token):
        raise HTTPException(status_code=401, detail="Relay administrator token required")


def _relay_policy() -> dict[str, int]:
    return {
        "agentPresenceSeconds": 30,
        "agentLossSeconds": AGENT_LOSS_TIMEOUT_SECONDS,
        "controlExchangeSeconds": CONTROL_EXCHANGE_SECONDS,
        "remotePollSeconds": REMOTE_APP_POLL_SECONDS,
    }


def _usage_update(
    reference: Any,
    existing: dict[str, object],
    entity_kind: str,
    entity_id: str,
    **increments: int,
) -> dict[str, object]:
    """Build counters that reuse an endpoint's existing Firestore write."""
    today = datetime.now(timezone.utc).date().isoformat()
    _archive_usage(reference, existing, entity_kind, entity_id, today)
    clean = {
        key: max(0, int(value))
        for key, value in increments.items()
        if int(value) > 0
    }
    if existing.get("usageDate") != today:
        return {"usageDate": today, "usage": clean}
    return {
        f"usage.{key}": firestore.Increment(value)
        for key, value in clean.items()
    }


def _current_usage(document: dict[str, object], today: str) -> dict[str, int]:
    if document.get("usageDate") != today:
        return {}
    usage = document.get("usage")
    if not isinstance(usage, dict):
        return {}
    return {
        str(key): max(0, int(value))
        for key, value in usage.items()
        if isinstance(value, (int, float)) and value >= 0
    }


def _archive_usage(
    reference: Any,
    document: dict[str, object],
    entity_kind: str,
    entity_id: str,
    today: str,
) -> None:
    """Persist the completed UTC-day counters once per entity and date."""
    usage_date = document.get("usageDate")
    if not isinstance(usage_date, str) or usage_date == today:
        return
    if document.get("usageArchivedDate") == usage_date:
        return
    try:
        datetime.strptime(usage_date, "%Y-%m-%d")
    except ValueError:
        return
    usage = _current_usage(document, usage_date)
    if not usage:
        return
    identity = hashlib.sha256(
        f"{entity_kind}:{entity_id}".encode("utf-8")
    ).hexdigest()[:24]
    archive_ref = (
        db.collection("usageDaily")
        .document(usage_date)
        .collection("entities")
        .document(identity)
    )
    archive_ref.set(
        {
            "kind": entity_kind,
            "usage": usage,
            "archivedAt": firestore.SERVER_TIMESTAMP,
            "expiresAt": datetime.now(timezone.utc) + timedelta(days=90),
        }
    )
    reference.update({"usageArchivedDate": usage_date})


def _usage_report(days: int = 7) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    today = now.date().isoformat()
    active_cutoff = now - timedelta(seconds=AGENT_LOSS_TIMEOUT_SECONDS)
    connected_cutoff = now - timedelta(seconds=120)
    totals: dict[str, int] = defaultdict(int)
    agent_rows: list[dict[str, object]] = []
    registered_apps = 0
    connected_apps = 0
    active_agents = 0
    usage_agents = 0
    usage_apps = 0
    agents = list(db.collection("agents").limit(1000).stream())
    for snapshot in agents:
        agent = snapshot.to_dict() or {}
        _archive_usage(snapshot.reference, agent, "agent", snapshot.id, today)
        usage = _current_usage(agent, today)
        if usage:
            usage_agents += 1
        for key, value in usage.items():
            totals[key] += value
        last_seen_at = agent.get("lastSeenAt")
        active = isinstance(last_seen_at, datetime) and last_seen_at >= active_cutoff
        if active:
            active_agents += 1
        apps = 0
        connected = 0
        for device_snapshot in snapshot.reference.collection("devices").stream():
            device = device_snapshot.to_dict() or {}
            _archive_usage(
                device_snapshot.reference,
                device,
                "app",
                f"{snapshot.id}/{device_snapshot.id}",
                today,
            )
            apps += 1
            device_usage = _current_usage(device, today)
            if device_usage:
                usage_apps += 1
            for key, value in device_usage.items():
                totals[key] += value
            last_connected_at = device.get("lastConnectedAt")
            if (
                isinstance(last_connected_at, datetime)
                and last_connected_at >= connected_cutoff
            ):
                connected += 1
        registered_apps += apps
        connected_apps += connected
        agent_rows.append({
            "agent": hashlib.sha256(snapshot.id.encode("utf-8")).hexdigest()[:12],
            "active": active,
            "registeredApps": apps,
            "connectedApps": connected,
            "usage": usage,
        })
    agent_rows.sort(
        key=lambda row: sum(int(value) for value in row["usage"].values()),
        reverse=True,
    )
    daily = _daily_usage(
        now,
        days,
        today,
        totals,
        usage_agents,
        usage_apps,
    )
    return {
        "generatedAt": now.isoformat(),
        "usageDate": today,
        "registeredAgents": len(agents),
        "activeAgents": active_agents,
        "registeredApps": registered_apps,
        "connectedApps": connected_apps,
        "totals": dict(sorted(totals.items())),
        "daily": daily,
        "policy": _relay_policy(),
        "agents": agent_rows[:100],
        "agentsTruncated": len(agent_rows) > 100,
        "privacy": "Agent identifiers are one-way hashes; PBX and call content is excluded.",
    }


def _daily_usage(
    now: datetime,
    days: int,
    today: str,
    today_totals: dict[str, int],
    today_agents: int,
    today_apps: int,
) -> list[dict[str, object]]:
    rollups: list[dict[str, object]] = []
    for offset in range(max(1, min(days, 31))):
        usage_date = (now.date() - timedelta(days=offset)).isoformat()
        if usage_date == today:
            rollups.append({
                "date": usage_date,
                "agents": today_agents,
                "apps": today_apps,
                "totals": dict(sorted(today_totals.items())),
                "complete": False,
            })
            continue
        totals: dict[str, int] = defaultdict(int)
        agent_count = 0
        app_count = 0
        entities = (
            db.collection("usageDaily")
            .document(usage_date)
            .collection("entities")
            .stream()
        )
        for entity_snapshot in entities:
            entity = entity_snapshot.to_dict() or {}
            if entity.get("kind") == "agent":
                agent_count += 1
            elif entity.get("kind") == "app":
                app_count += 1
            usage = entity.get("usage")
            if not isinstance(usage, dict):
                continue
            for key, value in usage.items():
                if isinstance(value, (int, float)) and value >= 0:
                    totals[str(key)] += int(value)
        rollups.append({
            "date": usage_date,
            "agents": agent_count,
            "apps": app_count,
            "totals": dict(sorted(totals.items())),
            "complete": True,
        })
    return rollups


def _usage_login_page(error: str = "") -> str:
    message = (
        f'<p class="error">{html.escape(error)}</p>'
        if error else
        "<p>Enter the Relay administrator token. It is stored only in a secure, HTTP-only session cookie.</p>"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PBXSense Relay usage</title><style>{_usage_css()}</style></head>
<body><main class="login"><section><p class="eyebrow">PBXSense Relay</p><h1>Usage dashboard</h1>
{message}<form method="post" action="/admin/usage"><label>Administrator token
<input type="password" name="token" autocomplete="current-password" required></label>
<button type="submit">Open dashboard</button></form></section></main></body></html>"""


def _admin_page_headers() -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'unsafe-inline'; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        ),
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }


def _usage_dashboard_page(report: dict[str, object]) -> str:
    policy = report["policy"]
    totals = report["totals"]
    daily_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(row['date']))}{'' if row['complete'] else ' (today)'}</td>"
        f"<td>{row['agents']}</td><td>{row['apps']}</td>"
        f"<td>{row['totals'].get('heartbeats', 0):,}</td>"
        f"<td>{row['totals'].get('controlExchanges', 0):,}</td>"
        f"<td>{row['totals'].get('remoteSnapshotReads', 0):,}</td>"
        f"<td>{row['totals'].get('encryptedSnapshotsPublished', 0):,}</td>"
        f"<td>{row['totals'].get('encryptedSnapshotBytes', 0):,}</td>"
        "</tr>"
        for row in report["daily"]
    )
    agent_rows = "".join(
        "<tr>"
        f"<td><code>{html.escape(str(row['agent']))}</code></td>"
        f"<td>{'Active' if row['active'] else 'Inactive'}</td>"
        f"<td>{row['registeredApps']}</td><td>{row['connectedApps']}</td>"
        f"<td>{sum(int(value) for value in row['usage'].values()):,}</td>"
        "</tr>"
        for row in report["agents"]
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="300"><title>PBXSense Relay usage</title>
<style>{_usage_css()}</style></head><body><main><header><div><p class="eyebrow">PBXSense Relay {RELAY_VERSION}</p>
<h1>Usage dashboard</h1><p>Updated {html.escape(str(report['generatedAt']))}; refreshes every five minutes.</p></div>
<span class="status">Privacy-safe</span></header>
<section class="cards"><article><span>Active Agents</span><strong>{report['activeAgents']}</strong><small>{report['registeredAgents']} registered</small></article>
<article><span>Connected apps</span><strong>{report['connectedApps']}</strong><small>{report['registeredApps']} registered</small></article>
<article><span>Heartbeats today</span><strong>{totals.get('heartbeats', 0):,}</strong><small>30/{policy['agentLossSeconds']} sec presence</small></article>
<article><span>Remote reads today</span><strong>{totals.get('remoteSnapshotReads', 0):,}</strong><small>{policy['remotePollSeconds']} sec app policy</small></article></section>
<section><h2>Remotely delivered policy</h2><div class="policy">
<span>Presence <b>{policy['agentPresenceSeconds']} sec</b></span>
<span>Lost after <b>{policy['agentLossSeconds']} sec</b></span>
<span>App poll <b>{policy['remotePollSeconds']} sec</b></span>
<span>Control exchange <b>{policy['controlExchangeSeconds']} sec</b></span></div>
<p class="note">Presence is fixed for reliable Agent-down detection. App polling and control exchange are bounded server settings delivered in Relay responses.</p></section>
<section><h2>Daily rollups</h2><div class="table"><table><thead><tr><th>UTC date</th><th>Agents</th><th>Apps</th><th>Heartbeats</th><th>Control</th><th>Remote reads</th><th>Snapshots</th><th>Encrypted bytes</th></tr></thead>
<tbody>{daily_rows}</tbody></table></div></section>
<section><h2>Agent activity today</h2><div class="table"><table><thead><tr><th>Hashed Agent</th><th>Status</th><th>Apps</th><th>Connected</th><th>Operations</th></tr></thead>
<tbody>{agent_rows}</tbody></table></div><p class="note">{html.escape(str(report['privacy']))}</p></section>
</main></body></html>"""


def _usage_css() -> str:
    return """
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#07110f;color:#edf7f2}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#17362e 0,#07110f 42%);min-height:100vh}
main{width:min(1180px,calc(100% - 32px));margin:0 auto;padding:42px 0 80px}header{display:flex;justify-content:space-between;gap:24px;align-items:flex-start}
h1{font-size:clamp(32px,5vw,54px);margin:4px 0 8px}h2{margin:0 0 18px;font-size:22px}.eyebrow{color:#f1bd70;text-transform:uppercase;letter-spacing:.14em;font-size:12px;font-weight:800}
p{color:#a9bdb5}.status{background:#193f35;color:#8ce0c2;border:1px solid #285b4e;border-radius:999px;padding:8px 13px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:34px 0}article,section{background:#0e1d19;border:1px solid #203c34;border-radius:18px;padding:22px}
section{margin:16px 0}article span,article small{display:block;color:#99afa6}article strong{display:block;font-size:34px;margin:10px 0 5px}
.policy{display:flex;flex-wrap:wrap;gap:10px}.policy span{background:#152a24;border-radius:10px;padding:10px 13px;color:#a9bdb5}.policy b{color:#edf7f2}
.table{overflow:auto}table{width:100%;border-collapse:collapse;min-width:760px}th,td{text-align:left;padding:12px;border-bottom:1px solid #203c34;font-variant-numeric:tabular-nums}th{color:#8ce0c2;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
code{color:#f1bd70}.note{font-size:13px}.login{display:grid;place-items:center;min-height:100vh;padding:20px}.login section{width:min(460px,100%)}label{display:grid;gap:8px;color:#a9bdb5}
input{width:100%;padding:13px;border-radius:10px;border:1px solid #36554c;background:#07110f;color:#fff}button{margin-top:14px;border:0;border-radius:10px;padding:12px 16px;background:#e9ad5c;color:#191107;font-weight:800;cursor:pointer}.error{color:#ffaaa0}
@media(max-width:800px){.cards{grid-template-columns:repeat(2,1fr)}header{display:block}.status{display:inline-block;margin-top:12px}}
@media(max-width:480px){.cards{grid-template-columns:1fr}}
"""


def _decode_public_key(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(_padding(value)))


def _decode_signature(value: str) -> bytes:
    return base64.urlsafe_b64decode(_padding(value))


def _decode_bytes(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(_padding(value))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 value") from exc


def _bounded_base64(value: object, field: str, limit: int) -> str:
    text = _clean_text(value, field)
    if len(text) > limit:
        raise HTTPException(status_code=400, detail=f"Invalid {field}")
    _decode_bytes(text)
    return text


def _padding(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _clean_text(value: object, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail=f"{name} is required")
    return text


def _bounded_text(value: object, name: str, limit: int) -> str:
    text = _clean_text(value, name)
    if len(text) > limit:
        raise HTTPException(status_code=400, detail=f"{name} is too long")
    return text


def _optional_text(value: object, *, limit: int = 120) -> str:
    return str(value or "").strip()[:limit]


def _timestamp_text(value: object) -> str:
    return value.isoformat() if isinstance(value, datetime) else ""
