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
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs

import firebase_admin
from fastapi import FastAPI, HTTPException, Request
from firebase_admin import firestore, messaging
from google.api_core.exceptions import AlreadyExists
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
try:
    from .backend_worker import backend_worker
except ImportError:  # Cloud Run loads app.py as a top-level module.
    from backend_worker import backend_worker

try:
    from .request_auth import (
        verify_agent_signature, verify_secure_agent_signature,
        verify_activation_signatures, _decode_public_key,
    )
except ImportError:  # Cloud Run loads app.py as a top-level module.
    from request_auth import (
        verify_agent_signature, verify_secure_agent_signature,
        verify_activation_signatures, _decode_public_key,
    )

try:
    from .notification_delivery import (
        NotificationDelivery, AgentStatusDelivery, _recipient_digest, _retryable_fcm_failure,
        _device_wants_event, _unique_devices_by_token,
    )
except ImportError:  # Cloud Run loads app.py as a top-level module.
    from notification_delivery import (
        NotificationDelivery, AgentStatusDelivery, _recipient_digest, _retryable_fcm_failure,
        _device_wants_event, _unique_devices_by_token,
    )

try:
    from .notification_usage import NotificationUsageRecorder
except ImportError:  # Cloud Run loads app.py as a top-level module.
    from notification_usage import NotificationUsageRecorder

try:
    from .usage_accounting import UsageAccounting, _current_usage, _usage_identity
    from .usage_dashboard import _usage_dashboard_page as render_usage_dashboard, _usage_css
except ImportError:  # Cloud Run loads app.py as a top-level module.
    from usage_accounting import UsageAccounting, _current_usage, _usage_identity
    from usage_dashboard import _usage_dashboard_page as render_usage_dashboard, _usage_css

try:
    from .cost_model import RelayCostModel
    from .usage_report import UsageReporter
except ImportError:  # Cloud Run loads app.py as a top-level module.
    from cost_model import RelayCostModel
    from usage_report import UsageReporter

try:
    from .authentication import RelayAuthentication
    from .routes import create_relay_router
except ImportError:  # Cloud Run loads app.py as a top-level module.
    from authentication import RelayAuthentication
    from routes import create_relay_router


RELAY_VERSION = "0.5.27"
app = FastAPI(title="PBXSense Push Relay", version=RELAY_VERSION)
firebase_admin.initialize_app(options={"projectId": os.getenv("GOOGLE_CLOUD_PROJECT")})
db = firestore.client()
_admin_token = os.getenv("PBXSENSE_RELAY_ADMIN_TOKEN", "").strip()
_ticket_secret = os.getenv("PBXSENSE_RELAY_TICKET_SECRET", "").strip()
_enrollment_mode = os.getenv(
    "PBXSENSE_RELAY_ENROLLMENT_MODE", "closed"
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
MAX_AGENTS_PER_ACCOUNT = max(
    1, min(1000, int(os.getenv("PBXSENSE_RELAY_MAX_AGENTS_PER_ACCOUNT", "10")))
)
REMOTE_APP_POLL_SECONDS = max(
    15, min(300, int(os.getenv("PBXSENSE_RELAY_REMOTE_APP_POLL_SECONDS", "60")))
)
CONTROL_EXCHANGE_SECONDS = max(
    60, min(900, int(os.getenv("PBXSENSE_RELAY_CONTROL_EXCHANGE_SECONDS", "300")))
)
ADMIN_COOKIE_TTL_SECONDS = 8 * 60 * 60


_cost_model = RelayCostModel.from_environment()
_request_windows: dict[str, deque[float]] = defaultdict(deque)
_event_windows: dict[str, deque[float]] = defaultdict(deque)
_window_lock = threading.Lock()
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


def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "pbxsense-push-relay",
        "version": RELAY_VERSION,
        "enrollmentMode": _enrollment_mode,
    }


@backend_worker
async def relay_usage(request: Request) -> dict[str, object]:
    """Return privacy-safe fleet usage and durable daily rollups."""
    _require_admin(request)
    return _usage_report()


@backend_worker
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


@backend_worker
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
        max_age=ADMIN_COOKIE_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="strict",
    )
    return response


@backend_worker
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


@backend_worker
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


@backend_worker
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
    logger.info(
        "activation_claimed agent_id=%s reused=%s",
        _safe_log_identifier(agent_id),
        claim["reusedAgent"],
    )
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
        account_id = str(activation.get("accountId", ""))
        if account_id:
            account_agents = (
                db.collection("agents")
                .where("accountId", "==", account_id)
                .limit(MAX_AGENTS_PER_ACCOUNT)
                .get(transaction=transaction)
            )
            if len(account_agents) >= MAX_AGENTS_PER_ACCOUNT:
                raise HTTPException(
                    status_code=409,
                    detail="This account has reached its Agent limit",
                )

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
            "activationId": activation_ref.id,
            "siteId": site_id,
            "accessTokenHash": hashlib.sha256(relay_access_token.encode("utf-8")).hexdigest(),
            **({"encryptionPublicKey": encryption_public_key} if encryption_public_key else {}),
            "createdAt": firestore.SERVER_TIMESTAMP,
            "updatedAt": firestore.SERVER_TIMESTAMP,
            "lastConnectedAt": firestore.SERVER_TIMESTAMP,
            "expiresAt": now + timedelta(days=90),
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


@backend_worker
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


@backend_worker
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
            "mutedSignalIds": _bounded_string_list(body.get("mutedSignalIds"), "mutedSignalIds"),
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
            "expiresAt": datetime.now(timezone.utc) + timedelta(days=90),
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


@backend_worker
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
                "activationId": str(device.get("activationId", "")),
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


@backend_worker
async def revoke_device(agent_id: str, request: Request) -> dict[str, str]:
    body, _ = await _authenticate_agent(agent_id, request)
    requested_device_id = _optional_identifier(body.get("relayDeviceId"))
    token = _optional_text(body.get("fcmToken"))
    if not requested_device_id and not token:
        raise HTTPException(status_code=400, detail="Device identity is required")
    device_id = requested_device_id or hashlib.sha256(token.encode("utf-8")).hexdigest()
    _delete_device_registration(agent_id, device_id)
    return {"status": "revoked"}


@backend_worker
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


@backend_worker
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


@backend_worker
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
        # Keep old Agent envelopes readable by old apps during rollout, while
        # new apps require and verify this signature against their QR-pinned key.
        if envelope.get("signature"):
            safe_envelope["signature"] = _bounded_base64(
                envelope["signature"], "signature", 100
            )
        devices_ref.document(device_id).collection("secureSnapshots").document("latest").set(safe_envelope)
        devices_ref.document(device_id).update(
            {
                "secureSnapshotUpdatedAt": firestore.SERVER_TIMESTAMP,
                **_usage_update(
                    devices_ref.document(device_id),
                    device,
                    "app",
                    f"{agent_id}/{device_id}",
                    encryptedSnapshotsPublished=1,
                    encryptedSnapshotBytes=len(ciphertext),
                ),
            }
        )
        stored += 1
    return {"stored": stored}


@backend_worker
async def read_secure_snapshot(agent_id: str, device_id: str, request: Request) -> dict[str, object]:
    device_ref, device = _authenticate_relay_device(agent_id, device_id, request)
    agent_snapshot = db.collection("agents").document(agent_id).get()
    agent = agent_snapshot.to_dict() if agent_snapshot.exists else None
    last_seen_at = agent.get("lastSeenAt") if agent else None
    if (
        not isinstance(last_seen_at, datetime)
        or last_seen_at < datetime.now(timezone.utc) - timedelta(seconds=AGENT_LOSS_TIMEOUT_SECONDS)
    ):
        device_ref.update({
            "lastConnectedAt": firestore.SERVER_TIMESTAMP,
            **_usage_update(
                device_ref,
                device,
                "app",
                f"{agent_id}/{device_id}",
                remoteSnapshotReads=1,
                remoteSnapshotUnavailable=1,
            ),
        })
        return {"available": False, "reason": "agentOffline"}
    snapshot = device_ref.collection("secureSnapshots").document("latest").get()
    if not snapshot.exists:
        device_ref.update({
            "lastConnectedAt": firestore.SERVER_TIMESTAMP,
            **_usage_update(
                device_ref,
                device,
                "app",
                f"{agent_id}/{device_id}",
                remoteSnapshotReads=1,
                remoteSnapshotUnavailable=1,
            ),
        })
        return {"available": False}
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
    envelope = snapshot.to_dict() or {}
    envelope.pop("updatedAt", None)
    return {
        "available": True,
        "agentLastSeenAt": last_seen_at.isoformat(),
        "envelope": envelope,
        "policy": _relay_policy(),
    }


@backend_worker
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
            "mutedSignalIds": _bounded_string_list(body.get("mutedSignalIds"), "mutedSignalIds"),
            "platform": _bounded_text(
                body.get("platform", "android"), "platform", 32
            ),
            "appVersion": _optional_text(body.get("appVersion")),
            "deviceModel": _optional_text(body.get("deviceModel")),
            "deviceName": _optional_text(body.get("deviceName")),
            "osVersion": _optional_text(body.get("osVersion")),
            "updatedAt": firestore.SERVER_TIMESTAMP,
            "lastConnectedAt": firestore.SERVER_TIMESTAMP,
            "expiresAt": datetime.now(timezone.utc) + timedelta(days=90),
        },
        merge=True,
    )
    _assign_device_token_transaction(db.transaction(), device_ref, fcm_token)
    logger.info(
        "device_self_registered agent_id=%s device_id=%s",
        _safe_log_identifier(agent_id),
        _safe_log_identifier(device_id),
    )
    return {"delivered": True, "deviceId": device_id}


@backend_worker
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


@backend_worker
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


@backend_worker
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
    db.collection("relayOperations").document("current").set(
        {
            "lastHeartbeatSweepAt": firestore.SERVER_TIMESTAMP,
            "lastHeartbeatSweepLost": lost,
        },
        merge=True,
    )
    return {"lost": lost}


@backend_worker
async def remove_device(agent_id: str, request: Request) -> dict[str, str]:
    body, _ = await _authenticate_agent(agent_id, request, touch_presence=False)
    fcm_token = _bounded_text(body.get("fcmToken"), "fcmToken", 4096)
    device_id = hashlib.sha256(fcm_token.encode("utf-8")).hexdigest()
    _delete_device_registration(agent_id, device_id)
    return {"status": "removed"}


@backend_worker
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
    now = datetime.now(timezone.utc)
    owner = secrets.token_urlsafe(18)
    fingerprint = hashlib.sha256(json.dumps(
        [signal_id, title, body, category, importance, notification_tag],
        separators=(",", ":"),
    ).encode()).hexdigest()
    quota_ref = db.collection("agents").document(agent_id).collection("rateLimits").document(f"events_{now:%Y%m%d%H}")
    delivery = _claim_event_delivery(db.transaction(), event_ref, quota_ref,
                                     agent_id, fingerprint, owner, now)
    if delivery is None:
        return {"status": "duplicate", "sent": 0}
    quota_count = int(delivery["quotaCount"])
    completed = set(delivery.get("completedRecipients", []))

    devices = [_device_record(document) for document in
        db.collection("agents").document(agent_id).collection("devices").stream()]
    return NotificationDelivery(
        messaging=messaging,
        checkpoint=lambda completed, done: _finish_event_delivery(
            db.transaction(), event_ref, owner, completed, done,
        ),
        cleanup=_remove_invalid_tokens, record_usage=_record_notification_usage,
        log=logger.info, safe_identifier=_safe_log_identifier,
    ).deliver(
        agent_id=agent_id, agent=agent, devices=devices, completed=completed,
        quota_count=quota_count, event_id=event_id, signal_id=signal_id,
        title=title, body=body, category=category, importance=importance,
        notification_tag=notification_tag, now=datetime.now(timezone.utc),
    )


@firestore.transactional
def _claim_event_delivery(transaction: Any, event_ref: Any, quota_ref: Any,
                          agent_id: str, fingerprint: str, owner: str,
                          now: datetime) -> dict[str, Any] | None:
    snapshot = event_ref.get(transaction=transaction)
    row = (snapshot.to_dict() or {}) if snapshot.exists else {}
    if snapshot.exists:
        if row.get("agentId") != agent_id:
            raise HTTPException(status_code=409, detail="Event belongs to another Agent")
        # Legacy records lack a lifecycle and remain deduplicated during upgrade.
        if row.get("state", "completed") == "completed":
            return None
        if row.get("fingerprint") != fingerprint:
            raise HTTPException(status_code=409, detail="Event payload changed")
        if row.get("leaseUntil", now) > now:
            raise HTTPException(status_code=503, detail="Event delivery is in progress")
    else:
        quota = quota_ref.get(transaction=transaction)
        count = int((quota.to_dict() or {}).get("count", 0)) if quota.exists else 0
        if count >= MAX_EVENTS_PER_AGENT_PER_HOUR:
            raise HTTPException(status_code=429, detail="Agent notification quota exceeded")
        transaction.set(quota_ref, {"count": count + 1,
                                   "updatedAt": firestore.SERVER_TIMESTAMP,
                                   "expiresAt": now + timedelta(hours=2)})
        row = {"agentId": agent_id, "fingerprint": fingerprint,
               "quotaCount": count + 1, "completedRecipients": [],
               "createdAt": firestore.SERVER_TIMESTAMP,
               "expiresAt": now + timedelta(days=2)}
    row.update({"state": "sending", "owner": owner,
                "leaseUntil": now + timedelta(seconds=60)})
    transaction.set(event_ref, row)
    return row


@firestore.transactional
def _finish_event_delivery(transaction: Any, event_ref: Any, owner: str,
                           completed: set[str], done: bool) -> None:
    snapshot = event_ref.get(transaction=transaction)
    row = snapshot.to_dict() or {}
    if row.get("owner") != owner:
        raise HTTPException(status_code=503, detail="Event delivery lease changed")
    transaction.update(event_ref, {"completedRecipients": sorted(completed),
                                  "state": "completed" if done else "pending",
                                  "leaseUntil": datetime.now(timezone.utc)})


def _relay_auth() -> RelayAuthentication:
    return RelayAuthentication(
        db=db, server_timestamp=firestore.SERVER_TIMESTAMP, already_exists=AlreadyExists,
        identifier=_bounded_identifier, max_snapshot_bytes=MAX_SECURE_SNAPSHOT_BYTES,
        admin_token=_admin_token, ticket_secret=_ticket_secret, admin_cookie=_admin_cookie,
        admin_cookie_ttl=ADMIN_COOKIE_TTL_SECONDS, clock=time.time,
        now=lambda: datetime.now(timezone.utc),
    )


async def _authenticate_agent(
    agent_id: str,
    request: Request,
    *,
    touch_presence: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return await _relay_auth().authenticate_agent(agent_id, request, touch_presence=touch_presence)


async def _require_replay_protected_signature(
    agent_id: str,
    agent: dict[str, Any],
    request: Request,
) -> None:
    return await _relay_auth().require_replay_protected_signature(agent_id, agent, request)


def _bounded_identifier(value: object, field: str) -> str:
    text = _clean_text(value, field)
    if len(text) > 96 or not text.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise HTTPException(status_code=400, detail=f"Invalid {field}")
    return text


def _safe_log_identifier(value: object) -> str:
    """Return a bounded single-line identifier even for defense-in-depth logs."""
    single_line = str(value).replace("\r", "_").replace("\n", "_")[:96]
    return "".join(
        character
        for character in single_line
        if character.isalnum() or character in {"-", "_", "."}
    ) or "invalid"


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
    with _window_lock:
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
    return _relay_auth().verify_public_key_request(public_key, request)


def _sign_enrollment_ticket(payload: dict[str, object]) -> str:
    return _relay_auth().sign_enrollment_ticket(payload)


def _verify_enrollment_ticket(ticket: str) -> dict[str, object]:
    return _relay_auth().verify_enrollment_ticket(ticket)


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


def _record_notification_usage(
    agent_id: str,
    agent: dict[str, object],
    *,
    eligible: int,
    accepted: int,
    failed: int,
    invalid: int,
    latency_ms: int,
    no_recipients: int = 0,
    transport_errors: int = 0,
    quota_count: int | None = None,
) -> None:
    NotificationUsageRecorder(
        db=db, server_timestamp=firestore.SERVER_TIMESTAMP,
        usage_update=_usage_update, now=lambda: datetime.now(timezone.utc),
    ).record(
        agent_id, agent, eligible=eligible, accepted=accepted, failed=failed,
        invalid=invalid, latency_ms=latency_ms, no_recipients=no_recipients,
        transport_errors=transport_errors, quota_count=quota_count,
    )


def _send_agent_status(agent_id: str, title: str, body: str) -> None:
    agent_snapshot = db.collection("agents").document(agent_id).get()
    agent = agent_snapshot.to_dict() if agent_snapshot.exists else {}
    now = datetime.now(timezone.utc)
    devices = [_device_record(document) for document in
        db.collection("agents").document(agent_id).collection("devices").stream()]
    AgentStatusDelivery(
        messaging=messaging, cleanup=_remove_invalid_tokens,
        record_usage=_record_notification_usage, log=logger.info,
        safe_identifier=_safe_log_identifier,
    ).deliver(
        agent_id=agent_id, agent=agent, devices=devices,
        title=title, body=body, now=now,
    )


def _device_record(document: Any) -> dict[str, Any]:
    device = document.to_dict() or {}
    device["_documentId"] = document.id
    return device


def _authenticate_relay_device(
    agent_id: str, device_id: str, request: Request
) -> tuple[Any, dict[str, Any]]:
    return _relay_auth().authenticate_relay_device(agent_id, device_id, request)


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
    return _relay_auth().admin_authenticated(request)


def _admin_cookie_value(expires_at: int | None = None) -> str:
    return _relay_auth().admin_cookie_value(expires_at)


def _admin_cookie_valid(value: str, now: int | None = None) -> bool:
    return _relay_auth().admin_cookie_valid(value, now)


def _require_admin(request: Request) -> None:
    return _relay_auth().require_admin(request)


def _relay_policy() -> dict[str, int]:
    return {
        "agentPresenceSeconds": 30,
        "agentLossSeconds": AGENT_LOSS_TIMEOUT_SECONDS,
        "controlExchangeSeconds": CONTROL_EXCHANGE_SECONDS,
        "remotePollSeconds": REMOTE_APP_POLL_SECONDS,
        "maxAppsPerAgent": MAX_DEVICES_PER_AGENT,
        "maxEventsPerAgentHour": MAX_EVENTS_PER_AGENT_PER_HOUR,
        "maxAgentsPerAccount": MAX_AGENTS_PER_ACCOUNT,
    }


def _consume_durable_event_quota(agent_id: str) -> int:
    """Enforce notification limits across Cloud Run instances and restarts."""
    now = datetime.now(timezone.utc)
    quota_ref = (
        db.collection("agents").document(agent_id)
        .collection("rateLimits").document(f"events_{now:%Y%m%d%H}")
    )
    return _increment_durable_quota(
        db.transaction(), quota_ref, MAX_EVENTS_PER_AGENT_PER_HOUR, now
    )


@firestore.transactional
def _increment_durable_quota(
    transaction: Any, quota_ref: Any, limit: int, now: datetime
) -> int:
    snapshot = quota_ref.get(transaction=transaction)
    count = int((snapshot.to_dict() or {}).get("count", 0)) if snapshot.exists else 0
    if count >= limit:
        raise HTTPException(
            status_code=429,
            detail="Agent notification quota exceeded",
        )
    transaction.set(
        quota_ref,
        {
            "count": count + 1,
            "updatedAt": firestore.SERVER_TIMESTAMP,
            "expiresAt": now + timedelta(hours=2),
        },
    )
    return count + 1


def _usage_accounting() -> UsageAccounting:
    return UsageAccounting(
        db=db, server_timestamp=firestore.SERVER_TIMESTAMP,
        increment=firestore.Increment, now=lambda: datetime.now(timezone.utc),
    )


def _usage_update(
    reference: Any,
    existing: dict[str, object],
    entity_kind: str,
    entity_id: str,
    **increments: int,
) -> dict[str, object]:
    return _usage_accounting().update(
        reference, existing, entity_kind, entity_id, **increments,
    )


def _archive_usage(
    reference: Any,
    document: dict[str, object],
    entity_kind: str,
    entity_id: str,
    today: str,
) -> None:
    _usage_accounting().archive(reference, document, entity_kind, entity_id, today)


def _estimated_relay_cost(usage: dict[str, int]) -> dict[str, float | int]:
    return _cost_model.estimate(usage)


def _usage_report(days: int = 7) -> dict[str, object]:
    return UsageReporter(
        db=db, archive=_archive_usage, daily=_daily_usage, cost=_cost_model,
        policy=_relay_policy, now=lambda: datetime.now(timezone.utc),
        agent_loss_seconds=AGENT_LOSS_TIMEOUT_SECONDS,
        max_events_per_hour=MAX_EVENTS_PER_AGENT_PER_HOUR,
    ).report(days)


def _daily_usage(
    now: datetime,
    days: int,
    today: str,
    today_totals: dict[str, int],
    today_agents: int,
    today_apps: int,
) -> list[dict[str, object]]:
    return _usage_accounting().daily(
        now, days, today, today_totals, today_agents, today_apps,
    )


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
    return render_usage_dashboard(
        report, relay_version=RELAY_VERSION, cost_estimator=_estimated_relay_cost,
    )


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


def _bounded_string_list(
    value: object, name: str, *, count: int = 100, limit: int = 160
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > count:
        raise HTTPException(status_code=400, detail=f"{name} must be a bounded list")
    return [_bounded_text(item, name, limit) for item in value]


def _timestamp_text(value: object) -> str:
    return value.isoformat() if isinstance(value, datetime) else ""

app.include_router(create_relay_router({
    "health": health,
    "relay_usage": relay_usage,
    "usage_dashboard": usage_dashboard,
    "usage_dashboard_login": usage_dashboard_login,
    "create_enrollment_ticket": create_enrollment_ticket,
    "create_activation": create_activation,
    "claim_activation": claim_activation,
    "activation_status": activation_status,
    "register_device": register_device,
    "list_devices": list_devices,
    "revoke_device": revoke_device,
    "heartbeat": heartbeat,
    "secure_exchange": secure_exchange,
    "publish_secure_snapshots": publish_secure_snapshots,
    "read_secure_snapshot": read_secure_snapshot,
    "register_own_device": register_own_device,
    "revoke_own_device": revoke_own_device,
    "queue_secure_ping": queue_secure_ping,
    "sweep_agent_heartbeats": sweep_agent_heartbeats,
    "remove_device": remove_device,
    "publish_event": publish_event,
}))
