"""PBXSense's keyless, multi-site FCM relay for Cloud Run.

Cloud Run obtains Google credentials from its attached service account. Agents
authenticate with per-installation Ed25519 keys and never hold Firebase or
Google service-account credentials.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

import firebase_admin
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from firebase_admin import firestore, messaging
from google.api_core.exceptions import AlreadyExists
from starlette.responses import JSONResponse


RELAY_VERSION = "0.5.1"
app = FastAPI(title="PBXSense Push Relay", version=RELAY_VERSION)
firebase_admin.initialize_app(options={"projectId": os.getenv("GOOGLE_CLOUD_PROJECT")})
db = firestore.client()
_admin_token = os.getenv("PBXSENSE_RELAY_ADMIN_TOKEN", "").strip()
_ticket_secret = os.getenv(
    "PBXSENSE_RELAY_TICKET_SECRET", _admin_token
).strip()
_enrollment_mode = os.getenv(
    "PBXSENSE_RELAY_ENROLLMENT_MODE", "open"
).strip().lower()
if _enrollment_mode not in {"open", "ticket", "closed"}:
    raise RuntimeError(
        "PBXSENSE_RELAY_ENROLLMENT_MODE must be open, ticket, or closed"
    )
_require_signed_existing_activations = os.getenv(
    "PBXSENSE_RELAY_REQUIRE_SIGNED_EXISTING_ACTIVATIONS",
    "true" if _enrollment_mode in {"ticket", "closed"} else "false",
).strip().lower() in {"1", "true", "yes", "on"}
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


@app.middleware("http")
async def bound_public_requests(request: Request, call_next: Any) -> Any:
    """Reject obvious floods before they can generate Firestore operations."""
    content_length = request.headers.get("content-length", "")
    if content_length.isdigit():
        maximum = (
            MAX_SECURE_SNAPSHOT_BYTES
            if request.url.path.endswith("/secure/snapshots")
            else 1024 * 1024
        )
        if int(content_length) > maximum:
            return JSONResponse(
                status_code=413, content={"detail": "Request body is too large"}
            )
    client = _client_key(request)
    is_activation = request.url.path == "/v1/activations"
    limit = 6 if is_activation else 120
    if not _consume_window(
        _client_window(client), limit=limit, seconds=60
    ):
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
    """Return privacy-safe current-day usage for operational cost tuning."""
    _require_admin(request)
    now = datetime.now(timezone.utc)
    today = now.date().isoformat()
    active_cutoff = now - timedelta(seconds=AGENT_LOSS_TIMEOUT_SECONDS)
    connected_cutoff = now - timedelta(seconds=120)
    totals: dict[str, int] = defaultdict(int)
    agent_rows: list[dict[str, object]] = []
    registered_apps = 0
    connected_apps = 0
    active_agents = 0
    agents = list(db.collection("agents").limit(1000).stream())
    for snapshot in agents:
        agent = snapshot.to_dict() or {}
        usage = _current_usage(agent, today)
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
            apps += 1
            device_usage = _current_usage(device, today)
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
    return {
        "generatedAt": now.isoformat(),
        "usageDate": today,
        "registeredAgents": len(agents),
        "activeAgents": active_agents,
        "registeredApps": registered_apps,
        "connectedApps": connected_apps,
        "totals": dict(sorted(totals.items())),
        "policy": _relay_policy(),
        "agents": agent_rows[:100],
        "privacy": "Agent identifiers are one-way hashes; PBX and call content is excluded.",
    }


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
    if existing_agents and _require_signed_existing_activations:
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
    activation_ref = db.collection("activations").document(activation_id)
    snapshot = activation_ref.get()
    if not snapshot.exists:
        raise HTTPException(status_code=401, detail="Unknown activation")
    activation = snapshot.to_dict() or {}
    valid_secret = hmac.compare_digest(
        str(activation.get("secretHash", "")),
        hashlib.sha256(secret.encode("utf-8")).hexdigest(),
    )
    expires_at = activation.get("expiresAt")
    if not valid_secret or activation.get("claimedAt") or not isinstance(expires_at, datetime) or expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Expired or used activation")
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

    existing_agents = list(
        db.collection("agents")
        .where("publicKey", "==", activation["publicKey"])
        .limit(1)
        .stream()
    )
    if existing_agents:
        existing = existing_agents[0]
        agent = existing.to_dict() or {}
        if agent.get("revoked"):
            raise HTTPException(status_code=403, detail="This Agent identity has been revoked")
        existing_site_id = str(agent.get("siteId", ""))
        if not existing_site_id:
            raise HTTPException(status_code=500, detail="Existing Agent has no site identity")
        batch = db.batch()
        batch.update(
            activation_ref,
            {
                "claimedAt": firestore.SERVER_TIMESTAMP,
                "agentId": existing.id,
                "siteId": existing_site_id,
                "reusedAgent": True,
            },
        )
        batch.commit()
        logger.info("activation_claimed agent_id=%s reused=true", existing.id)
        _create_relay_device(
            existing.id, existing_site_id, relay_device_id,
            relay_access_token, encryption_public_key,
        )
        result = {
            "status": "claimed", "agentId": existing.id,
            "siteId": existing_site_id,
        }
        result.update({"deviceId": relay_device_id, "deviceAccessToken": relay_access_token})
        return result

    site_name = _bounded_text(
        body.get("siteName", activation.get("displayName")), "siteName", 120
    )
    site_id = f"site_{secrets.token_urlsafe(10)}"
    agent_id = f"agent_{secrets.token_urlsafe(12)}"
    batch = db.batch()
    batch.create(db.collection("sites").document(site_id), {"name": site_name, "createdAt": firestore.SERVER_TIMESTAMP})
    batch.create(db.collection("agents").document(agent_id), {
        "tenantId": site_id,
        "siteId": site_id,
        "siteName": site_name,
        "displayName": activation["displayName"],
        "publicKey": activation["publicKey"],
        "enrolledAt": firestore.SERVER_TIMESTAMP,
        "lastSeenAt": firestore.SERVER_TIMESTAMP,
        "revoked": False,
        **({"accountId": activation["accountId"]} if activation.get("accountId") else {}),
    })
    batch.update(activation_ref, {"claimedAt": firestore.SERVER_TIMESTAMP, "agentId": agent_id, "siteId": site_id})
    ticket_id = str(activation.get("enrollmentTicketId", ""))
    if _enrollment_mode == "ticket":
        ticket_expires_at = activation.get("enrollmentTicketExpiresAt")
        if (
            not ticket_id
            or not isinstance(ticket_expires_at, datetime)
            or ticket_expires_at < datetime.now(timezone.utc)
        ):
            raise HTTPException(status_code=401, detail="Enrollment ticket expired")
        batch.create(
            db.collection("enrollmentTickets").document(ticket_id),
            {
                "accountId": activation.get("accountId", ""),
                "usedAt": firestore.SERVER_TIMESTAMP,
                "expiresAt": ticket_expires_at,
            },
        )
    try:
        batch.commit()
    except AlreadyExists as exc:
        raise HTTPException(
            status_code=401, detail="Enrollment ticket was already used"
        ) from exc
    _create_relay_device(
        agent_id, site_id, relay_device_id,
        relay_access_token, encryption_public_key,
    )
    logger.info("activation_claimed agent_id=%s reused=false", agent_id)
    result = {"status": "claimed", "agentId": agent_id, "siteId": site_id}
    result.update({"deviceId": relay_device_id, "deviceAccessToken": relay_access_token})
    return result


def _create_relay_device(
    agent_id: str, site_id: str, device_id: str,
    access_token: str, encryption_public_key: str,
) -> None:
    _require_device_capacity(agent_id)
    db.collection("agents").document(agent_id).collection("devices").document(device_id).create({
        "siteId": site_id,
        "accessTokenHash": hashlib.sha256(access_token.encode("utf-8")).hexdigest(),
        **({"encryptionPublicKey": encryption_public_key} if encryption_public_key else {}),
        "createdAt": firestore.SERVER_TIMESTAMP,
        "updatedAt": firestore.SERVER_TIMESTAMP,
        "lastConnectedAt": firestore.SERVER_TIMESTAMP,
        "expiresAt": datetime.now(timezone.utc) + timedelta(days=30),
        "meaningfulEnabled": True,
        "activityEnabled": True,
    })


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
    if not devices_ref.document(device_id).get().exists:
        _require_device_capacity(agent_id)
    devices_ref.document(device_id).set(
        {
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
        merge=True,
    )
    # Keep an O(1) ownership pointer for this secret FCM token. This migrates a
    # previous registration even when an Agent rebuild changed its identity,
    # without a collection-group query or an additional Firestore index.
    token_ref = db.collection("deviceTokens").document(
        hashlib.sha256(fcm_token.encode("utf-8")).hexdigest()
    )
    previous = token_ref.get()
    previous_path = str((previous.to_dict() or {}).get("devicePath", "")) \
        if previous.exists else ""
    current_path = devices_ref.document(device_id).path
    if previous_path and previous_path != current_path:
        previous_ref = db.document(previous_path)
        if previous_ref.get().exists:
            previous_ref.delete()
    token_ref.set({
        "devicePath": current_path,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    })
    return {"status": "registered", "deviceId": device_id}


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
        **_usage_update(agent, heartbeats=1),
    })
    return {"status": "ok", "policy": _relay_policy()}


@app.post("/v1/agents/{agent_id}/secure/exchange")
async def secure_exchange(agent_id: str, request: Request) -> dict[str, object]:
    """Exchange bounded control frames over an outbound-only Agent session."""
    body, agent = await _authenticate_agent(agent_id, request, touch_presence=False)
    await _require_replay_protected_signature(agent_id, agent, request)
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
        **_usage_update(agent, controlExchanges=1),
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
    await _require_replay_protected_signature(agent_id, agent, request)
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
                device,
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
        **_usage_update(device, remoteSnapshotReads=1),
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
    device_ref, device = _authenticate_relay_device(agent_id, device_id, request)
    body = await _json_body(request)
    fcm_token = _bounded_text(body.get("fcmToken"), "fcmToken", 4096)
    previous_token = str(device.get("fcmToken", ""))
    if previous_token and previous_token != fcm_token:
        previous_token_ref = db.collection("deviceTokens").document(
            hashlib.sha256(previous_token.encode("utf-8")).hexdigest()
        )
        previous_token_snapshot = previous_token_ref.get()
        if (
            previous_token_snapshot.exists
            and str((previous_token_snapshot.to_dict() or {}).get("devicePath", ""))
            == device_ref.path
        ):
            previous_token_ref.delete()
    device_ref.set(
        {
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
            "updatedAt": firestore.SERVER_TIMESTAMP,
            "lastConnectedAt": firestore.SERVER_TIMESTAMP,
            "expiresAt": datetime.now(timezone.utc) + timedelta(days=30),
        },
        merge=True,
    )
    token_ref = db.collection("deviceTokens").document(
        hashlib.sha256(fcm_token.encode("utf-8")).hexdigest()
    )
    previous = token_ref.get()
    previous_path = str((previous.to_dict() or {}).get("devicePath", "")) \
        if previous.exists else ""
    current_path = device_ref.path
    if previous_path and previous_path != current_path:
        previous_ref = db.document(previous_path)
        if previous_ref.get().exists:
            previous_ref.delete()
    token_ref.set({
        "devicePath": current_path,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    })
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
    _delete_device_registration(agent_id, device_id, device=device)
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
            notification=messaging.AndroidNotification(tag=event_id),
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
    candidate = forwarded.split(",", 1)[0].strip() if forwarded else ""
    if candidate:
        return candidate[:64]
    return str(request.client.host if request.client else "unknown")[:64]


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


def _require_device_capacity(agent_id: str) -> None:
    devices = (
        db.collection("agents")
        .document(agent_id)
        .collection("devices")
        .limit(MAX_DEVICES_PER_AGENT)
        .stream()
    )
    if sum(1 for _ in devices) >= MAX_DEVICES_PER_AGENT:
        raise HTTPException(
            status_code=409,
            detail=f"This Agent has reached its {MAX_DEVICES_PER_AGENT}-app limit",
        )


def _delete_device_registration(
    agent_id: str,
    device_id: str,
    *,
    device: dict[str, Any] | None = None,
) -> None:
    device_ref = (
        db.collection("agents").document(agent_id)
        .collection("devices").document(device_id)
    )
    if device is None:
        snapshot = device_ref.get()
        device = (snapshot.to_dict() or {}) if snapshot.exists else {}
    fcm_token = str(device.get("fcmToken", ""))
    device_ref.delete()
    if not fcm_token:
        return
    token_ref = db.collection("deviceTokens").document(
        hashlib.sha256(fcm_token.encode("utf-8")).hexdigest()
    )
    pointer = token_ref.get()
    if pointer.exists and str((pointer.to_dict() or {}).get("devicePath", "")) == device_ref.path:
        token_ref.delete()


def _remove_invalid_tokens(agent_id: str, devices: list[dict[str, Any]], responses: list[Any]) -> int:
    removed = 0
    for device, response in zip(devices, responses, strict=True):
        if response.success or not isinstance(response.exception, messaging.UnregisteredError):
            continue
        device_id = str(device.get("_documentId", ""))
        if device_id:
            _delete_device_registration(agent_id, device_id, device=device)
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


def _usage_update(existing: dict[str, object], **increments: int) -> dict[str, object]:
    """Build counters that reuse an endpoint's existing Firestore write."""
    today = datetime.now(timezone.utc).date().isoformat()
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
