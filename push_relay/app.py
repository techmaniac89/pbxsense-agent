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
from datetime import datetime, timedelta, timezone
from typing import Any

import firebase_admin
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from firebase_admin import firestore, messaging
from google.api_core.exceptions import AlreadyExists


app = FastAPI(title="PBXSense Push Relay", version="0.1.1")
firebase_admin.initialize_app(options={"projectId": os.getenv("GOOGLE_CLOUD_PROJECT")})
db = firestore.client()
_admin_token = os.getenv("PBXSENSE_RELAY_ADMIN_TOKEN", "").strip()
AGENT_LOSS_TIMEOUT_SECONDS = 60
logger = logging.getLogger(__name__)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "pbxsense-push-relay"}


@app.post("/v1/activations")
async def create_activation(request: Request) -> dict[str, str]:
    """Create the opaque, short-lived capability embedded in the Agent QR."""
    body = await _json_body(request)
    public_key = _clean_text(body.get("publicKey"), "publicKey")
    display_name = _clean_text(body.get("displayName"), "displayName")
    _decode_public_key(public_key)
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
        }
    )
    return {"activationId": activation_id, "activationSecret": activation_secret, "expiresAt": expires_at.isoformat()}


@app.post("/v1/activations/{activation_id}/claim")
async def claim_activation(activation_id: str, request: Request) -> dict[str, str]:
    body = await _json_body(request)
    secret = _clean_text(body.get("activationSecret"), "activationSecret")
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
        return {"status": "claimed", "agentId": existing.id, "siteId": existing_site_id}

    site_name = _clean_text(body.get("siteName", activation.get("displayName")), "siteName")
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
    })
    batch.update(activation_ref, {"claimedAt": firestore.SERVER_TIMESTAMP, "agentId": agent_id, "siteId": site_id})
    batch.commit()
    logger.info("activation_claimed agent_id=%s reused=false", agent_id)
    return {"status": "claimed", "agentId": agent_id, "siteId": site_id}


@app.post("/v1/activations/{activation_id}/status")
async def activation_status(activation_id: str, request: Request) -> dict[str, object]:
    body = await _json_body(request)
    secret = _clean_text(body.get("activationSecret"), "activationSecret")
    snapshot = db.collection("activations").document(activation_id).get()
    activation = snapshot.to_dict() if snapshot.exists else None
    if not activation or not hmac.compare_digest(
        str(activation.get("secretHash", "")), hashlib.sha256(secret.encode("utf-8")).hexdigest()
    ):
        raise HTTPException(status_code=401, detail="Unknown activation")
    return {"claimed": bool(activation.get("claimedAt")), "agentId": activation.get("agentId", "")}


@app.post("/v1/agents/{agent_id}/devices")
async def register_device(agent_id: str, request: Request) -> dict[str, str]:
    body, agent = await _authenticate_agent(agent_id, request)
    fcm_token = _clean_text(body.get("fcmToken"), "fcmToken")
    device_id = hashlib.sha256(fcm_token.encode("utf-8")).hexdigest()
    db.collection("agents").document(agent_id).collection("devices").document(device_id).set(
        {
            "fcmToken": fcm_token,
            "meaningfulEnabled": bool(body.get("meaningfulEnabled", True)),
            "activityEnabled": bool(body.get("activityEnabled", True)),
            "platform": _clean_text(body.get("platform", "android"), "platform"),
            "siteId": agent["siteId"],
            "updatedAt": firestore.SERVER_TIMESTAMP,
            "expiresAt": datetime.now(timezone.utc) + timedelta(days=30),
        },
        merge=True,
    )
    return {"status": "registered", "deviceId": device_id}


@app.post("/v1/agents/{agent_id}/devices/revoke")
async def revoke_device(agent_id: str, request: Request) -> dict[str, str]:
    body, _ = await _authenticate_agent(agent_id, request)
    token = _clean_text(body.get("fcmToken"), "fcmToken")
    device_id = hashlib.sha256(token.encode("utf-8")).hexdigest()
    db.collection("agents").document(agent_id).collection("devices").document(device_id).delete()
    return {"status": "revoked"}


@app.post("/v1/agents/{agent_id}/heartbeat")
async def heartbeat(agent_id: str, request: Request) -> dict[str, str]:
    _, agent = await _authenticate_agent(agent_id, request)
    agent_ref = db.collection("agents").document(agent_id)
    was_lost = bool(agent.get("lostAt"))
    agent_ref.update({"lastSeenAt": firestore.SERVER_TIMESTAMP, "lostAt": None})
    if was_lost:
        _send_agent_status(agent_id, "PBXSense Agent is reachable again.", "Live PBX updates have resumed.")
    return {"status": "ok"}


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
        snapshot.reference.update({"lostAt": firestore.SERVER_TIMESTAMP})
        _send_agent_status(
            snapshot.id,
            "PBXSense lost the Agent.",
            "Live PBX updates are paused until the Agent is reachable again.",
        )
        lost += 1
    return {"lost": lost}


@app.delete("/v1/agents/{agent_id}/devices")
async def remove_device(agent_id: str, request: Request) -> dict[str, str]:
    body, _ = await _authenticate_agent(agent_id, request)
    fcm_token = _clean_text(body.get("fcmToken"), "fcmToken")
    device_id = hashlib.sha256(fcm_token.encode("utf-8")).hexdigest()
    db.collection("agents").document(agent_id).collection("devices").document(device_id).delete()
    return {"status": "removed"}


@app.post("/v1/agents/{agent_id}/events")
async def publish_event(agent_id: str, request: Request) -> dict[str, Any]:
    event, agent = await _authenticate_agent(agent_id, request)
    event_id = _clean_text(event.get("id"), "id")
    title = _clean_text(event.get("title"), "title")
    body = _clean_text(event.get("body"), "body")
    category = _clean_text(event.get("category"), "category")
    importance = _clean_text(event.get("importance"), "importance")
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

    devices = [
        document.to_dict() or {}
        for document in db.collection("agents").document(agent_id).collection("devices").stream()
    ]
    now = datetime.now(timezone.utc)
    eligible_devices = [
        device
        for device in devices
        if _device_wants_event(device, category, importance)
        and device.get("expiresAt", now) >= now
    ]
    tokens = [str(device["fcmToken"]) for device in eligible_devices]
    if not tokens:
        return {"status": "accepted", "sent": 0}

    message = messaging.MulticastMessage(
        tokens=tokens,
        notification=messaging.Notification(title=title, body=body),
        data={
            "signalId": event_id,
            "siteId": agent["siteId"],
            "category": category,
            "importance": importance,
        },
        android=messaging.AndroidConfig(priority="high"),
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


async def _authenticate_agent(agent_id: str, request: Request) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_body = await request.body()
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
    db.collection("agents").document(agent_id).update({"lastSeenAt": firestore.SERVER_TIMESTAMP})
    return body, agent


def _remove_invalid_tokens(agent_id: str, devices: list[dict[str, Any]], responses: list[Any]) -> int:
    removed = 0
    for device, response in zip(devices, responses, strict=True):
        if response.success or not isinstance(response.exception, messaging.UnregisteredError):
            continue
        token = str(device.get("fcmToken", ""))
        if token:
            device_id = hashlib.sha256(token.encode("utf-8")).hexdigest()
            db.collection("agents").document(agent_id).collection("devices").document(device_id).delete()
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
    devices = [
        document.to_dict() or {}
        for document in db.collection("agents").document(agent_id).collection("devices").stream()
    ]
    eligible_devices = [
        device
        for device in devices
        if device.get("meaningfulEnabled", True)
        and device.get("expiresAt", now) >= now
    ]
    tokens = [str(device.get("fcmToken", "")) for device in eligible_devices]
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


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="JSON body required") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="JSON object required")
    return body


def _require_admin(request: Request) -> None:
    supplied = request.headers.get("x-pbxsense-admin-token", "")
    if not _admin_token or not hmac.compare_digest(supplied, _admin_token):
        raise HTTPException(status_code=401, detail="Relay administrator token required")


def _decode_public_key(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(_padding(value)))


def _decode_signature(value: str) -> bytes:
    return base64.urlsafe_b64decode(_padding(value))


def _padding(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _clean_text(value: object, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail=f"{name} is required")
    return text
