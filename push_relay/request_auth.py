"""Signed-request verification without Firebase or replay-store access."""
from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException, Request


def verify_agent_signature(
    public_key: str, request: Request, raw_body: bytes, *, now: float,
) -> None:
    timestamp = request.headers.get("x-pbxsense-timestamp", "")
    signature = request.headers.get("x-pbxsense-signature", "")
    try:
        issued_at = int(timestamp)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid request timestamp") from exc
    if abs(now - issued_at) > 300:
        raise HTTPException(status_code=401, detail="Expired signed request")
    message = f"{timestamp}\n{request.url.path}\n".encode("utf-8") + raw_body
    try:
        _decode_public_key(public_key).verify(_decode_signature(signature), message)
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise HTTPException(status_code=401, detail="Invalid Agent signature") from exc


def verify_secure_agent_signature(
    public_key: str, request: Request, raw_body: bytes,
) -> str:
    timestamp = request.headers.get("x-pbxsense-timestamp", "")
    nonce = request.headers.get("x-pbxsense-nonce", "")
    signature = request.headers.get("x-pbxsense-signature-v2", "")
    if not 16 <= len(nonce) <= 96 or not nonce.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(status_code=401, detail="Invalid secure request nonce")
    digest = hashlib.sha256(raw_body).hexdigest()
    message = (
        f"{timestamp}\n{nonce}\n{request.method.upper()}\n{request.url.path}\n{digest}"
    ).encode("utf-8")
    try:
        _decode_public_key(public_key).verify(
            _decode_signature(signature), message
        )
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise HTTPException(status_code=401, detail="Invalid secure Agent signature") from exc
    return nonce


def verify_activation_signatures(
    public_key: str, request: Request, raw_body: bytes, *, now: float,
) -> str:
    timestamp = request.headers.get("x-pbxsense-timestamp", "")
    signature = request.headers.get("x-pbxsense-signature", "")
    try:
        issued_at = int(timestamp)
    except ValueError as exc:
        raise HTTPException(
            status_code=401, detail="Signed activation request required"
        ) from exc
    if abs(now - issued_at) > 300:
        raise HTTPException(status_code=401, detail="Expired activation request")
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
    return nonce


def _decode_public_key(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(_padding(value)))


def _decode_signature(value: str) -> bytes:
    return base64.urlsafe_b64decode(_padding(value))


def _padding(value: str) -> str:
    return value + "=" * (-len(value) % 4)

