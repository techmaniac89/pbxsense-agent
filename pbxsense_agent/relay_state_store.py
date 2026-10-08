from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    InvalidTag = ValueError  # type: ignore[assignment,misc]
    AESGCM = None  # type: ignore[assignment,misc]


class RelayStateStore:
    """Encrypted file persistence; callers own state mutation and synchronization."""

    def __init__(
        self, path: str, *, storage_secret: str,
        legacy_storage_secrets: tuple[str, ...] = (),
    ) -> None:
        self._path = Path(path)
        self._storage_secret = storage_secret.strip()
        self._storage_secrets = tuple(dict.fromkeys(
            secret.strip()
            for secret in (self._storage_secret, *legacy_storage_secrets)
            if secret.strip()
        ))
        # The first save must also migrate plaintext and old-key envelopes.
        self._last_saved_state_fingerprint = ""

    def load(self) -> dict[str, Any]:
        try:
            decoded = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(decoded, dict):
                return {"outbox": [], "delivered": {}}
            if decoded.get("format") != "pbxsense-relay-state-v1":
                # Existing installations are migrated on the next save.
                return decoded
            return self._decrypt_state(decoded)
        except (OSError, json.JSONDecodeError):
            return {"outbox": [], "delivered": {}}

    def _decrypt_state(self, envelope: dict[str, Any]) -> dict[str, Any]:
        if AESGCM is None or not self._storage_secrets:
            raise RuntimeError(
                "The encrypted relay identity needs PBXSENSE_RELAY_STATE_KEY "
                "or the Agent token used when it was created"
            )
        try:
            nonce = _decode(str(envelope["nonce"]))
            ciphertext = _decode(str(envelope["ciphertext"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("The encrypted relay identity is malformed") from exc
        for secret in self._storage_secrets:
            try:
                plaintext = AESGCM(_relay_state_key(secret)).decrypt(
                    nonce, ciphertext, b"pbxsense-relay-state-v1"
                )
                decoded = json.loads(plaintext.decode("utf-8"))
                if isinstance(decoded, dict):
                    return decoded
            except (InvalidTag, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                continue
        raise RuntimeError(
            "The relay identity could not be decrypted; restore its state key "
            "instead of creating a new identity"
        )

    def save(self, state: dict[str, Any]) -> None:
        if AESGCM is None or not self._storage_secret:
            raise RuntimeError(
                "PBXSENSE_RELAY_STATE_KEY or PBXSENSE_AGENT_TOKEN is required "
                "to protect relay identity state"
            )
        serialized_state = json.dumps(state, sort_keys=True).encode("utf-8")
        state_fingerprint = hashlib.sha256(serialized_state).hexdigest()
        if state_fingerprint == self._last_saved_state_fingerprint:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self._path.parent.chmod(0o700)
        temporary = self._path.with_suffix(".tmp")
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(_relay_state_key(self._storage_secret)).encrypt(
            nonce,
            serialized_state,
            b"pbxsense-relay-state-v1",
        )
        envelope = {
            "format": "pbxsense-relay-state-v1",
            "nonce": _encode(nonce),
            "ciphertext": _encode(ciphertext),
        }
        temporary.write_text(json.dumps(envelope, sort_keys=True), encoding="utf-8")
        if os.name != "nt":
            temporary.chmod(0o600)
        temporary.replace(self._path)
        self._last_saved_state_fingerprint = state_fingerprint
        if os.name != "nt":
            self._path.chmod(0o600)

    def protect_storage(self) -> None:
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


def _relay_state_key(secret: str) -> bytes:
    return hashlib.sha256(
        b"pbxsense-relay-state-v1\0" + secret.encode("utf-8")
    ).digest()

def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

