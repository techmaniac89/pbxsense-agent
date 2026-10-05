from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AppCredentials:
    """Persistent, separately revocable app access and private admin sessions."""

    def __init__(self, path: Path, secret: str, admin_secret: str | None = None) -> None:
        self.path = path
        self.key = hashlib.sha256(secret.encode()).digest()
        self.lock = threading.RLock()
        binding = hashlib.sha256((admin_secret if admin_secret is not None else secret).encode()).hexdigest()
        self.state: dict = {"adminCookie": secrets.token_urlsafe(32), "apps": {}, "adminBinding": binding}
        if path.exists():
            envelope = json.loads(path.read_text())
            raw = AESGCM(self.key).decrypt(
                base64.b64decode(envelope["nonce"]),
                base64.b64decode(envelope["data"]), b"pbxsense-app-credentials-v1",
            )
            loaded = json.loads(raw)
            if not isinstance(loaded, dict) or not isinstance(loaded.get("apps"), dict):
                raise ValueError("Invalid app credential state")
            self.state = loaded
            if loaded.get("adminBinding") != binding:
                self.state = {"adminCookie": secrets.token_urlsafe(32), "apps": {}, "adminBinding": binding}
                self._save()
        else:
            self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        nonce = secrets.token_bytes(12)
        data = AESGCM(self.key).encrypt(
            nonce, json.dumps(self.state).encode(), b"pbxsense-app-credentials-v1",
        )
        temporary = self.path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"nonce": base64.b64encode(nonce).decode(),
                       "data": base64.b64encode(data).decode()}, handle)
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)

    def cookie(self) -> str:
        return self.state["adminCookie"]

    def issue(self, activation: str = "") -> str:
        with self.lock:
            # Unclaimed QR credentials expire; do not accumulate abandoned pages.
            now = time.time()
            self.state["apps"] = {key: value for key, value in self.state["apps"].items()
                                  if value.get("device") or value["expires"] > now}
            if len(self.state["apps"]) >= 500:
                raise ValueError("App credential limit reached")
            token = "app_" + secrets.token_urlsafe(32)
            self.state["apps"][hashlib.sha256(token.encode()).hexdigest()] = {
                "activation": activation, "device": "", "expires": now + 900,
            }
            self._save()
            return token

    def accepts(self, token: str) -> bool:
        with self.lock:
            row = self.state["apps"].get(hashlib.sha256(token.encode()).hexdigest())
            return bool(row and (row.get("device") or row["expires"] > time.time()))

    def activate(self, token: str) -> None:
        with self.lock:
            digest = hashlib.sha256(token.encode()).hexdigest()
            row = self.state["apps"].get(digest)
            if row and not row["device"] and self.accepts(token):
                row["device"] = "local_" + digest
                self._save()

    def bind(self, token: str, device: str) -> bool:
        with self.lock:
            row = self.state["apps"].get(hashlib.sha256(token.encode()).hexdigest())
            if not device or not row or not self.accepts(token):
                return False
            # Cloud device IDs must be learned from the signed Agent listing,
            # never chosen by an app during its first registration.
            if row["activation"] and (not row["device"] or row["device"].startswith("local_")):
                return False
            if not row["activation"] and not re.fullmatch(r"[0-9a-f]{12}", device):
                return False
            if row["device"] and not row["device"].startswith("local_") and row["device"] != device:
                return False
            row["device"] = device
            self._save()
            return True

    def sync_devices(self, devices: list) -> None:
        with self.lock:
            changed = False
            for device in devices:
                activation = device.get("activationId", "")
                for row in self.state["apps"].values():
                    if activation and row["activation"] == activation and (not row["device"] or row["device"].startswith("local_")):
                        row["device"] = str(device.get("revokeId") or device["id"])
                        changed = True
                    if row["device"] == device.get("id") and device.get("revokeId"):
                        if row.get("revokeId") != device["revokeId"]:
                            row["revokeId"] = device["revokeId"]
                            changed = True
            if changed:
                self._save()

    def revoke(self, device: str) -> None:
        with self.lock:
            # Fail closed for older relays that cannot identify an Internet-only QR.
            self.state["apps"] = {key: row for key, row in self.state["apps"].items()
                                  if row["device"] and not row["device"].startswith("local_")
                                  and row["device"] != device and row.get("revokeId") != device}
            self._save()
