"""Bounded, signed HTTP exchange; no relay identity or notification policy."""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import secrets
import threading
import time
import urllib.parse
from contextlib import contextmanager, nullcontext
from typing import Any, Callable


MAX_RESPONSE_BYTES = 5 * 1024 * 1024


class RelayRequestError(OSError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status

    @property
    def retryable(self) -> bool:
        return self.status in {408, 425, 429} or self.status >= 500


def validated_relay_url(value: str) -> str:
    url = value.rstrip("/")
    if not url:
        return ""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return url
    if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return url
    raise ValueError("PBXSENSE_RELAY_URL must use HTTPS (HTTP is allowed only for localhost)")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class RelayHttpTransport:
    def __init__(self, *, url: str, timeout_seconds: float,
                 sign: Callable[[bytes], bytes]) -> None:
        self.url = validated_relay_url(url)
        self._parsed = urllib.parse.urlparse(self.url)
        self._timeout_seconds = timeout_seconds
        self._sign = sign
        self._connection: http.client.HTTPConnection | None = None
        self._connection_lock = threading.Lock()
        self._local = threading.local()

    @contextmanager
    def isolated(self):
        """Use a disposable connection without taking the delivery-stream lock."""
        previous_mode = getattr(self._local, "isolated", False)
        previous_connection = getattr(self._local, "connection", None)
        self._local.isolated = True
        self._local.connection = None
        try:
            yield
        finally:
            self._close_connection()
            self._local.isolated = previous_mode
            self._local.connection = previous_connection

    def request(self, path: str, payload: dict[str, object], *, signed: bool,
                replay_protected: bool = True) -> dict[str, Any]:
        lock = nullcontext() if getattr(self._local, "isolated", False) else self._connection_lock
        with lock:
            raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if signed:
                timestamp = str(int(time.time()))
                message = f"{timestamp}\n{path}\n".encode("utf-8") + raw
                headers.update({"X-PBXSense-Timestamp": timestamp,
                                "X-PBXSense-Signature": _encode(self._sign(message))})
                if replay_protected:
                    nonce = secrets.token_urlsafe(18)
                    digest = hashlib.sha256(raw).hexdigest()
                    v2_message = f"{timestamp}\n{nonce}\nPOST\n{path}\n{digest}".encode("utf-8")
                    headers.update({"X-PBXSense-Nonce": nonce,
                                    "X-PBXSense-Signature-V2": _encode(self._sign(v2_message))})
            request_path = f"{self._parsed.path.rstrip('/')}{path}" or "/"
            try:
                connection = self._get_connection()
                connection.request("POST", request_path, body=raw, headers=headers)
                response = connection.getresponse()
                response_body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(response_body) > MAX_RESPONSE_BYTES:
                    raise OSError("Relay response exceeds the 5 MiB safety limit")
                if response.status >= 400:
                    detail = response_body.decode("utf-8", errors="replace")[:200]
                    message = f"Relay returned HTTP {response.status}"
                    if detail:
                        message += f": {detail}"
                    self._close_connection()
                    raise RelayRequestError(response.status, message)
                decoded = json.loads(response_body.decode("utf-8"))
            except RelayRequestError:
                raise
            except (http.client.HTTPException, OSError, TimeoutError) as exc:
                self._close_connection()
                raise OSError("The relay request could not be completed.") from exc
            except (ValueError, UnicodeError):
                self._close_connection()
                raise
            return decoded if isinstance(decoded, dict) else {}

    def _get_connection(self) -> http.client.HTTPConnection:
        isolated = getattr(self._local, "isolated", False)
        connection = getattr(self._local, "connection", None) if isolated else self._connection
        if connection is not None:
            return connection
        connection_type = http.client.HTTPSConnection if self._parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(self._parsed.hostname, port=self._parsed.port,
                                     timeout=self._timeout_seconds)
        if isolated:
            self._local.connection = connection
        else:
            self._connection = connection
        return connection

    def _close_connection(self) -> None:
        if getattr(self._local, "isolated", False):
            connection = getattr(self._local, "connection", None)
            self._local.connection = None
        else:
            connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
