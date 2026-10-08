from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException, Request

from push_relay.request_auth import (
    verify_agent_signature,
    verify_secure_agent_signature,
    verify_activation_signatures,
)
from push_relay.authentication import RelayAuthentication


def encoded(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class AlreadyExists(Exception):
    pass


class RelayRequestAuthTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public_key = encoded(self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ))
        self.now = int(time.time())
        self.body = b'{"displayName":"PBX","value":1}'
        self.nonce = "abcdefghijklmnop_nonce"

    def request(self, *, path="/v1/agents/agent_test/heartbeat", method="POST",
                timestamp=None, body=None, header_changes=None):
        timestamp = str(self.now if timestamp is None else timestamp)
        body = self.body if body is None else body
        v1 = f"{timestamp}\n{path}\n".encode() + body
        v2 = (f"{timestamp}\n{self.nonce}\n{method}\n{path}\n"
              f"{hashlib.sha256(body).hexdigest()}").encode()
        headers = {
            "x-pbxsense-timestamp": timestamp,
            "x-pbxsense-nonce": self.nonce,
            "x-pbxsense-signature": encoded(self.key.sign(v1)),
            "x-pbxsense-signature-v2": encoded(self.key.sign(v2)),
        }
        headers.update(header_changes or {})
        request = Request({
            "type": "http", "method": method, "path": path,
            "headers": [(name.encode(), value.encode()) for name, value in headers.items()],
            "query_string": b"", "server": ("relay.example", 443), "scheme": "https",
        })
        request._body = body
        return request

    def assert_rejected(self, function, *args, detail, **kwargs):
        with self.assertRaises(HTTPException) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.status_code, 401)
        self.assertEqual(caught.exception.detail, detail)

    def test_agent_signatures_accept_exact_body_and_return_nonce(self):
        request = self.request()
        verify_agent_signature(self.public_key, request, self.body, now=self.now)
        self.assertEqual(
            verify_secure_agent_signature(self.public_key, request, self.body),
            self.nonce,
        )

    def test_activation_requires_both_signatures(self):
        request = self.request(path="/v1/activations")
        self.assertEqual(
            verify_activation_signatures(self.public_key, request, self.body, now=self.now),
            self.nonce,
        )
        for header, detail in (
            ("x-pbxsense-signature", "Invalid activation signature"),
            ("x-pbxsense-signature-v2", "Invalid secure activation signature"),
        ):
            self.assert_rejected(
                verify_activation_signatures, self.public_key,
                self.request(path="/v1/activations", header_changes={header: ""}),
                self.body, now=self.now, detail=detail,
            )

    def test_timestamp_skew_includes_exact_boundary_in_both_directions(self):
        for difference in (-300, 300):
            request = self.request(timestamp=self.now + difference)
            verify_agent_signature(self.public_key, request, self.body, now=self.now)
            verify_activation_signatures(self.public_key, request, self.body, now=self.now)
        for difference in (-301, 301):
            self.assert_rejected(
                verify_agent_signature, self.public_key,
                self.request(timestamp=self.now + difference), self.body,
                now=self.now, detail="Expired signed request",
            )
            self.assert_rejected(
                verify_activation_signatures, self.public_key,
                self.request(timestamp=self.now + difference), self.body,
                now=self.now, detail="Expired activation request",
            )

    def test_invalid_timestamp_keeps_existing_errors(self):
        request = self.request(timestamp="not-a-time")
        self.assert_rejected(
            verify_agent_signature, self.public_key, request, self.body,
            now=self.now, detail="Invalid request timestamp",
        )
        self.assert_rejected(
            verify_activation_signatures, self.public_key, request, self.body,
            now=self.now, detail="Signed activation request required",
        )

    def test_v1_binds_body_and_path_and_v2_also_binds_method(self):
        request = self.request()
        self.assert_rejected(
            verify_agent_signature, self.public_key, request, self.body + b" ",
            now=self.now, detail="Invalid Agent signature",
        )
        request = self.request()
        request.scope["path"] = "/v1/agents/another/heartbeat"
        self.assert_rejected(
            verify_agent_signature, self.public_key, request, self.body,
            now=self.now, detail="Invalid Agent signature",
        )
        request = self.request()
        request.scope["method"] = "DELETE"
        self.assert_rejected(
            verify_secure_agent_signature, self.public_key, request, self.body,
            detail="Invalid secure Agent signature",
        )
        self.assert_rejected(
            verify_secure_agent_signature, self.public_key, self.request(), self.body + b" ",
            detail="Invalid secure Agent signature",
        )

    def test_nonce_validation_and_signature_binding(self):
        for nonce in ("short", "a" * 97, "abcdefghijklmnop/slash"):
            request = self.request(header_changes={"x-pbxsense-nonce": nonce})
            self.assert_rejected(
                verify_secure_agent_signature, self.public_key, request, self.body,
                detail="Invalid secure request nonce",
            )
            self.assert_rejected(
                verify_activation_signatures, self.public_key, request, self.body,
                now=self.now, detail="Invalid activation nonce",
            )
        self.assert_rejected(
            verify_secure_agent_signature, self.public_key,
            self.request(header_changes={"x-pbxsense-nonce": "other_valid_nonce"}),
            self.body, detail="Invalid secure Agent signature",
        )

    def test_wrong_public_key_and_malformed_signatures_fail(self):
        other = Ed25519PrivateKey.generate()
        other_public = encoded(other.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ))
        for public in (other_public, "", "invalid-key"):
            self.assert_rejected(
                verify_agent_signature, public, self.request(), self.body,
                now=self.now, detail="Invalid Agent signature",
            )
        self.assert_rejected(
            verify_secure_agent_signature, self.public_key,
            self.request(header_changes={"x-pbxsense-signature-v2": "bad"}),
            self.body, detail="Invalid secure Agent signature",
        )

    def wrappers(self):
        # Exercise the actual database coordination functions without importing
        # the Firebase-initializing application module.
        module = ast.parse(Path("push_relay/app.py").read_text(encoding="utf-8"))
        names = {"_require_replay_protected_signature", "_verify_public_key_request"}
        functions = [node for node in module.body
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and node.name in names]
        database = MagicMock()
        namespace = {
            "Any": object, "Request": Request, "HTTPException": HTTPException,
            "verify_secure_agent_signature": verify_secure_agent_signature,
            "verify_activation_signatures": verify_activation_signatures,
            "db": database, "hashlib": hashlib, "time": time,
            "firestore": SimpleNamespace(SERVER_TIMESTAMP="server-time"),
            "datetime": datetime, "timedelta": timedelta, "timezone": timezone,
            "AlreadyExists": AlreadyExists,
        }
        exec(compile(ast.Module(functions, type_ignores=[]), "relay-auth-wrappers", "exec"),
             namespace)
        namespace["_relay_auth"] = lambda: RelayAuthentication(
            db=database, server_timestamp="server-time", already_exists=AlreadyExists,
            identifier=lambda value, field: str(value), max_snapshot_bytes=1024 * 1024,
            admin_token="", ticket_secret="", admin_cookie="admin",
            admin_cookie_ttl=8 * 60 * 60, clock=time.time,
            now=lambda: datetime.now(timezone.utc),
        )
        return namespace, database

    def test_secure_replay_claim_follows_verification_and_replay_is_409(self):
        namespace, database = self.wrappers()
        reference = (database.collection.return_value.document.return_value
                     .collection.return_value.document.return_value)
        function = namespace["_require_replay_protected_signature"]
        asyncio.run(function("agent_test", {"publicKey": self.public_key}, self.request()))
        reference.create.assert_called_once()
        record = reference.create.call_args.args[0]
        self.assertEqual(record["createdAt"], "server-time")
        self.assertGreater(record["expiresAt"], datetime.now(timezone.utc))
        reference.create.side_effect = AlreadyExists()
        with self.assertRaises(HTTPException) as caught:
            asyncio.run(function("agent_test", {"publicKey": self.public_key}, self.request()))
        self.assertEqual(caught.exception.status_code, 409)
        reference.create.reset_mock()
        with self.assertRaises(HTTPException):
            asyncio.run(function("agent_test", {}, self.request()))
        reference.create.assert_not_called()

    def test_activation_replay_claim_uses_public_key_scoped_hash(self):
        namespace, database = self.wrappers()
        function = namespace["_verify_public_key_request"]
        function(self.public_key, self.request(path="/v1/activations"))
        database.collection.assert_called_with("activationNonces")
        expected = hashlib.sha256(f"{self.public_key}:{self.nonce}".encode()).hexdigest()
        database.collection.return_value.document.assert_called_with(expected)
        reference = database.collection.return_value.document.return_value
        reference.create.side_effect = AlreadyExists()
        with self.assertRaises(HTTPException) as caught:
            function(self.public_key, self.request(path="/v1/activations"))
        self.assertEqual(caught.exception.status_code, 409)
        reference.create.reset_mock()
        with self.assertRaises(HTTPException):
            function(self.public_key, self.request(
                path="/v1/activations", header_changes={"x-pbxsense-signature-v2": ""},
            ))
        reference.create.assert_not_called()

    def test_cloud_image_includes_auth_module_and_top_level_import_works(self):
        import subprocess
        import sys
        dockerfile = Path("push_relay/Dockerfile").read_text()
        self.assertIn("COPY request_auth.py .", dockerfile)
        subprocess.run(
            [sys.executable, "-c", "import request_auth; assert callable(request_auth.verify_agent_signature)"],
            cwd="push_relay", check=True, capture_output=True,
        )

    def test_top_level_application_loads_and_preserves_public_schema(self):
        import subprocess
        import sys
        # Startup/schema smoke check with Firebase mocked: no credentials,
        # Firestore traffic or cloud mutation is involved.
        code = """
import os
import sys
from types import ModuleType
from unittest.mock import MagicMock
os.environ["PBXSENSE_RELAY_ENROLLMENT_MODE"] = "closed"
os.environ["PBXSENSE_RELAY_ADMIN_TOKEN"] = ""
os.environ["PBXSENSE_RELAY_TICKET_SECRET"] = ""
firebase = ModuleType("firebase_admin")
firebase.initialize_app = MagicMock()
firestore = ModuleType("firebase_admin.firestore")
firestore.client = MagicMock()
firestore.SERVER_TIMESTAMP = "server-time"
firestore.client.return_value.collection.return_value.document.return_value.get.return_value.exists = False
firestore.transactional = lambda function: function
firebase.firestore = firestore
firebase.messaging = ModuleType("firebase_admin.messaging")
sys.modules["firebase_admin"] = firebase
sys.modules["firebase_admin.firestore"] = firestore
sys.modules["firebase_admin.messaging"] = firebase.messaging
for name in ("google", "google.api_core", "google.api_core.exceptions"):
    sys.modules[name] = ModuleType(name)
sys.modules["google.api_core.exceptions"].AlreadyExists = type("AlreadyExists", (Exception,), {})
import app
import asyncio
import json
async def smoke(path="/health", method="GET", payload=b""):
    messages = []
    received = False
    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": payload, "more_body": False}
        await asyncio.Future()
    async def send(message):
        messages.append(message)
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "https", "path": path,
        "raw_path": path.encode(), "query_string": b"", "headers": [],
        "server": ("relay.example", 443), "client": ("127.0.0.1", 1234),
    }
    await asyncio.wait_for(app.app(scope, receive, send), timeout=5)
    status = next(item for item in messages if item["type"] == "http.response.start")["status"]
    body = b"".join(item.get("body", b"") for item in messages if item["type"] == "http.response.body")
    return status, body
status, body = asyncio.run(smoke())
assert status == 200 and json.loads(body)["version"] == app.RELAY_VERSION
for path, method, body in (
    ("/v1/internal/usage", "GET", b""),
    ("/v1/agents/agent/heartbeat", "POST", b"{}"),
    ("/v1/agents/agent/devices/device/secure-snapshot", "POST", b"{}"),
):
    status, _ = asyncio.run(smoke(path, method, body))
    assert status == 401, (path, status)
schema = app.app.openapi()
from routes import ROUTES
actual = {(method.upper(), path) for path, operations in schema["paths"].items()
          for method in operations}
assert actual == {(method, path) for method, path, _, _ in ROUTES}
assert len(actual) == 21
assert "/v1/activations" in schema["paths"]
assert "/v1/agents/{agent_id}/events" in schema["paths"]
heartbeat = schema["paths"]["/v1/agents/{agent_id}/heartbeat"]["post"]
assert not any(parameter["name"] == "request" for parameter in heartbeat.get("parameters", []))
assert callable(app.verify_agent_signature)
"""
        result = subprocess.run(
            [sys.executable, "-c", code], cwd="push_relay",
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
