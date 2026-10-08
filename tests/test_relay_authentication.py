import asyncio
import base64
import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException, Request
from push_relay.authentication import RelayAuthentication


class AlreadyExists(Exception):
    pass


def encode(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


class RelayAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
        self.key = Ed25519PrivateKey.generate()
        self.public = encode(self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ))
        self.db = MagicMock()
        self.agent_ref = self.db.collection.return_value.document.return_value
        self.agent_ref.get.return_value.exists = True
        self.agent_ref.get.return_value.to_dict.return_value = {"publicKey": self.public}
        self.nonce_ref = self.agent_ref.collection.return_value.document.return_value
        self.auth = RelayAuthentication(
            db=self.db, server_timestamp="server-time", already_exists=AlreadyExists,
            identifier=lambda value, field: str(value), max_snapshot_bytes=64,
            admin_token="admin-secret", ticket_secret="ticket-secret",
            admin_cookie="admin-cookie", admin_cookie_ttl=28800,
            clock=lambda: self.now.timestamp(), now=lambda: self.now,
        )

    def request(self, body=b"{}", path="/v1/agents/agent/heartbeat", headers=None):
        stamp = str(int(self.now.timestamp()))
        nonce = "abcdefghijklmnop"
        signed = {
            "x-pbxsense-timestamp": stamp, "x-pbxsense-nonce": nonce,
            "x-pbxsense-signature": encode(self.key.sign(f"{stamp}\n{path}\n".encode() + body)),
            "x-pbxsense-signature-v2": encode(self.key.sign(
                f"{stamp}\n{nonce}\nPOST\n{path}\n{hashlib.sha256(body).hexdigest()}".encode(),
            )),
        }
        signed.update(headers or {})
        request = Request({
            "type": "http", "method": "POST", "path": path, "scheme": "https",
            "server": ("relay.example", 443), "query_string": b"",
            "headers": [(key.encode(), value.encode()) for key, value in signed.items()],
        })
        request._body = body
        return request

    def authenticate(self, request=None, **kwargs):
        return asyncio.run(self.auth.authenticate_agent(
            "agent", request or self.request(), **kwargs,
        ))

    def test_nonce_claim_precedes_presence_update(self):
        order = []
        self.nonce_ref.create.side_effect = lambda *a: order.append("nonce")
        self.agent_ref.update.side_effect = lambda *a: order.append("presence")
        body, agent = self.authenticate()
        self.assertEqual(body, {})
        self.assertEqual(agent["publicKey"], self.public)
        self.assertEqual(order, ["nonce", "presence"])
        self.assertEqual(self.nonce_ref.create.call_args.args[0]["expiresAt"],
                         self.now + timedelta(minutes=10))
        self.agent_ref.update.assert_called_once_with({"lastSeenAt": "server-time"})

    def test_non_presence_request_still_claims_nonce(self):
        self.authenticate(touch_presence=False)
        self.nonce_ref.create.assert_called_once()
        self.agent_ref.update.assert_not_called()

    def test_replayed_and_failed_nonce_claims_do_not_touch_presence(self):
        for failure, expected in ((AlreadyExists(), HTTPException), (RuntimeError(), RuntimeError)):
            self.nonce_ref.create.side_effect = failure
            with self.assertRaises(expected) as caught:
                self.authenticate()
            if isinstance(caught.exception, HTTPException):
                self.assertEqual(caught.exception.status_code, 409)
            self.agent_ref.update.assert_not_called()

    def test_invalid_signature_unknown_and_revoked_agents_do_not_write(self):
        with self.assertRaises(HTTPException):
            self.authenticate(self.request(headers={"x-pbxsense-signature-v2": ""}))
        self.agent_ref.get.return_value.exists = False
        with self.assertRaises(HTTPException) as caught:
            self.authenticate()
        self.assertEqual(caught.exception.detail, "Unknown Agent")
        self.agent_ref.get.return_value.exists = True
        self.agent_ref.get.return_value.to_dict.return_value = {"revoked": True}
        with self.assertRaises(HTTPException) as caught:
            self.authenticate()
        self.assertEqual(caught.exception.detail, "Agent has been revoked")
        self.nonce_ref.create.assert_not_called()
        self.agent_ref.update.assert_not_called()

    def test_body_validation_precedes_identity_lookup(self):
        for body, path, code in (
            (b"not-json", "/heartbeat", 400),
            (b"[]", "/heartbeat", 400),
            (b"x" * 65, "/v1/agents/agent/secure/snapshots", 413),
        ):
            with self.assertRaises(HTTPException) as caught:
                self.authenticate(self.request(body=body, path=path))
            self.assertEqual(caught.exception.status_code, code)
        self.db.collection.assert_not_called()

    def test_device_bearer_credentials_and_expiry_boundary(self):
        self.nonce_ref.get.return_value.exists = True
        self.nonce_ref.get.return_value.to_dict.return_value = {
            "accessTokenHash": hashlib.sha256(b"app-token").hexdigest(),
            "expiresAt": self.now,
        }
        request = self.request(headers={"authorization": "Bearer app-token"})
        reference, _ = self.auth.authenticate_relay_device("agent", "device", request)
        self.assertIs(reference, self.nonce_ref)
        with self.assertRaises(HTTPException):
            self.auth.authenticate_relay_device("agent", "device", self.request())
        self.nonce_ref.get.return_value.to_dict.return_value["expiresAt"] -= timedelta(seconds=1)
        with self.assertRaises(HTTPException) as caught:
            self.auth.authenticate_relay_device("agent", "device", request)
        self.assertEqual(caught.exception.detail, "Device credential expired")

    def test_admin_cookie_auth_does_not_authorize_header_only_internal_api(self):
        cookie = self.auth.admin_cookie_value(int(self.now.timestamp()) + 60)
        request = self.request(headers={"cookie": f"admin-cookie={cookie}"})
        self.assertTrue(self.auth.admin_authenticated(request))
        with self.assertRaises(HTTPException):
            self.auth.require_admin(request)
        header = self.request(headers={"x-pbxsense-admin-token": "admin-secret"})
        self.auth.require_admin(header)
        self.assertTrue(self.auth.admin_authenticated(header))
        self.assertFalse(self.auth.admin_cookie_valid(cookie, int(self.now.timestamp()) + 60))
        self.auth._admin_token = ""
        self.assertFalse(self.auth.admin_authenticated(header))

    def test_tickets_preserve_signature_expiry_and_missing_secret_errors(self):
        payload = {"id": "ticket", "accountId": "account",
                   "expiresAt": int(self.now.timestamp()) + 60}
        ticket = self.auth.sign_enrollment_ticket(payload)
        self.assertEqual(self.auth.verify_enrollment_ticket(ticket), payload)
        with self.assertRaises(HTTPException):
            self.auth.verify_enrollment_ticket(ticket + "tampered")
        expired = self.auth.sign_enrollment_ticket({**payload, "expiresAt": int(self.now.timestamp())})
        with self.assertRaises(HTTPException) as caught:
            self.auth.verify_enrollment_ticket(expired)
        self.assertEqual(caught.exception.detail, "Enrollment ticket expired")
        self.auth._ticket_secret = ""
        for function, value in ((self.auth.sign_enrollment_ticket, payload),
                                (self.auth.verify_enrollment_ticket, ticket)):
            with self.assertRaises(HTTPException) as caught:
                function(value)
            self.assertEqual(caught.exception.status_code, 503)
