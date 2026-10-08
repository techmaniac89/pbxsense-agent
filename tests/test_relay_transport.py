import base64
import hashlib
import http.client
import json
import threading
import unittest
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pbxsense_agent.relay import RelayRequestError as CompatibleRequestError
from pbxsense_agent.relay_transport import (
    MAX_RESPONSE_BYTES, RelayHttpTransport, RelayRequestError, validated_relay_url,
)


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class RelayTransportTest(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.transport = RelayHttpTransport(url="https://relay.example/base", timeout_seconds=5,
                                            sign=self.key.sign)

    def connection(self, status=200, body=b"{}"):
        connection = MagicMock()
        connection.getresponse.return_value.status = status
        connection.getresponse.return_value.read.return_value = body
        return connection

    def test_signatures_bind_exact_canonical_bytes_and_logical_path(self):
        connection = self.connection()
        with patch("pbxsense_agent.relay_transport.http.client.HTTPSConnection", return_value=connection), patch("pbxsense_agent.relay_transport.time.time", return_value=123):
            self.transport.request("/v1/test", {"z": 2, "a": "value"}, signed=True)
            self.transport.request("/v1/test", {"a": "value", "z": 2}, signed=True)
        first, second = connection.request.call_args_list
        self.assertEqual(first.args, ("POST", "/base/v1/test"))
        raw, headers = first.kwargs["body"], first.kwargs["headers"]
        self.assertEqual(raw, b'{"a":"value","z":2}')
        self.key.public_key().verify(decode(headers["X-PBXSense-Signature"]), b"123\n/v1/test\n" + raw)
        v2 = f"123\n{headers['X-PBXSense-Nonce']}\nPOST\n/v1/test\n{hashlib.sha256(raw).hexdigest()}".encode()
        self.key.public_key().verify(decode(headers["X-PBXSense-Signature-V2"]), v2)
        self.assertNotEqual(headers["X-PBXSense-Nonce"], second.kwargs["headers"]["X-PBXSense-Nonce"])
        self.assertEqual(raw, second.kwargs["body"])

    def test_unsigned_and_legacy_only_modes_preserve_header_contract(self):
        connection = self.connection()
        with patch("pbxsense_agent.relay_transport.http.client.HTTPSConnection", return_value=connection):
            self.transport.request("/v1/test", {}, signed=False)
            self.assertEqual(connection.request.call_args.kwargs["headers"], {"Content-Type": "application/json"})
            self.transport.request("/v1/test", {}, signed=True, replay_protected=False)
        headers = connection.request.call_args.kwargs["headers"]
        self.assertIn("X-PBXSense-Signature", headers)
        self.assertNotIn("X-PBXSense-Nonce", headers)
        self.assertNotIn("X-PBXSense-Signature-V2", headers)

    def test_response_size_limit_discards_connection(self):
        connection = self.connection(body=b"x" * (MAX_RESPONSE_BYTES + 1))
        with patch("pbxsense_agent.relay_transport.http.client.HTTPSConnection", return_value=connection):
            with self.assertRaises(OSError):
                self.transport.request("/v1/test", {}, signed=False)
        connection.getresponse.return_value.read.assert_called_once_with(MAX_RESPONSE_BYTES + 1)
        connection.close.assert_called_once()
        self.assertIsNone(self.transport._connection)

    def test_bad_json_discards_connection_and_next_request_reconnects(self):
        first, second = self.connection(body=b"not-json"), self.connection(body=b'{"ok":true}')
        with patch("pbxsense_agent.relay_transport.http.client.HTTPSConnection", side_effect=[first, second]):
            with self.assertRaises(json.JSONDecodeError):
                self.transport.request("/v1/test", {}, signed=False)
            self.assertEqual(self.transport.request("/v1/test", {}, signed=False), {"ok": True})
        first.close.assert_called_once()

    def test_http_error_keeps_status_classification_and_compatibility_alias(self):
        self.assertIs(CompatibleRequestError, RelayRequestError)
        for status, retryable in ((400, False), (408, True), (425, True), (429, True), (503, True)):
            connection = self.connection(status=status, body=b"temporary failure")
            with patch("pbxsense_agent.relay_transport.http.client.HTTPSConnection", return_value=connection):
                with self.assertRaises(RelayRequestError) as error:
                    self.transport.request("/v1/test", {}, signed=False)
            self.assertEqual(error.exception.status, status)
            self.assertEqual(error.exception.retryable, retryable)
            connection.close.assert_called_once()

    def test_isolated_request_does_not_wait_for_busy_delivery_stream(self):
        shared, dedicated = self.connection(), self.connection()
        entered, release = threading.Event(), threading.Event()
        errors = []
        def slow_send(*args, **kwargs):
            entered.set()
            release.wait(2)
        shared.request.side_effect = slow_send
        self.transport._connection = shared
        def delivery():
            try:
                self.transport.request("/v1/event", {}, signed=True)
            except Exception as error:
                errors.append(error)
        worker = threading.Thread(target=delivery)
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            with patch("pbxsense_agent.relay_transport.http.client.HTTPSConnection", return_value=dedicated):
                with self.transport.isolated():
                    self.assertEqual(self.transport.request("/v1/heartbeat", {}, signed=True), {})
            dedicated.close.assert_called_once()
            shared.close.assert_not_called()
            self.assertIs(self.transport._connection, shared)
        finally:
            release.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])

    def test_isolated_network_failure_does_not_discard_shared_connection(self):
        shared, dedicated = self.connection(), self.connection()
        self.transport._connection = shared
        dedicated.getresponse.side_effect = http.client.RemoteDisconnected()
        with patch("pbxsense_agent.relay_transport.http.client.HTTPSConnection", return_value=dedicated):
            with self.transport.isolated(), self.assertRaises(OSError):
                self.transport.request("/v1/heartbeat", {}, signed=False)
        dedicated.close.assert_called_once()
        self.assertIs(self.transport._connection, shared)
        shared.close.assert_not_called()

    def test_plaintext_is_loopback_only_and_https_is_default(self):
        for url in ("http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080", "https://relay.example/"):
            self.assertTrue(validated_relay_url(url))
        for url in ("http://relay.example", "ftp://relay.example", "https:///missing-host"):
            with self.assertRaises(ValueError):
                validated_relay_url(url)
