from __future__ import annotations

import ast
import asyncio
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

from pbxsense_agent import main as agent_main


class SnapshotSignatureTransportTest(unittest.TestCase):
    def test_pairing_qr_pins_the_agent_key_not_the_relay_response(self) -> None:
        request = SimpleNamespace(base_url="https://agent.example/")
        with patch.object(agent_main.push_relay, "activation", return_value={
            "id": "activation", "secret": "secret"
        }), patch.object(agent_main.push_relay, "signing_public_key", return_value="trusted-agent-key"):
            payload = agent_main._pairing_payload(request)
        query = parse_qs(urlparse(payload).query)
        self.assertEqual(query["agentSigningKey"], ["trusted-agent-key"])

    def test_relay_preserves_signature_and_signed_fields(self) -> None:
        # Execute the real route with isolated Firestore/auth stubs, without
        # initializing Firebase or requiring production service credentials.
        tree = ast.parse(Path("push_relay/app.py").read_text(encoding="utf-8"))
        route = next(node for node in tree.body
                     if isinstance(node, ast.AsyncFunctionDef)
                     and node.name == "publish_secure_snapshots")
        route.decorator_list = []
        envelope = {
            "deviceId": "device", "sequence": 7,
            "createdAt": "2026-10-05T12:00:00+00:00",
            "ephemeralPublicKey": "ephemeral", "salt": "salt",
            "nonce": "nonce", "ciphertext": "ciphertext", "signature": "signed",
        }
        db = MagicMock()
        namespace = {
            "Request": object, "HTTPException": RuntimeError, "db": db,
            "firestore": SimpleNamespace(SERVER_TIMESTAMP="timestamp"),
            "_authenticate_agent": AsyncMock(return_value=({"envelopes": [envelope]}, {})),
            "_bounded_identifier": lambda value, _: value,
            "_clean_text": lambda value, _: value,
            "_bounded_base64": lambda value, _name, _limit: value,
            "_usage_update": lambda *args, **kwargs: {},
        }
        exec(compile(ast.Module([route], type_ignores=[]), "relay-route", "exec"), namespace)
        result = asyncio.run(namespace["publish_secure_snapshots"]("agent", object()))
        self.assertEqual(result, {"stored": 1})
        devices = db.collection.return_value.document.return_value.collection.return_value
        saved = devices.document.return_value.collection.return_value.document.return_value.set.call_args.args[0]
        for field in envelope:
            if field != "deviceId":
                self.assertEqual(saved[field], envelope[field])


if __name__ == "__main__":
    unittest.main()
