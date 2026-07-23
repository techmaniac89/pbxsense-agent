from __future__ import annotations

import time
import unittest

from pbxsense_agent.internet_relay import SecureInternetRelay


class SecureInternetRelayTest(unittest.TestCase):
    def test_ping_is_answered_on_the_next_outbound_exchange(self) -> None:
        payloads: list[dict[str, object]] = []

        def exchange(payload: dict[str, object]) -> dict:
            payloads.append(payload)
            if len(payloads) == 1:
                return {"commands": [{
                    "id": "command_ping",
                    "type": "ping",
                    "expiresAt": int(time.time()) + 30,
                }]}
            return {"commands": []}

        relay = SecureInternetRelay(
            enabled=True, exchange=exchange, agent_version="test"
        )
        relay.poll()
        relay.poll()

        self.assertEqual(
            payloads[0]["capabilities"], ["ping", "encryptedSnapshotV1"]
        )
        self.assertEqual(payloads[1]["responses"], [{
            "id": "command_ping", "status": "ok", "kind": "pong"
        }])
        self.assertTrue(relay.status()["connected"])

    def test_expired_and_malformed_commands_are_ignored(self) -> None:
        relay = SecureInternetRelay(
            enabled=True,
            exchange=lambda _: {"commands": [
                {"id": "expired", "type": "ping", "expiresAt": 1},
                {"id": "contains spaces", "type": "ping", "expiresAt": 9999999999},
            ]},
            agent_version="test",
        )
        relay.poll()
        captured: list[dict[str, object]] = []
        relay._exchange = lambda payload: captured.append(payload) or {"commands": []}
        relay.poll()
        self.assertEqual(captured, [])

    def test_disabled_relay_never_opens_an_exchange(self) -> None:
        calls = 0

        def exchange(_: dict[str, object]) -> dict:
            nonlocal calls
            calls += 1
            return {}

        relay = SecureInternetRelay(
            enabled=False, exchange=exchange, agent_version="test"
        )
        relay.poll()
        self.assertEqual(calls, 0)
        self.assertFalse(relay.status()["enabled"])

    def test_accepts_bounded_server_control_exchange_policy(self) -> None:
        relay = SecureInternetRelay(
            enabled=True,
            exchange=lambda _: {
                "commands": [],
                "policy": {"controlExchangeSeconds": 600},
            },
            agent_version="test",
        )

        relay.poll()

        self.assertEqual(relay.status()["controlExchangeSeconds"], 600)

        relay._accept_policy({"controlExchangeSeconds": 30})
        self.assertEqual(relay.status()["controlExchangeSeconds"], 600)
