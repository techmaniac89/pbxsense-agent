from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pbxsense_agent.relay import AgentRelay


class _RecordingRelay(AgentRelay):
    def __init__(self, path: str) -> None:
        super().__init__(
            url="https://relay.example",
            identity_path=path,
            display_name="Test PBX",
        )
        self._state["agent_id"] = "agent_test"
        self.requests: list[tuple[str, dict, bool]] = []

    def _request(self, path: str, payload: dict, *, signed: bool) -> dict:
        self.requests.append((path, payload, signed))
        return {"status": "accepted"}


class _ActivationRelay(AgentRelay):
    def __init__(self, path: str) -> None:
        super().__init__(
            url="https://relay.example",
            identity_path=path,
            display_name="Test PBX",
        )
        self.requests: list[tuple[str, dict, bool]] = []

    def _request(self, path: str, payload: dict, *, signed: bool) -> dict:
        self.requests.append((path, payload, signed))
        return {
            "activationId": "activation_new",
            "activationSecret": "secret_new",
            "expiresAt": "2030-01-01T00:10:00+00:00",
        }


class RelayTest(unittest.TestCase):
    def test_expired_activation_is_replaced_in_pairing_qr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _ActivationRelay(str(Path(directory) / "identity.json"))
            relay._state["activation"] = {
                "id": "activation_old",
                "secret": "secret_old",
                "expires_at": 100.0,
            }

            with patch("pbxsense_agent.relay.time.time", return_value=200.0):
                activation = relay.activation()

            self.assertEqual(activation, {"id": "activation_new", "secret": "secret_new"})
            self.assertEqual(relay.requests[0][0], "/v1/activations")

    def test_relay_status_expiry_removes_stale_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _ActivationRelay(str(Path(directory) / "identity.json"))
            relay._state["activation"] = {
                "id": "activation_old",
                "secret": "secret_old",
                "expires_at": 9999999999.0,
            }

            def expired_status(path: str, payload: dict, *, signed: bool) -> dict:
                return {"claimed": False, "expired": True}

            relay._request = expired_status  # type: ignore[method-assign]
            self.assertFalse(relay._ensure_enrolled())
            self.assertNotIn("activation", relay._state)

    def test_queues_only_eligible_signals_for_a_qr_enrolled_agent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            relay.observe(
                [
                    {
                        "id": "sig_activity",
                        "state": "active",
                        "category": "activity",
                        "importance": "feed",
                        "title": "Phone recovered",
                        "body": "101 is online again.",
                    },
                    {
                        "id": "sig_tip",
                        "state": "active",
                        "category": "recommendation",
                        "importance": "feed",
                        "title": "A tip",
                    },
                ]
            )

            self.assertEqual(
                [request[0] for request in relay.requests],
                ["/v1/agents/agent_test/events"],
            )

            relay.observe(
                [
                    {
                        "id": "sig_activity",
                        "state": "active",
                        "category": "activity",
                        "importance": "feed",
                        "title": "Phone recovered",
                        "body": "101 is online again.",
                    }
                ]
            )
            self.assertEqual(len(relay.requests), 1)

    def test_registers_paired_device_with_notification_preferences(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            result = relay.register_device(
                fcm_token="token-123",
                meaningful=False,
                activity=False,
            )

            self.assertEqual(result, {"configured": True, "queued": True})
            self.assertEqual(relay.requests[-1][0], "/v1/agents/agent_test/devices")
            self.assertEqual(
                relay.requests[-1][1],
                {
                    "fcmToken": "token-123",
                    "meaningfulEnabled": False,
                    "activityEnabled": False,
                    "platform": "android",
                },
            )

    def test_queues_device_registration_until_qr_enrollment_completes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            relay._state.pop("agent_id")

            result = relay.register_device(
                fcm_token="token-123",
                meaningful=True,
                activity=True,
            )

            self.assertEqual(result, {"configured": False, "queued": True})
            self.assertEqual(relay.status()["queued"], 1)
            self.assertEqual(relay.requests, [])

    def test_preserves_distinct_device_registrations_while_offline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            relay._state.pop("agent_id")

            relay.register_device(fcm_token="phone-one", meaningful=True, activity=True)
            relay.register_device(fcm_token="phone-two", meaningful=False, activity=True)
            relay.register_device(fcm_token="phone-one", meaningful=False, activity=False)

            queued = relay._state["outbox"]
            self.assertEqual(len(queued), 2)
            self.assertEqual(
                {item["payload"]["fcmToken"] for item in queued},
                {"phone-one", "phone-two"},
            )
            phone_one = next(item for item in queued if item["payload"]["fcmToken"] == "phone-one")
            self.assertFalse(phone_one["payload"]["meaningfulEnabled"])

    def test_heartbeats_every_fifteen_seconds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            relay._last_heartbeat_at = 100.0

            with patch("pbxsense_agent.relay.time.monotonic", return_value=114.0):
                relay.heartbeat()
            self.assertEqual(relay.requests, [])

            with patch("pbxsense_agent.relay.time.monotonic", return_value=115.0):
                relay.heartbeat()
            self.assertEqual([request[0] for request in relay.requests], ["/v1/agents/agent_test/heartbeat"])
