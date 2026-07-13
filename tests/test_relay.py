from __future__ import annotations

import hashlib
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
        if path.endswith("/devices/list"):
            registrations = [
                request_payload
                for request_path, request_payload, _ in self.requests
                if request_path.endswith("/devices")
            ]
            return {
                "devices": [
                    {
                        "id": hashlib.sha256(
                            str(registration["fcmToken"]).encode("utf-8")
                        ).hexdigest()[:12]
                    }
                    for registration in registrations
                ]
            }
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


class _ClaimedActivationRelay(_ActivationRelay):
    def _request(self, path: str, payload: dict, *, signed: bool) -> dict:
        self.requests.append((path, payload, signed))
        if path.endswith("/status"):
            return {"claimed": True, "agentId": "agent_claimed"}
        return super()._request(path, payload, signed=signed)


class RelayTest(unittest.TestCase):
    def test_pair_page_refresh_adopts_claim_before_serving_second_app(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _ClaimedActivationRelay(str(Path(directory) / "identity.json"))
            relay._state["activation"] = {
                "id": "activation_claimed",
                "secret": "secret_claimed",
                "expires_at": 9999999999.0,
            }

            activation = relay.activation()

            self.assertEqual(activation, {})
            self.assertTrue(relay.configured)
            self.assertEqual(relay.status()["agentId"], "agent_claimed")

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

    def test_corrupt_activation_expiry_does_not_break_pairing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _ActivationRelay(str(Path(directory) / "identity.json"))
            relay._state["activation"] = {
                "id": "activation_old",
                "secret": "secret_old",
                "expires_at": "not-a-timestamp",
            }

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

    def test_live_call_activity_stays_in_feed_without_push_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            relay.observe(
                [
                    {
                        "id": f"sig_{kind}",
                        "kind": kind,
                        "state": "active",
                        "category": "activity",
                        "importance": "feed",
                        "title": "Live call activity",
                    }
                    for kind in (
                        "call_active",
                        "pbx_live_calls_activity",
                        "trunk_active",
                        "trunk_call_active",
                    )
                ]
            )

            self.assertEqual(relay.requests, [])

    def test_registers_paired_device_with_notification_preferences(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            result = relay.register_device(
                fcm_token="token-123",
                meaningful=False,
                activity=False,
            )

            self.assertEqual(
                result,
                {"configured": True, "queued": False, "delivered": True},
            )
            registration_request = next(
                request
                for request in relay.requests
                if request[0] == "/v1/agents/agent_test/devices"
            )
            self.assertEqual(registration_request[0], "/v1/agents/agent_test/devices")
            self.assertEqual(
                registration_request[1],
                {
                    "fcmToken": "token-123",
                    "meaningfulEnabled": False,
                    "activityEnabled": False,
                    "platform": "android",
                    "appVersion": "",
                    "deviceModel": "",
                    "deviceName": "",
                    "osVersion": "",
                },
            )

    def test_registration_is_not_ready_until_device_is_visible_in_relay_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            original_request = relay._request

            def missing_from_list(path: str, payload: dict, *, signed: bool) -> dict:
                if path.endswith("/devices/list"):
                    relay.requests.append((path, payload, signed))
                    return {"devices": []}
                return original_request(path, payload, signed=signed)

            relay._request = missing_from_list  # type: ignore[method-assign]

            result = relay.register_device(
                fcm_token="token-123",
                meaningful=True,
                activity=True,
            )

            self.assertEqual(
                result,
                {"configured": True, "queued": True, "delivered": False},
            )

    def test_registers_optional_app_and_device_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))

            relay.register_device(
                fcm_token="token-123",
                meaningful=True,
                activity=False,
                platform="android",
                app_version="0.2.86-beta+208",
                device_model="Pixel 8",
                device_name="Work phone",
                os_version="16",
            )

            registration = next(
                payload for path, payload, _ in relay.requests if path.endswith("/devices")
            )
            self.assertEqual(registration["appVersion"], "0.2.86-beta+208")
            self.assertEqual(registration["deviceModel"], "Pixel 8")
            self.assertEqual(registration["deviceName"], "Work phone")
            self.assertEqual(registration["osVersion"], "16")

    def test_device_registration_advances_pair_page_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            initial_revision = relay.status()["deviceRegistrationRevision"]

            relay.register_device(
                fcm_token="token-123",
                meaningful=True,
                activity=True,
            )

            self.assertEqual(
                relay.status()["deviceRegistrationRevision"],
                int(initial_revision) + 1,
            )

    def test_queued_registration_does_not_redirect_before_relay_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            relay._state.pop("agent_id")
            initial_revision = relay.status()["deviceRegistrationRevision"]
            initial_attempt_revision = relay.status()["deviceRegistrationAttemptRevision"]

            relay.register_device(
                fcm_token="token-123",
                meaningful=True,
                activity=True,
            )

            self.assertEqual(
                relay.status()["deviceRegistrationRevision"],
                initial_revision,
            )
            self.assertEqual(
                relay.status()["deviceRegistrationAttemptRevision"],
                int(initial_attempt_revision) + 1,
            )

            relay._state["agent_id"] = "agent_test"
            relay._flush()

            self.assertEqual(
                relay.status()["deviceRegistrationRevision"],
                int(initial_revision) + 1,
            )

    def test_lists_only_relay_sanitized_device_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))

            def list_response(path: str, payload: dict, *, signed: bool) -> dict:
                relay.requests.append((path, payload, signed))
                return {"devices": [{"id": "abc123", "deviceModel": "Pixel 8"}]}

            relay._request = list_response  # type: ignore[method-assign]
            result = relay.devices()

            self.assertTrue(result["available"])
            self.assertEqual(result["devices"], [{"id": "abc123", "deviceModel": "Pixel 8"}])
            self.assertEqual(relay.requests[-1], ("/v1/agents/agent_test/devices/list", {}, True))

    def test_device_list_treats_first_pairing_as_an_empty_setup_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            relay._state.pop("agent_id")

            result = relay.devices()

            self.assertFalse(result["available"])
            self.assertEqual(result["state"], "notEnrolled")
            self.assertEqual(result["devices"], [])

    def test_queues_device_registration_until_qr_enrollment_completes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            relay._state.pop("agent_id")

            result = relay.register_device(
                fcm_token="token-123",
                meaningful=True,
                activity=True,
            )

            self.assertEqual(
                result,
                {"configured": False, "queued": True, "delivered": False},
            )
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
