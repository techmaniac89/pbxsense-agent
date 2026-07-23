from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pbxsense_agent.relay import (
    AgentRelay,
    RelayRequestError,
    _encrypt_snapshot_for_device,
    _secure_snapshot_projection,
)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: object) -> bytes:
    text = str(value)
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


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
                        "id": registration.get("relayDeviceId") or hashlib.sha256(
                            str(registration["fcmToken"]).encode("utf-8")
                        ).hexdigest()[:12]
                    }
                    for registration in registrations
                ]
            }
        return {"status": "accepted"}


class _ActivationRelay(AgentRelay):
    def __init__(self, path: str, enrollment_ticket: str = "") -> None:
        super().__init__(
            url="https://relay.example",
            identity_path=path,
            display_name="Test PBX",
            enrollment_ticket=enrollment_ticket,
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


class _SecureExchangeRelay(_RecordingRelay):
    def _request(
        self,
        path: str,
        payload: dict,
        *,
        signed: bool,
        replay_protected: bool = False,
    ) -> dict:
        self.requests.append((path, payload, replay_protected))
        if path.endswith("/secure/snapshots"):
            return {"stored": len(payload.get("envelopes", []))}
        return {"protocolVersion": 1, "commands": []}


class RelayTest(unittest.TestCase):
    def test_new_relay_activation_is_signed_and_carries_provisioned_ticket(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _ActivationRelay(
                str(Path(directory) / "identity.json"),
                enrollment_ticket="ticket_provisioned",
            )

            relay.activation()

            path, payload, signed = relay.requests[-1]
            self.assertEqual(path, "/v1/activations")
            self.assertEqual(payload["enrollmentTicket"], "ticket_provisioned")
            self.assertTrue(signed)

    def test_secure_projection_exposes_only_customer_facing_relay_status(self) -> None:
        projected = _secure_snapshot_projection({
            "connection": {"pbxHost": "10.0.0.1", "pbxPort": 5038},
            "internetRelay": {
                "enabled": True, "connected": True, "lastError": "",
                "sessionId": "private-session", "lastExchangeAt": 123,
            },
            "calls": [],
        })
        self.assertEqual(projected["internetRelay"], {
            "enabled": True, "connected": True, "lastError": "",
        })

    def test_unchanged_snapshot_is_not_rewritten_on_a_timer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _SecureExchangeRelay(str(Path(directory) / "identity.json"))
            app_private = X25519PrivateKey.generate()
            public = app_private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            relay._secure_devices = [{
                "id": "device_test", "encryptionPublicKey": _b64(public),
            }]
            relay._secure_devices_refreshed_at = time.monotonic()

            self.assertEqual(relay.publish_secure_snapshot({"mood": "Quiet"}), 1)
            self.assertEqual(relay.publish_secure_snapshot({"mood": "Quiet"}), 0)
            writes = [path for path, _, _ in relay.requests
                      if path.endswith("/secure/snapshots")]
            self.assertEqual(len(writes), 1)

    def test_secure_snapshot_is_end_to_end_decryptable_by_only_the_app_key(self) -> None:
        app_private = X25519PrivateKey.generate()
        app_public = app_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        plaintext = json.dumps({"greeting": "Good morning"}).encode()
        envelope = _encrypt_snapshot_for_device(
            plaintext, "agent_test",
            {"id": "device_test", "encryptionPublicKey": _b64(app_public)}, 7,
        )
        ephemeral = X25519PublicKey.from_public_bytes(_unb64(envelope["ephemeralPublicKey"]))
        key = HKDF(
            algorithm=SHA256(), length=32, salt=_unb64(envelope["salt"]),
            info=b"pbxsense-secure-relay-v1",
        ).derive(app_private.exchange(ephemeral))
        decrypted = AESGCM(key).decrypt(
            _unb64(envelope["nonce"]), _unb64(envelope["ciphertext"]),
            (
                "pbxsense-relay-v1|agent_test|device_test|7|"
                + str(envelope["createdAt"])
            ).encode(),
        )
        self.assertEqual(decrypted, plaintext)

    def test_all_relay_traffic_rejects_plain_http_outside_local_development(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "must use HTTPS"):
                AgentRelay(
                    url="http://relay.example",
                    identity_path=str(Path(directory) / "identity.json"),
                    display_name="Test PBX",
                )

    def test_plain_http_is_allowed_for_local_relay_development(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = AgentRelay(
                url="http://localhost:8080",
                identity_path=str(Path(directory) / "identity.json"),
                display_name="Test PBX",
            )
            self.assertEqual(relay._url, "http://localhost:8080")

    def test_permanent_outbox_error_does_not_block_later_items(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            relay._state["outbox"] = [
                {"kind": "events", "payload": {"id": "invalid"}},
                {"kind": "events", "payload": {"id": "valid"}},
            ]
            attempts = 0

            def request(path: str, payload: dict, *, signed: bool) -> dict:
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise RelayRequestError(400, "Relay returned HTTP 400")
                return {"status": "accepted"}

            relay._request = request  # type: ignore[method-assign]
            relay._flush()

            self.assertEqual(relay._state["outbox"], [])
            self.assertEqual(relay.status()["rejectedOutboxItems"], 1)
            self.assertEqual(attempts, 2)

    def test_secure_exchange_requires_replay_protected_signing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _SecureExchangeRelay(str(Path(directory) / "identity.json"))
            result = relay.secure_exchange({"protocolVersion": 1})
            self.assertEqual(result["protocolVersion"], 1)
            self.assertEqual(
                relay.requests[-1],
                (
                    "/v1/agents/agent_test/secure/exchange",
                    {"protocolVersion": 1},
                    True,
                ),
            )
    def test_pair_page_refresh_adopts_claim_before_serving_second_app(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _ClaimedActivationRelay(str(Path(directory) / "identity.json"))
            relay._state["activation"] = {
                "id": "activation_claimed",
                "secret": "secret_claimed",
                "expires_at": 9999999999.0,
            }

            activation = relay.activation()

            self.assertEqual(
                activation,
                {"id": "activation_new", "secret": "secret_new"},
            )
            self.assertTrue(relay.configured)
            self.assertEqual(relay.status()["agentId"], "agent_claimed")

    def test_enrolled_agent_issues_activation_for_an_additional_app(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _ActivationRelay(str(Path(directory) / "identity.json"))
            relay._state["agent_id"] = "agent_existing"

            activation = relay.activation()

            self.assertEqual(
                activation,
                {"id": "activation_new", "secret": "secret_new"},
            )
            self.assertEqual(relay.requests[0][0], "/v1/activations")
            self.assertEqual(relay.status()["agentId"], "agent_existing")

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

    def test_relay_uses_episode_id_but_ignores_it_for_active_dedupe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            base = {
                "id": "sig_endpoint_200_unavailable",
                "kind": "endpoint_unavailable",
                "state": "active",
                "category": "health",
                "importance": "attention",
                "title": "Phone looks unavailable.",
                "body": "The phone is offline.",
            }
            relay.observe([{**base, "notificationId": "episode_one"}])
            relay.observe([{**base, "notificationId": "episode_restart"}])

            events = [payload for path, payload, _ in relay.requests if path.endswith("/events")]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["id"], "episode_one")
            self.assertEqual(events[0]["signalId"], base["id"])

            relay.observe([])
            relay.observe([{**base, "notificationId": "episode_two"}])
            events = [payload for path, payload, _ in relay.requests if path.endswith("/events")]
            self.assertEqual(len(events), 2)
            self.assertEqual(events[1]["id"], "episode_two")

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

    def test_secure_device_registration_is_confirmed_by_credential_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))

            result = relay.register_device(
                fcm_token="token-123",
                meaningful=True,
                activity=True,
                relay_device_id="device_secure",
                encryption_public_key="app-public-key",
            )

            self.assertTrue(result["delivered"])
            registration = next(
                payload for path, payload, _ in relay.requests if path.endswith("/devices")
            )
            self.assertEqual(registration["relayDeviceId"], "device_secure")
            self.assertEqual(registration["encryptionPublicKey"], "app-public-key")

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

    def test_removes_one_relay_device_by_registration_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))

            self.assertTrue(relay.remove_device(
                fcm_token="", relay_device_id="device_phone_one"
            ))
            self.assertEqual(
                relay.requests[-1],
                (
                    "/v1/agents/agent_test/devices/revoke",
                    {"fcmToken": "", "relayDeviceId": "device_phone_one"},
                    True,
                ),
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

    def test_heartbeats_every_thirty_seconds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            relay = _RecordingRelay(str(Path(directory) / "identity.json"))
            relay._last_heartbeat_at = 100.0

            with patch("pbxsense_agent.relay.time.monotonic", return_value=129.0):
                relay.heartbeat()
            self.assertEqual(relay.requests, [])

            with patch("pbxsense_agent.relay.time.monotonic", return_value=130.0):
                relay.heartbeat()
            self.assertEqual([request[0] for request in relay.requests], ["/v1/agents/agent_test/heartbeat"])
