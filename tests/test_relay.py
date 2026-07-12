from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pbxsense_agent.relay import AgentRelay


class _RecordingRelay(AgentRelay):
    def __init__(self, path: str) -> None:
        super().__init__(
            url="https://relay.example",
            claim_code="claim-code",
            identity_path=path,
            display_name="Test PBX",
        )
        self.requests: list[tuple[str, dict, bool]] = []

    def _request(self, path: str, payload: dict, *, signed: bool) -> dict:
        self.requests.append((path, payload, signed))
        if path == "/v1/agents/enroll":
            return {"agentId": "agent_test"}
        return {"status": "accepted"}


class RelayTest(unittest.TestCase):
    def test_enrolls_once_and_queues_only_eligible_signals(self) -> None:
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

            self.assertEqual(relay.status()["agentId"], "agent_test")
            self.assertEqual(
                [request[0] for request in relay.requests],
                ["/v1/agents/enroll", "/v1/agents/agent_test/events"],
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
            self.assertEqual(len(relay.requests), 2)

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
