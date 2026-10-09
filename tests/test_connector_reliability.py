from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from defusedxml import ElementTree as ET

from pbxsense_agent.cucm import CucmClient, CucmError, _merge_inventory_and_registration, _risport_devices
from pbxsense_agent.observations import PbxEndpoint, PbxSnapshot
from pbxsense_agent.presence_history import EndpointLastActiveTracker
from pbxsense_agent.pulse import ActivityTracker, EndpointAvailabilitySignalTracker, _person_presence
from pbxsense_agent.settings import AgentSettings
from pbxsense_agent.yeastar import YeastarClient, YeastarError


class ConnectorReliabilityTest(unittest.TestCase):
    def test_cucm_batches_explicit_device_names_and_parses_real_array_shape(self):
        client = CucmClient(AgentSettings.from_env())
        names = [f"SEP{n:04}" for n in range(1201)]
        def soap(path, body, action):
            self.assertEqual(action, "selectCmDeviceExt")
            root = ET.fromstring(body)
            requested = [node.text for node in root.iter() if node.tag.endswith("}Item")]
            self.assertLessEqual(len(requested), 200)
            return ET.fromstring("<Envelope><CmDevices>" + "".join(
                f"<item><Name>{name}</Name><Status>Registered</Status><IPAddress><item><IP>10.0.0.1</IP></item></IPAddress></item>"
                for name in requested) + "</CmDevices></Envelope>")
        with patch.object(client, "_soap", side_effect=soap) as query:
            result = client._registration_status(names + [names[0]])
        self.assertEqual(len(result), 1201)
        self.assertEqual(query.call_count, 7)
        self.assertEqual(result[names[0]]["ip"], "10.0.0.1")
        self.assertEqual(client._registration_details["missingDevices"], 0)

    def test_partial_cucm_batch_remains_usable_and_total_failure_is_not_healthy(self):
        client = CucmClient(AgentSettings.from_env())
        root = ET.fromstring("<Envelope><CmDevices><item><Name>SEP000</Name><Status>Registered</Status></item></CmDevices></Envelope>")
        with patch.object(client, "_soap", side_effect=[root, CucmError("unavailable")]):
            result = client._registration_status([f"SEP{n:03}" for n in range(201)])
        self.assertIn("SEP000", result)
        self.assertEqual(client._registration_details["failedBatches"], 1)
        with patch.object(client, "_soap", side_effect=CucmError("unavailable")):
            with self.assertRaises(CucmError):
                client._registration_status(["SEP000"])

    def test_cucm_query_budget_is_bounded_and_empty_inventory_needs_no_query(self):
        client = CucmClient(AgentSettings.from_env())
        with patch.object(client, "_soap", return_value=ET.fromstring("<Envelope/>")) as query:
            self.assertEqual(client._registration_status([]), {})
            query.assert_not_called()
            client._registration_status([f"SEP{n:05}" for n in range(10001)])
        self.assertEqual(query.call_count, 50)
        self.assertTrue(client._registration_details["queryLimitReached"])
        self.assertEqual(client._registration_details["missingDevices"], 10001)

    def test_missing_shared_line_device_is_unknown_not_confirmed_offline(self):
        rows = [{"extension": "101", "device_name": name} for name in ("SEP1", "SEP2")]
        unknown = _merge_inventory_and_registration(rows, {"SEP1": {"status": "Unregistered"}})[0]
        self.assertEqual(unknown.health_status, "unknown")
        self.assertEqual(_person_presence(unknown, is_talking=False), ("unknown", "Unknown"))
        down = _merge_inventory_and_registration(rows, {
            "SEP1": {"status": "Unregistered"}, "SEP2": {"status": "Rejected"},
        })[0]
        self.assertEqual(down.device_state, "Unavailable")

    def test_unknown_registration_neither_starts_outage_nor_confirms_recovery(self):
        now = datetime(2026, 10, 9, 12)
        unknown = PbxSnapshot(True, "test", endpoints=[PbxEndpoint("101", "Unknown", health_status="unknown")])
        down = PbxSnapshot(True, "test", endpoints=[PbxEndpoint("101", "Unavailable", health_status="down")])
        health = EndpointAvailabilitySignalTracker(outage_confirmation=timedelta(0))
        activity = ActivityTracker(phone_outage_confirmation=timedelta(0), phone_recovery_confirmation=timedelta(0))
        self.assertEqual(health.observe(unknown, now), set())
        activity.observe(down, now)
        self.assertEqual(health.observe(down, now), {"101"})
        episode = health.notification_ids()["101"]
        self.assertEqual(health.observe(unknown, now + timedelta(minutes=1)), {"101"})
        self.assertEqual(health.notification_ids()["101"], episode)
        events = activity.observe(unknown, now + timedelta(minutes=1))
        self.assertFalse(any(event["kind"] == "pbx_phone_recovered_activity" for event in events))
        with TemporaryDirectory() as directory:
            last = EndpointLastActiveTracker(str(Path(directory) / "activity.json"))
            self.assertEqual(last.observe(unknown, now), {})

    def yeastar(self):
        client = YeastarClient(replace(AgentSettings.from_env(), history_poll_seconds=30))
        for name in ("_endpoints", "_trunks", "_channels", "_queues", "_cdr_calls", "_voicemails"):
            setattr(client, name, Mock(return_value=[]))
        return client

    def test_yeastar_history_failure_does_not_hide_live_core_and_retains_prior_records(self):
        client = self.yeastar()
        calls = []
        messages = []
        client._cdr_calls.return_value = calls
        client._voicemails.return_value = messages
        with patch("pbxsense_agent.yeastar.time.monotonic", return_value=0):
            first = client.snapshot()
        client._cdr_calls.side_effect = YeastarError("history unavailable")
        client._voicemails.side_effect = YeastarError("history unavailable")
        with patch("pbxsense_agent.yeastar.time.monotonic", return_value=30):
            result = client.snapshot()
        self.assertTrue(result.reachable)
        self.assertIs(result.recent_calls, first.recent_calls)
        self.assertIs(result.voicemails, first.voicemails)
        self.assertEqual(set(client._history_errors), {"cdr", "voicemail"})
        client._channels.side_effect = YeastarError("core unavailable")
        with patch("pbxsense_agent.yeastar.time.monotonic", return_value=32):
            self.assertFalse(client.snapshot().reachable)

    def test_yeastar_live_and_history_refresh_independently_and_optional_sources_recover(self):
        client = self.yeastar()
        client._cdr_calls.side_effect = [YeastarError("denied"), []]
        with patch("pbxsense_agent.yeastar.time.monotonic", return_value=0):
            self.assertTrue(client.snapshot().reachable)
        with patch("pbxsense_agent.yeastar.time.monotonic", return_value=2):
            client.snapshot()
        self.assertEqual(client._channels.call_count, 2)
        self.assertEqual(client._cdr_calls.call_count, 1)
        self.assertEqual(client._voicemails.call_count, 1)
        with patch("pbxsense_agent.yeastar.time.monotonic", return_value=30):
            client.snapshot()
        self.assertEqual(client._history_errors, {})
        self.assertEqual(client._history_success["cdr"], 30)

    def test_yeastar_v2_cdr_status_and_duration_map_without_losing_v1(self):
        client = YeastarClient(replace(AgentSettings.from_env(), yeastar_api_version="v2.0"))
        with patch.object(client, "_api", return_value={"data": [{
            "call_from_number": "101", "call_to_number": "102", "last_status": "ABANDONED",
            "call_duration": 42, "time": "2026-10-09 12:00:00",
        }]}):
            call = client._cdr_calls()[0]
        self.assertEqual(call.disposition, "NO ANSWER")
        self.assertEqual(call.duration_seconds, 42)
