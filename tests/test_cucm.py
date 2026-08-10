from __future__ import annotations

import csv
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

from pbxsense_agent.cucm import (
    CucmClient,
    _cucm_trunk_health,
    _merge_inventory_and_registration,
    _perfmon_for_trunk,
    _risport_devices,
    enrich_cucm_trunks_with_history,
)
from pbxsense_agent.engine import build_engine_signals
from pbxsense_agent.history import CdrCall, read_recent_cucm_calls
from pbxsense_agent.jtapi import JtapiBridge, _channel_from_call
from pbxsense_agent.pulse import AmiChannel, AmiEndpoint
from pbxsense_agent.settings import AgentSettings


class CucmConnectorTest(unittest.TestCase):
    def test_bundled_jtapi_bridge_targets_java_8(self) -> None:
        class_file = Path(__file__).parents[1] / "jtapi_bridge" / "classes" / "PBXSenseJtapiBridge.class"
        bytecode = class_file.read_bytes()
        self.assertEqual(bytecode[:4], b"\xca\xfe\xba\xbe")
        self.assertEqual(int.from_bytes(bytecode[6:8], "big"), 52)

    def test_jtapi_is_optional_by_default(self) -> None:
        settings = replace(AgentSettings.from_env(), pbx_type="cucm", mode="cucm")
        diagnostics = JtapiBridge(settings).diagnostics()
        self.assertFalse(diagnostics["jtapiConfigured"])
        self.assertFalse(diagnostics["liveCallsAvailable"])

    def test_jtapi_call_maps_to_agent_live_channel(self) -> None:
        channel = _channel_from_call({
            "id": "cluster-42", "caller": "1001", "destination": "2000",
            "extension": "1001", "state": "Ringing", "duration": "4",
        })
        self.assertEqual(channel.channel, "JTAPI/cluster-42")
        self.assertEqual(channel.caller_number, "1001")
        self.assertEqual(channel.connected_number, "2000")
        self.assertEqual(channel.state, "Ringing")

    def test_cached_core_snapshot_still_refreshes_jtapi_calls(self) -> None:
        settings = replace(AgentSettings.from_env(), pbx_type="cucm", mode="cucm")
        client = CucmClient(settings)
        client._directory_inventory = lambda: []  # type: ignore[method-assign]
        client._registration_status = lambda: {}  # type: ignore[method-assign]
        client._trunk_endpoints = lambda: []  # type: ignore[method-assign]

        class Calls:
            count = 0
            def channels(self) -> list[AmiChannel]:
                self.count += 1
                return [AmiChannel(
                    channel=f"JTAPI/{self.count}", extension="1001", caller="1001",
                    connected="2000", state="Up", linked_id=str(self.count),
                )]
            def diagnostics(self) -> dict[str, object]:
                return {}

        calls = Calls()
        client._jtapi = calls  # type: ignore[assignment]
        first = client.snapshot()
        second = client.snapshot()
        self.assertEqual(first.channels[0].channel, "JTAPI/1")
        self.assertEqual(second.channels[0].channel, "JTAPI/2")

    def test_inventory_and_risport_merge_shared_line_devices(self) -> None:
        endpoints = _merge_inventory_and_registration(
            [
                {"extension": "1001", "device_name": "SEP001", "line_description": "Reception"},
                {"extension": "1001", "device_name": "SEP002", "line_description": "Reception"},
                {"extension": "1002", "device_name": "SEP003", "line_description": "Office"},
            ],
            {
                "SEP001": {"status": "UnRegistered", "ip": ""},
                "SEP002": {"status": "Registered", "ip": "10.0.0.12"},
                "SEP003": {"status": "Rejected", "ip": "10.0.0.13"},
            },
        )

        self.assertEqual(len(endpoints), 2)
        self.assertEqual(endpoints[0].device_state, "Reachable")
        self.assertEqual(endpoints[0].ip_address, "10.0.0.12")
        self.assertEqual(endpoints[1].device_state, "Unavailable")

    def test_trunk_health_requires_options_and_preserves_partial_service(self) -> None:
        self.assertEqual(
            _cucm_trunk_health("Registered", options_ping="enabled"),
            ("healthy", "high"),
        )
        self.assertEqual(
            _cucm_trunk_health("PartiallyRegistered", options_ping="enabled"),
            ("degraded", "high"),
        )
        self.assertEqual(
            _cucm_trunk_health("UnRegistered", options_ping="enabled"),
            ("down", "high"),
        )
        self.assertEqual(
            _cucm_trunk_health("Registered", options_ping="disabled"),
            ("unknown", "low"),
        )

    def test_risport_ext_device_and_perfmon_instance_are_parsed(self) -> None:
        from xml.etree import ElementTree as ET

        root = ET.fromstring("""
          <Envelope><CmDevice><Name>SIP_TRUNK_1</Name><Status>Registered</Status>
          <IPAddress><IP>10.0.0.5</IP></IPAddress><Model>131</Model></CmDevice></Envelope>
        """)
        self.assertEqual(_risport_devices(root)["SIP_TRUNK_1"]["ip"], "10.0.0.5")
        counters = {
            r"\\cucm\Cisco SIP(SIP_TRUNK_1)\CallsActive": 2,
            r"\\cucm\Cisco SIP(SIP_TRUNK_1)\CallsCompleted": 41,
            r"\\cucm\Cisco SIP(OTHER)\CallsActive": 9,
        }
        self.assertEqual(
            _perfmon_for_trunk(counters, "SIP_TRUNK_1"),
            {"CallsActive": 2, "CallsCompleted": 41},
        )

    def test_recent_completed_cdr_corroborates_unknown_trunk_but_not_down(self) -> None:
        now = datetime(2026, 8, 10, 12, 0)
        calls = [CdrCall(
            source="1001", destination="18005551212", disposition="ANSWERED",
            started_at=now - timedelta(minutes=2), duration_seconds=30,
            destination_channel="SIP_TRUNK_1",
        )]
        endpoints = [
            AmiEndpoint(
                extension="SIP_TRUNK_1", device_state="Unknown", role="trunk",
                health_status="unknown", health_confidence="low",
            ),
            AmiEndpoint(
                extension="SIP_TRUNK_1", device_state="OutOfService", role="trunk",
                health_status="down", health_confidence="high",
            ),
        ]
        enriched = enrich_cucm_trunks_with_history(endpoints, calls, now=now)
        self.assertEqual(enriched[0].health_status, "healthy")
        self.assertEqual(enriched[0].health_confidence, "high")
        self.assertEqual(enriched[1].health_status, "down")

    def test_perfmon_activity_does_not_override_explicit_down_trunk(self) -> None:
        settings = replace(
            AgentSettings.from_env(), pbx_type="cucm", mode="cucm",
            cucm_perfmon_enabled=True,
        )
        client = CucmClient(settings)
        client._sip_trunk_inventory = lambda: [{  # type: ignore[method-assign]
            "name": "SIP_TRUNK_1", "description": "Carrier",
            "options_ping": "enabled",
        }]
        client._trunk_registration_status = lambda names: {  # type: ignore[method-assign]
            "SIP_TRUNK_1": {"status": "OutOfService"}
        }
        client._sip_perfmon_counters = lambda: {  # type: ignore[method-assign]
            r"\cucm\Cisco SIP(SIP_TRUNK_1)\CallsActive": 1,
        }

        trunk = client._trunk_endpoints()[0]

        self.assertEqual(trunk.health_status, "down")
        self.assertEqual(trunk.health_confidence, "high")

    def test_cucm_retains_known_trunk_as_unknown_on_service_query_failure(self) -> None:
        settings = replace(AgentSettings.from_env(), pbx_type="cucm", mode="cucm")
        client = CucmClient(settings)
        known = AmiEndpoint(
            extension="SIP_TRUNK_1", device_state="Registered", role="trunk",
            health_status="healthy", health_confidence="high",
        )
        client._directory_inventory = lambda: []  # type: ignore[method-assign]
        client._registration_status = lambda: {}  # type: ignore[method-assign]
        calls = iter(([known], OSError("temporary")))

        def trunks() -> list[AmiEndpoint]:
            value = next(calls)
            if isinstance(value, OSError):
                raise value
            return value

        client._trunk_endpoints = trunks  # type: ignore[method-assign]
        first = client.snapshot()
        client._refresh_after = 0
        second = client.snapshot()

        self.assertEqual(first.endpoints[0].health_status, "healthy")
        self.assertEqual(second.endpoints[0].health_status, "unknown")
        self.assertIn("temporarily unavailable", second.endpoints[0].health_evidence[-1])

    def test_cdr_and_cmr_are_correlated_into_call_quality(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cdr = Path(directory, "cdr")
            cmr = Path(directory, "cmr")
            cdr.mkdir(); cmr.mkdir()
            self._write(cdr / "cdr.csv", [{
                "globalCallID_callManagerId": "1", "globalCallID_callId": "42",
                "dateTimeOrigination": "1784678400", "duration": "90",
                "callingPartyNumber": "1001", "originalCalledPartyNumber": "2000",
                "finalCalledPartyNumber": "1002", "origDeviceName": "SEP001",
                "destDeviceName": "SEP002",
            }])
            self._write(cmr / "cmr.csv", [{
                "globalCallID_callManagerId": "1", "globalCallID_callId": "42",
                "packetsReceived": "950", "numberPacketsLost": "50",
                "jitter": "35", "latency": "170",
            }])

            calls = read_recent_cucm_calls(str(cdr), str(cmr))

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].destination, "1002")
        self.assertEqual(calls[0].packet_loss_percent, 5.0)
        signals = build_engine_signals(
            endpoints=[], queues=[], recent_calls=calls, voicemails=[],
            security_events=[], extension_names={}, now=calls[0].started_at,
        )
        self.assertIn("call_quality_degradation", {signal["kind"] for signal in signals})

    @staticmethod
    def _write(path: Path, rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)


if __name__ == "__main__":
    unittest.main()
