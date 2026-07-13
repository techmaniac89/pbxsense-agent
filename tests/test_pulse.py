from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime, timedelta
from unittest.mock import patch
from zoneinfo import ZoneInfo

from pbxsense_agent.ami import (
    AmiEvent,
    _endpoint_role,
    _endpoints_from_events,
    _number_from_pjsip_value,
    _queues_from_events,
)
from pbxsense_agent.connectors import connector_for_settings
from pbxsense_agent.freeswitch import (
    FreeSwitchClient,
    _channel_from_row,
    _first_integer,
    _pipe_first_column,
    _read_json_cdr_calls,
    _read_voicemails as _read_freeswitch_voicemails,
)
from pbxsense_agent.grandstream import GrandstreamUcmClient
from pbxsense_agent.recordings import find_recording
from pbxsense_agent.history import (
    CdrCall,
    SecurityEvent,
    history_diagnostics,
    read_recent_cdr_calls,
    read_recent_security_events,
    read_recent_voicemails,
)
from pbxsense_agent.live import home_live_events
from pbxsense_agent.network import is_private_or_loopback_host
from pbxsense_agent.pulse import (
    AmiChannel,
    AmiEndpoint,
    AmiQueue,
    AmiSnapshot,
    ActivityTracker,
    EndpointAvailabilitySignalTracker,
    build_home_payload,
)
from pbxsense_agent.settings import AgentSettings, _normalize_pbx_type
from pbxsense_agent.yeastar import YeastarClient, _channels_from_call_response


class PulseMappingTest(unittest.TestCase):
    def test_gui_pbx_names_normalize_to_engine_connectors(self) -> None:
        self.assertEqual(_normalize_pbx_type("freepbx"), "asterisk")
        self.assertEqual(_normalize_pbx_type("issabel"), "asterisk")
        self.assertEqual(_normalize_pbx_type("vitalpbx"), "asterisk")
        self.assertEqual(_normalize_pbx_type("grandstream-ucm"), "grandstream")
        self.assertEqual(_normalize_pbx_type("ucm6300"), "grandstream")
        self.assertEqual(_normalize_pbx_type("fusionpbx"), "freeswitch")
        self.assertEqual(_normalize_pbx_type("yeastar-p-series"), "yeastar")

    def test_connector_factory_can_select_freeswitch(self) -> None:
        settings = AgentSettings(
            mode="freeswitch",
            pbx_type="freeswitch",
            host="127.0.0.1",
            port=5038,
            username="",
            password="",
            freeswitch_host="127.0.0.1",
            freeswitch_port=8021,
            freeswitch_password="secret",
            freeswitch_cdr_json_path="",
            freeswitch_voicemail_path="",
            display_name="FreeSWITCH",
            timeout_seconds=3,
            extension_names={},
            cdr_csv_path="/tmp/Master.csv",
            voicemail_path="/tmp/voicemail",
            timezone="UTC",
            token="",
        )

        connector = connector_for_settings(settings)

        self.assertIsInstance(connector, FreeSwitchClient)

    def test_connector_factory_can_select_yeastar(self) -> None:
        settings = AgentSettings(
            mode="yeastar",
            pbx_type="yeastar",
            host="127.0.0.1",
            port=5038,
            username="",
            password="",
            freeswitch_host="127.0.0.1",
            freeswitch_port=8021,
            freeswitch_password="",
            freeswitch_cdr_json_path="",
            freeswitch_voicemail_path="",
            display_name="Yeastar P-Series",
            timeout_seconds=3,
            extension_names={},
            cdr_csv_path="",
            voicemail_path="",
            timezone="UTC",
            token="",
            yeastar_base_url="https://pbx.example.test",
            yeastar_client_id="client-id",
            yeastar_client_secret="client-secret",
        )

        self.assertIsInstance(connector_for_settings(settings), YeastarClient)

    def test_grandstream_connector_uses_its_own_ami_defaults(self) -> None:
        with patch.dict(
            os.environ,
            {
                "PBXSENSE_PBX_TYPE": "grandstream-ucm",
                "GRANDSTREAM_UCM_AMI_HOST": "ucm.example.test",
            },
            clear=True,
        ):
            settings = AgentSettings.from_env()

        connector = connector_for_settings(settings)

        self.assertEqual(settings.pbx_type, "grandstream")
        self.assertEqual(settings.grandstream_ami_host, "ucm.example.test")
        self.assertEqual(settings.grandstream_ami_port, 7777)
        self.assertFalse(settings.grandstream_ami_tls)
        self.assertIsInstance(connector, GrandstreamUcmClient)

    def test_yeastar_active_call_response_maps_to_snapshot_channels(self) -> None:
        channels = _channels_from_call_response(
            {
                "data": [
                    {
                        "call_id": "call-1",
                        "members": [
                            {
                                "inbound": {
                                    "from": "2105550100",
                                    "to": "1000",
                                    "channel_id": "PJSIP/trunk-1",
                                    "member_status": "RING",
                                }
                            },
                            {
                                "extension": {
                                    "number": "1000",
                                    "channel_id": "PJSIP/1000-1",
                                    "member_status": "RING",
                                }
                            },
                        ],
                    }
                ]
            }
        )

        self.assertEqual(channels[0].caller_number, "2105550100")
        self.assertEqual(channels[0].extension, "1000")
        self.assertEqual(channels[1].endpoint, "1000")
        self.assertEqual(channels[1].linked_id, "call-1")

    def test_yeastar_cdr_maps_recording_metadata_without_exposing_a_vendor_url(self) -> None:
        settings = AgentSettings(
            mode="yeastar",
            pbx_type="yeastar",
            host="",
            port=0,
            username="",
            password="",
            freeswitch_host="",
            freeswitch_port=0,
            freeswitch_password="",
            freeswitch_cdr_json_path="",
            freeswitch_voicemail_path="",
            display_name="Yeastar P-Series",
            timeout_seconds=3,
            extension_names={},
            cdr_csv_path="",
            voicemail_path="",
            timezone="UTC",
            token="",
        )
        client = YeastarClient(settings)
        with patch.object(
            client,
            "_api",
            return_value={
                "data": [
                    {
                        "call_from_number": "1000",
                        "call_to_number": "2105550100",
                        "disposition": "ANSWERED",
                        "time": "2026-07-09 13:30:00",
                        "duration": 42,
                        "record_file": "20260709-1000-2105550100.wav",
                    }
                ]
            },
        ):
            calls = client._cdr_calls()

        self.assertEqual(calls[0].recording_id, "20260709-1000-2105550100.wav")

    def test_yeastar_queue_status_maps_waiting_callers_and_longest_wait(self) -> None:
        settings = AgentSettings(
            mode="yeastar", pbx_type="yeastar", host="", port=0,
            username="", password="", freeswitch_host="", freeswitch_port=0,
            freeswitch_password="", freeswitch_cdr_json_path="",
            freeswitch_voicemail_path="", display_name="Yeastar",
            timeout_seconds=3, extension_names={}, cdr_csv_path="",
            voicemail_path="", timezone="UTC", token="",
        )
        client = YeastarClient(settings)

        def queue_api(endpoint: str, params: dict | None = None) -> dict:
            if endpoint == "queue/search":
                return {"data": [{"id": 3, "number": "6400", "name": "Support"}]}
            return {
                "waiting_calls": 2,
                "waiting_list": [{"duration": 18}, {"duration": 42}],
            }

        with patch.object(client, "_api", side_effect=queue_api):
            queues = client._queues()

        self.assertEqual(queues[0].name, "6400")
        self.assertEqual(queues[0].waiting_callers, 2)
        self.assertEqual(queues[0].longest_wait_seconds, 42)

    def test_recording_locator_never_returns_files_outside_the_configured_root(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            recording = root / "20260626-171943-1000-1001.wav"
            recording.write_bytes(b"audio")

            found = find_recording(str(root), "171943-1000")

        self.assertEqual(found, recording)

    def test_recording_locator_does_not_match_overlapping_call_ids(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "20260626-171943-10001-1001.wav").write_bytes(b"wrong")

            found = find_recording(str(root), "171943-1000")

        self.assertIsNone(found)

    def test_recording_locator_rejects_ambiguous_matches(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a-171943-1000.wav").write_bytes(b"one")
            (root / "b-171943-1000.wav").write_bytes(b"two")

            found = find_recording(str(root), "171943-1000")

        self.assertIsNone(found)

    def test_freeswitch_json_cdr_and_voicemail_paths_are_optional_history_sources(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            cdr_dir = root / "json_cdr"
            cdr_dir.mkdir()
            (cdr_dir / "call.json").write_text(
                '{"variables":{"caller_id_number":"101","destination_number":"102",'
                '"hangup_cause":"NORMAL_CLEARING","start_epoch":"1782493200",'
                '"duration":"33","last_app":"bridge","last_arg":"user/102"}}',
                encoding="utf-8",
            )
            voicemail_dir = root / "voicemail"
            mailbox_dir = voicemail_dir / "default" / "120"
            mailbox_dir.mkdir(parents=True)
            (mailbox_dir / "msg_0001.txt").write_text(
                'username=120\ncaller_id_name=Maria\ncreated_epoch=1782493200\n',
                encoding="utf-8",
            )

            calls = _read_json_cdr_calls(str(cdr_dir))
            voicemails = _read_freeswitch_voicemails(str(voicemail_dir))

        self.assertEqual(calls[0].source, "101")
        self.assertEqual(calls[0].destination, "102")
        self.assertEqual(calls[0].disposition, "ANSWERED")
        self.assertEqual(voicemails[0].mailbox, "120")
        self.assertEqual(voicemails[0].caller, "Maria")

    def test_private_or_loopback_host_detection_for_lan_web_unlock(self) -> None:
        self.assertTrue(is_private_or_loopback_host("127.0.0.1"))
        self.assertTrue(is_private_or_loopback_host("192.168.1.20"))
        self.assertTrue(is_private_or_loopback_host("10.0.0.8"))
        self.assertTrue(is_private_or_loopback_host("172.16.4.5"))
        self.assertTrue(is_private_or_loopback_host("localhost"))
        self.assertFalse(is_private_or_loopback_host("8.8.8.8"))
        self.assertFalse(is_private_or_loopback_host("example.com"))

    def test_freeswitch_channel_row_maps_to_pbxsense_snapshot_channel(self) -> None:
        channel = _channel_from_row(
            {
                "uuid": "call-1",
                "name": "sofia/internal/101@pbx.local",
                "cid_name": "Reception",
                "cid_num": "101",
                "dest": "102",
                "state": "CS_EXECUTE",
                "call_uuid": "bridge-1",
            }
        )

        self.assertEqual(channel.endpoint, "101")
        self.assertEqual(channel.extension, "102")
        self.assertEqual(channel.caller, "Reception")
        self.assertEqual(channel.caller_number, "101")
        self.assertEqual(channel.linked_id, "bridge-1")

    def test_freeswitch_callcenter_queue_output_maps_waiting_count(self) -> None:
        raw = "name|strategy|moh_sound\nsupport@default|longest-idle-agent|moh\n"
        self.assertEqual(_pipe_first_column(raw), ["support@default"])
        self.assertEqual(_first_integer("2"), 2)

    def test_ami_contact_status_refreshes_endpoint_reachability(self) -> None:
        endpoints = _endpoints_from_events(
            [
                AmiEvent(
                    name="EndpointList",
                    fields={
                        "ObjectName": "102",
                        "DeviceState": "Unavailable",
                        "ActiveChannels": "0",
                    },
                ),
                AmiEvent(
                    name="ContactList",
                    fields={
                        "EndpointName": "102",
                        "Status": "Reachable",
                    },
                ),
            ]
        )

        self.assertEqual(endpoints[0].device_state, "Reachable")

    def test_ami_unreachable_contact_stays_unreachable(self) -> None:
        endpoints = _endpoints_from_events(
            [
                AmiEvent(
                    name="EndpointList",
                    fields={
                        "ObjectName": "103",
                        "DeviceState": "Reachable",
                        "ActiveChannels": "0",
                    },
                ),
                AmiEvent(
                    name="ContactList",
                    fields={
                        "EndpointName": "103",
                        "Status": "Unreachable",
                    },
                ),
            ]
        )

        self.assertEqual(endpoints[0].device_state, "Unreachable")

    def test_chan_sip_peers_map_to_endpoints(self) -> None:
        endpoints = _endpoints_from_events(
            [
                AmiEvent(
                    name="PeerEntry",
                    fields={
                        "ObjectName": "102",
                        "Status": "OK (12 ms)",
                        "Description": "Warehouse phone",
                    },
                ),
                AmiEvent(
                    name="PeerEntry",
                    fields={
                        "ObjectName": "cosmote",
                        "Status": "Unreachable",
                        "Description": "Cosmote SIP trunk",
                    },
                ),
            ]
        )

        self.assertEqual(endpoints[0].extension, "102")
        self.assertEqual(endpoints[0].device_state, "Reachable")
        self.assertEqual(endpoints[0].role, "extension")
        self.assertEqual(endpoints[1].device_state, "Unreachable")
        self.assertEqual(endpoints[1].role, "trunk")

    def test_pjsip_uri_can_provide_trunk_number(self) -> None:
        self.assertEqual(
            _number_from_pjsip_value("sip:2105550000@sip.provider.example"),
            "2105550000",
        )
        self.assertEqual(
            _number_from_pjsip_value('"Office" <sip:+302105550000@pbx.example>'),
            "+302105550000",
        )

    def test_ami_queue_status_maps_waiting_callers_and_members(self) -> None:
        queues = _queues_from_events(
            [
                AmiEvent(
                    name="QueueParams",
                    fields={"Queue": "support", "Calls": "2"},
                ),
                AmiEvent(
                    name="QueueEntry",
                    fields={"Queue": "support", "Wait": "34"},
                ),
                AmiEvent(
                    name="QueueEntry",
                    fields={"Queue": "support", "Wait": "95"},
                ),
                AmiEvent(
                    name="QueueMember",
                    fields={"Queue": "support", "Status": "1", "Paused": "0"},
                ),
                AmiEvent(
                    name="QueueMember",
                    fields={"Queue": "support", "Status": "2", "Paused": "0"},
                ),
                AmiEvent(
                    name="QueueMember",
                    fields={"Queue": "support", "Status": "1", "Paused": "1"},
                ),
            ]
        )

        self.assertEqual(len(queues), 1)
        self.assertEqual(queues[0].name, "support")
        self.assertEqual(queues[0].waiting_callers, 2)
        self.assertEqual(queues[0].longest_wait_seconds, 95)
        self.assertEqual(queues[0].available_members, 1)
        self.assertEqual(queues[0].busy_members, 1)
        self.assertEqual(queues[0].paused_members, 1)
        self.assertEqual(queues[0].total_members, 3)

    def test_home_payload_includes_queue_summary_without_caller_details(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                queues=[
                    AmiQueue(
                        name="support",
                        waiting_callers=2,
                        longest_wait_seconds=95,
                        available_members=0,
                        busy_members=1,
                        paused_members=1,
                        total_members=2,
                    )
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(
            payload["queues"],
            [
                {
                    "name": "support",
                    "queue": "support",
                    "status": "needs_attention",
                    "statusText": "2 callers waiting",
                    "detail": "Longest wait 1m 35s · No members available · 1 busy · 1 paused",
                    "waitingCallers": 2,
                    "longestWaitSeconds": 95,
                    "availableMembers": 0,
                    "busyMembers": 1,
                    "pausedMembers": 1,
                    "totalMembers": 2,
                }
            ],
        )

    def test_live_events_describe_changed_home_snapshot_parts(self) -> None:
        previous = {
            "connection": {"kind": "local", "label": "Connected"},
            "now": {"title": "The office is quiet.", "isActive": False},
            "signals": [
                {
                    "id": "sig_old",
                    "title": "Old Signal",
                    "state": "active",
                }
            ],
            "calls": [],
            "people": [
                {
                    "extension": "101",
                    "name": "Reception",
                    "status": "online",
                }
            ],
            "trunks": [
                {
                    "endpoint": "cosmote",
                    "name": "Cosmote",
                    "statusText": "Available",
                }
            ],
            "queues": [
                {"queue": "support", "waitingCallers": 0},
            ],
        }
        current = {
            "connection": {"kind": "reconnecting", "label": "Reconnecting"},
            "now": {"title": "Reception is talking.", "isActive": True},
            "signals": [
                {
                    "id": "sig_old",
                    "title": "Old Signal resolved",
                    "state": "resolved",
                },
                {
                    "id": "sig_new",
                    "title": "New Signal",
                    "state": "active",
                },
            ],
            "calls": [{"title": "Reception is talking.", "isActive": True}],
            "people": [
                {
                    "extension": "101",
                    "name": "Reception",
                    "status": "talking",
                }
            ],
            "trunks": [
                {
                    "endpoint": "cosmote",
                    "name": "Cosmote",
                    "statusText": "Carrying a call",
                }
            ],
            "queues": [
                {"queue": "support", "waitingCallers": 2},
            ],
        }

        events = home_live_events(previous, current)

        self.assertEqual(
            [event["type"] for event in events],
            [
                "connection_updated",
                "call_updated",
                "signal_updated",
                "signal_created",
                "calls_updated",
                "person_updated",
                "trunk_updated",
                "queue_updated",
            ],
        )

    def test_live_events_include_removed_signal(self) -> None:
        events = home_live_events(
            {"signals": [{"id": "sig_phone_recovered"}]},
            {"signals": []},
        )

        self.assertEqual(
            events,
            [{"type": "signal_removed", "data": {"id": "sig_phone_recovered"}}],
        )

    def test_home_payload_maps_active_call_to_signal(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[
                    AmiChannel(
                        channel="PJSIP/101-00000042",
                        extension="101",
                        caller="Maria",
                        connected="Reception",
                        state="Up",
                    )
                ],
                endpoints=[AmiEndpoint(extension="101", device_state="Reachable")],
            ),
            display_name="Office PBX",
            extension_names={"101": "Reception"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["greeting"], "Good evening")
        self.assertEqual(payload["connection"]["kind"], "local")
        self.assertIs(payload["now"]["isActive"], True)
        self.assertEqual(payload["signals"][0]["title"], "Reception is talking to Maria.")
        self.assertEqual(payload["people"][0]["status"], "talking")
        self.assertEqual(payload["people"][0]["presence"], {"state": "on_call", "label": "On a call"})

    def test_person_presence_preserves_explicit_extension_state(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                endpoints=[
                    AmiEndpoint(
                        extension="101",
                        device_state="Reachable",
                        label="Reception",
                        presence="Do Not Disturb",
                    ),
                    AmiEndpoint(
                        extension="102",
                        device_state="Reachable",
                        label="Support",
                        presence="Away",
                    ),
                    AmiEndpoint(
                        extension="103",
                        device_state="Ringing",
                        label="Sales",
                    ),
                    AmiEndpoint(
                        extension="104",
                        device_state="Unavailable",
                        label="Warehouse",
                        presence="Do Not Disturb",
                    ),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        people = {person["extension"]: person for person in payload["people"]}
        self.assertEqual(people["101"]["presence"], {"state": "do_not_disturb", "label": "Do not disturb"})
        self.assertEqual(people["101"]["statusText"], "Do not disturb")
        self.assertEqual(people["102"]["presence"], {"state": "away", "label": "Away"})
        self.assertEqual(people["103"]["presence"], {"state": "ringing", "label": "Ringing"})
        self.assertEqual(people["104"]["presence"], {"state": "offline", "label": "Offline"})

    def test_active_call_overrides_stale_extension_presence(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[
                    AmiChannel(
                        channel="PJSIP/101-00000042",
                        extension="101",
                        caller="Maria",
                        connected="Reception",
                        state="Up",
                    )
                ],
                endpoints=[
                    AmiEndpoint(
                        extension="101",
                        device_state="Reachable",
                        presence="Away",
                    )
                ],
            ),
            display_name="Office PBX",
            extension_names={"101": "Reception"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["people"][0]["presence"]["state"], "on_call")

    def test_unreachable_ami_becomes_health_signal(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=False,
                agent_version="test",
                error="connection refused",
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 9, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["greeting"], "Good morning")
        self.assertEqual(payload["connection"]["kind"], "reconnecting")
        self.assertEqual(payload["signals"][0]["category"], "health")
        self.assertEqual(payload["signals"][0]["importance"], "important")
        self.assertEqual(payload["signals"][0]["technical"]["error"], "connection refused")

    def test_unavailable_endpoint_becomes_attention_signal(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                endpoints=[
                    AmiEndpoint(extension="200", device_state="Unavailable"),
                ],
            ),
            display_name="Office PBX",
            extension_names={"200": "Warehouse"},
            now=datetime(2026, 6, 26, 13, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["greeting"], "Good afternoon")
        self.assertEqual(payload["people"][0]["status"], "unavailable")
        self.assertEqual(payload["signals"][0]["title"], "Warehouse looks unavailable.")
        self.assertEqual(payload["signals"][0]["importance"], "attention")

    def test_endpoint_unavailability_requires_stable_outage_and_recovery(self) -> None:
        tracker = EndpointAvailabilitySignalTracker(
            outage_confirmation=timedelta(minutes=1),
        )
        now = datetime(2026, 7, 12, 10, tzinfo=ZoneInfo("Europe/Athens"))
        unavailable = AmiSnapshot(
            reachable=True,
            agent_version="test",
            endpoints=[AmiEndpoint(extension="200", device_state="Unavailable")],
        )
        reachable = AmiSnapshot(
            reachable=True,
            agent_version="test",
            endpoints=[AmiEndpoint(extension="200", device_state="Reachable")],
        )

        self.assertEqual(tracker.observe(unavailable, now), set())
        self.assertEqual(tracker.observe(unavailable, now + timedelta(seconds=59)), set())
        self.assertEqual(
            tracker.observe(unavailable, now + timedelta(minutes=1)),
            {"200"},
        )

        self.assertEqual(tracker.observe(reachable, now + timedelta(minutes=1, seconds=1)), set())
        self.assertEqual(tracker.observe(unavailable, now + timedelta(minutes=1, seconds=2)), set())
        self.assertEqual(tracker.observe(unavailable, now + timedelta(minutes=3)), {"200"})

        self.assertEqual(tracker.observe(reachable, now + timedelta(minutes=3, seconds=1)), set())
        self.assertEqual(tracker.observe(reachable, now + timedelta(minutes=5, seconds=1)), set())
        self.assertEqual(tracker.observe(unavailable, now + timedelta(minutes=5, seconds=2)), set())
        self.assertEqual(
            tracker.observe(unavailable, now + timedelta(minutes=6, seconds=2)),
            {"200"},
        )

    def test_new_outage_is_not_suppressed_during_recovery_window(self) -> None:
        tracker = EndpointAvailabilitySignalTracker()
        now = datetime(2026, 7, 12, 10, tzinfo=ZoneInfo("Europe/Athens"))
        unavailable = AmiSnapshot(
            reachable=True,
            agent_version="test",
            endpoints=[AmiEndpoint(extension="200", device_state="Unavailable")],
        )
        reachable = AmiSnapshot(
            reachable=True,
            agent_version="test",
            endpoints=[AmiEndpoint(extension="200", device_state="Reachable")],
        )

        self.assertEqual(tracker.observe(unavailable, now), {"200"})
        self.assertEqual(tracker.observe(reachable, now + timedelta(seconds=1)), set())
        self.assertEqual(tracker.observe(unavailable, now + timedelta(seconds=2)), {"200"})

    def test_endpoint_label_is_used_before_manual_extension_name(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[
                    AmiChannel(
                        channel="PJSIP/101-00000042",
                        extension="101",
                        caller="Maria",
                        connected="",
                        state="Up",
                    )
                ],
                endpoints=[
                    AmiEndpoint(
                        extension="101",
                        device_state="Reachable",
                        label="Front Desk",
                    )
                ],
            ),
            display_name="Office PBX",
            extension_names={"101": "Reception"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["people"][0]["name"], "Front Desk")
        self.assertEqual(payload["signals"][0]["title"], "Front Desk is talking to Maria.")

    def test_trunk_is_not_shown_as_person(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                endpoints=[
                    AmiEndpoint(
                        extension="sip-provider",
                        device_state="Reachable",
                        label="Main SIP trunk",
                        role="trunk",
                    ),
                    AmiEndpoint(extension="101", device_state="Reachable"),
                ],
            ),
            display_name="Office PBX",
            extension_names={"101": "Reception"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(len(payload["people"]), 1)
        self.assertEqual(payload["people"][0]["name"], "Reception")
        self.assertEqual(len(payload["trunks"]), 1)
        self.assertEqual(payload["trunks"][0]["name"], "Main SIP trunk")

    def test_unavailable_trunk_becomes_trunk_health_signal(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                endpoints=[
                    AmiEndpoint(
                        extension="sip-provider",
                        device_state="Unavailable",
                        label="Main SIP trunk",
                        role="trunk",
                    ),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["people"], [])
        self.assertEqual(payload["trunks"][0]["available"], False)
        self.assertEqual(payload["signals"][0]["kind"], "trunk_unavailable")
        self.assertEqual(
            payload["signals"][0]["title"],
            "Main SIP trunk looks unavailable.",
        )
        self.assertEqual(payload["signals"][0]["technical"]["role"], "trunk")

    def test_registered_trunk_is_shown_as_working(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                endpoints=[
                    AmiEndpoint(
                        extension="cosmote",
                        device_state="Registered",
                        label="Cosmote",
                        role="trunk",
                    ),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["people"], [])
        self.assertEqual(payload["trunks"][0]["statusText"], "Working")
        self.assertEqual(payload["trunks"][0]["detail"], "Registered and ready")
        self.assertEqual(payload["trunks"][0]["available"], True)

    def test_active_trunk_channel_does_not_create_duplicate_trunk_signal(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[
                    AmiChannel(
                        channel="PJSIP/cosmote-00000044",
                        extension="2105550000",
                        caller="2101234567",
                        connected="",
                        state="Up",
                        endpoint="cosmote",
                        caller_number="102",
                        connected_number="2105550000",
                    )
                ],
                endpoints=[
                    AmiEndpoint(
                        extension="cosmote",
                        device_state="Registered",
                        active_channels=1,
                        label="Cosmote",
                        role="trunk",
                    ),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        trunk_signals = [
            signal for signal in payload["signals"] if signal["technical"].get("role") == "trunk"
        ]
        self.assertEqual(len(trunk_signals), 1)
        self.assertEqual(payload["now"]["title"], "102 is calling 2105550000.")
        self.assertEqual(trunk_signals[0]["title"], "102 is calling 2105550000.")
        self.assertEqual(trunk_signals[0]["technical"]["destination"], "2105550000")

    def test_trunk_call_replaces_dialplan_placeholder_with_trunk_number(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[
                    AmiChannel(
                        channel="PJSIP/cosmote-00000045",
                        extension="s",
                        caller="2101234567",
                        connected="",
                        state="Up",
                        endpoint="cosmote",
                        caller_number="2101234567",
                    )
                ],
                endpoints=[
                    AmiEndpoint(
                        extension="cosmote",
                        device_state="Registered",
                        active_channels=1,
                        label="Cosmote",
                        role="trunk",
                        number="2105550000",
                    ),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        trunk_signals = [
            signal for signal in payload["signals"] if signal["technical"].get("role") == "trunk"
        ]
        self.assertEqual(payload["now"]["title"], "2101234567 is calling 2105550000.")
        self.assertEqual(
            trunk_signals[0]["title"],
            "2101234567 is calling 2105550000.",
        )
        self.assertEqual(trunk_signals[0]["technical"]["destination"], "2105550000")

    def test_unknown_endpoint_name_falls_back_to_number_only(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                endpoints=[AmiEndpoint(extension="205", device_state="Reachable")],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["people"][0]["name"], "205")

    def test_linphone_named_endpoint_is_still_a_person(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                endpoints=[
                    AmiEndpoint(
                        extension="linphone",
                        device_state="Reachable",
                        label="Linphone",
                    ),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(len(payload["people"]), 1)
        self.assertEqual(payload["people"][0]["name"], "Linphone")

    def test_cosmote_endpoint_is_classified_as_trunk(self) -> None:
        self.assertEqual(_endpoint_role("cosmote", {}), "trunk")
        self.assertEqual(
            _endpoint_role("main-line", {"Description": "Cosmote SIP line"}),
            "trunk",
        )

    def test_internal_call_uses_channel_endpoint_and_display_names(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[
                    AmiChannel(
                        channel="PJSIP/102-00000042",
                        extension="103",
                        caller="TechManiac",
                        connected="<unknown>",
                        state="Up",
                        endpoint="102",
                        caller_number="102",
                    )
                ],
                endpoints=[
                    AmiEndpoint(
                        extension="102",
                        device_state="Reachable",
                        label="TechManiac",
                    ),
                    AmiEndpoint(
                        extension="103",
                        device_state="Reachable",
                        label="Support Desk",
                    ),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["now"]["title"], "TechManiac is talking to Support Desk.")
        self.assertEqual(payload["people"][0]["status"], "talking")

    def test_reverse_internal_call_uses_display_name_instead_of_unknown(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[
                    AmiChannel(
                        channel="PJSIP/103-00000043",
                        extension="102",
                        caller="<unknown>",
                        connected="<unknown>",
                        state="Up",
                        endpoint="103",
                        caller_number="103",
                    )
                ],
                endpoints=[
                    AmiEndpoint(
                        extension="102",
                        device_state="Reachable",
                        label="TechManiac",
                    ),
                    AmiEndpoint(
                        extension="103",
                        device_state="Reachable",
                        label="Support Desk",
                    ),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["now"]["title"], "Support Desk is talking to TechManiac.")
        self.assertEqual(payload["people"][1]["status"], "talking")

    def test_mirrored_internal_call_legs_become_one_active_call(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[
                    AmiChannel(
                        channel="PJSIP/102-00000050",
                        extension="linphone",
                        caller="MicroSIP",
                        connected="Linphone",
                        state="Up",
                        endpoint="102",
                        caller_number="102",
                    ),
                    AmiChannel(
                        channel="PJSIP/linphone-00000051",
                        extension="102",
                        caller="Linphone",
                        connected="MicroSIP",
                        state="Up",
                        endpoint="linphone",
                        caller_number="linphone",
                    ),
                ],
                endpoints=[
                    AmiEndpoint(
                        extension="102",
                        device_state="Reachable",
                        label="MicroSIP",
                    ),
                    AmiEndpoint(
                        extension="linphone",
                        device_state="Reachable",
                        label="Linphone",
                    ),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(len(payload["calls"]), 1)
        self.assertEqual(payload["now"]["title"], "MicroSIP is talking to Linphone.")

    def test_mirrored_internal_call_prefers_original_caller_leg(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[
                    AmiChannel(
                        channel="PJSIP/103-00000051",
                        extension="102",
                        caller="MicroSIP",
                        connected="Linphone",
                        state="Up",
                        endpoint="103",
                        caller_number="102",
                        linked_id="bridge-1",
                    ),
                    AmiChannel(
                        channel="PJSIP/102-00000050",
                        extension="103",
                        caller="MicroSIP",
                        connected="Linphone",
                        state="Up",
                        endpoint="102",
                        caller_number="102",
                        linked_id="bridge-1",
                    ),
                ],
                endpoints=[
                    AmiEndpoint(
                        extension="102",
                        device_state="Reachable",
                        label="MicroSIP",
                    ),
                    AmiEndpoint(
                        extension="103",
                        device_state="Reachable",
                        label="Linphone",
                    ),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(len(payload["calls"]), 1)
        self.assertEqual(payload["now"]["title"], "MicroSIP is talking to Linphone.")

    def test_cdr_history_adds_answered_and_missed_calls(self) -> None:
        with TemporaryDirectory() as directory:
            cdr_path = Path(directory) / "Master.csv"
            cdr_path.write_text(
                '"","101","102","from-internal","101","PJSIP/101","PJSIP/102","Dial","","2026-06-26 20:00:00","2026-06-26 20:00:02","2026-06-26 20:01:02","62","60","ANSWERED","","1"\n'
                '"","103","104","from-internal","103","PJSIP/103","","Dial","","2026-06-26 20:05:00","","2026-06-26 20:05:30","30","0","NO ANSWER","","2"\n',
                encoding="utf-8",
            )
            records = read_recent_cdr_calls(str(cdr_path))

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=records,
            ),
            display_name="Office PBX",
            extension_names={"101": "Reception", "102": "Support", "103": "Sales"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        titles = [call["title"] for call in payload["calls"]]
        self.assertIn("Reception called Support.", titles)
        self.assertIn("Sales missed 104.", titles)
        self.assertIn("missed", {call["kind"] for call in payload["calls"]})

    def test_cdr_userfield_adds_a_protected_recording_reference(self) -> None:
        with TemporaryDirectory() as directory:
            cdr_path = Path(directory) / "Master.csv"
            cdr_path.write_text(
                '"","101","102","from-internal","101","PJSIP/101","PJSIP/102","Dial","","2026-06-26 20:00:00","2026-06-26 20:00:02","2026-06-26 20:01:02","62","60","ANSWERED","","1","/var/spool/asterisk/monitor/call-1.wav"\n',
                encoding="utf-8",
            )
            records = read_recent_cdr_calls(str(cdr_path))

        payload = build_home_payload(
            AmiSnapshot(reachable=True, agent_version="test", recent_calls=records),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["calls"][0]["recording"]["id"], "call-1.wav")
        self.assertEqual(payload["calls"][0]["recording"]["url"], "/recordings/call-1.wav")

    def test_cdr_history_does_not_replace_current_moment(self) -> None:
        record = CdrCall(
            source="linphone",
            destination="102",
            disposition="NO ANSWER",
            started_at=datetime(2026, 6, 26, 19, 55),
            duration_seconds=12,
        )

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=[record],
            ),
            display_name="Office PBX",
            extension_names={"linphone": "Linphone", "102": "Support"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["now"]["title"], "The office is quiet.")
        self.assertIn("Linphone missed Support.", [call["title"] for call in payload["calls"]])

    def test_call_history_does_not_create_a_calculated_moment(self) -> None:
        now = datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens"))
        recent_record = CdrCall(
            source="101",
            destination="102",
            disposition="ANSWERED",
            started_at=now.replace(tzinfo=None) - timedelta(hours=2),
            duration_seconds=60,
        )
        old_record = CdrCall(
            source="103",
            destination="104",
            disposition="ANSWERED",
            started_at=now.replace(tzinfo=None) - timedelta(days=2),
            duration_seconds=60,
        )

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=[recent_record, old_record],
            ),
            display_name="Office PBX",
            extension_names={},
            now=now,
            moment_hours=3,
        )

        moments = [
            signal for signal in payload["signals"] if signal["category"] == "moment"
        ]
        self.assertEqual(moments, [])

    def test_activity_tracker_emits_real_pbx_transitions(self) -> None:
        now = datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens"))
        tracker = ActivityTracker()
        active = AmiChannel(
            channel="PJSIP/101-00000042",
            extension="101",
            caller="Maria",
            connected="Reception",
            state="Up",
        )
        tracker.observe(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[active],
                queues=[AmiQueue(name="support", waiting_callers=2)],
                endpoints=[AmiEndpoint(extension="101", device_state="Unavailable")],
            ),
            now,
        )
        events = tracker.observe(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                queues=[AmiQueue(name="support", waiting_callers=0)],
                endpoints=[AmiEndpoint(extension="101", device_state="Reachable")],
            ),
            now + timedelta(minutes=1),
        )

        self.assertEqual(
            {event["kind"] for event in events},
            {
                "pbx_queue_cleared_activity",
                "pbx_phone_recovered_activity",
            },
        )
        payload = build_home_payload(
            AmiSnapshot(reachable=True, agent_version="test"),
            display_name="Office PBX",
            extension_names={},
            now=now + timedelta(minutes=1),
            moment_events=events,
        )
        self.assertEqual(
            {signal["kind"] for signal in payload["signals"] if signal["category"] == "activity"},
            {event["kind"] for event in events},
        )

    def test_activity_tracker_removes_reversed_recovery_and_clear_activity(self) -> None:
        now = datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens"))
        tracker = ActivityTracker()
        active = AmiChannel(
            channel="PJSIP/101-00000042",
            extension="101",
            caller="Maria",
            connected="Reception",
            state="Up",
        )
        tracker.observe(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[active],
                queues=[AmiQueue(name="support", waiting_callers=2)],
                endpoints=[AmiEndpoint(extension="101", device_state="Unavailable")],
            ),
            now,
        )
        tracker.observe(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                queues=[AmiQueue(name="support", waiting_callers=0)],
                endpoints=[AmiEndpoint(extension="101", device_state="Reachable")],
            ),
            now + timedelta(minutes=1),
        )
        events = tracker.observe(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[active],
                queues=[AmiQueue(name="support", waiting_callers=1)],
                endpoints=[AmiEndpoint(extension="101", device_state="Unavailable")],
            ),
            now + timedelta(minutes=2),
        )

        self.assertEqual(events, [])
        events = tracker.observe(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                queues=[AmiQueue(name="support", waiting_callers=1)],
                endpoints=[AmiEndpoint(extension="101", device_state="Reachable")],
            ),
            now + timedelta(minutes=3),
        )

        self.assertFalse(
            any(event["kind"] == "pbx_phone_recovered_activity" for event in events)
        )

    def test_activity_tracker_keeps_last_healthy_state_through_pbx_outage(self) -> None:
        now = datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens"))
        tracker = ActivityTracker()
        tracker.observe(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                endpoints=[AmiEndpoint(extension="101", device_state="Unavailable")],
            ),
            now,
        )
        tracker.observe(
            AmiSnapshot(reachable=False, agent_version="test"),
            now + timedelta(minutes=1),
        )
        events = tracker.observe(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                endpoints=[AmiEndpoint(extension="101", device_state="Reachable")],
            ),
            now + timedelta(minutes=2),
        )

        self.assertEqual(
            [event["kind"] for event in events],
            ["pbx_phone_recovered_activity"],
        )

    def test_activity_tracker_recognizes_unregistered_phone_recovery(self) -> None:
        now = datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens"))
        tracker = ActivityTracker()
        offline_snapshot = AmiSnapshot(
            reachable=True,
            agent_version="test",
            endpoints=[AmiEndpoint(extension="101", device_state="Unregistered")],
        )
        tracker.observe(offline_snapshot, now)

        recovered_snapshot = AmiSnapshot(
            reachable=True,
            agent_version="test",
            endpoints=[AmiEndpoint(extension="101", device_state="Registered")],
        )
        events = tracker.observe(recovered_snapshot, now + timedelta(minutes=1))
        payload = build_home_payload(
            recovered_snapshot,
            display_name="Office PBX",
            extension_names={},
            now=now + timedelta(minutes=1),
            moment_events=events,
        )

        self.assertEqual(
            [event["kind"] for event in events],
            ["pbx_phone_recovered_activity"],
        )
        self.assertTrue(
            any(
                signal["kind"] == "pbx_phone_recovered_activity"
                for signal in payload["signals"]
            )
        )

    def test_cdr_history_replaces_placeholder_destination_with_trunk_number(self) -> None:
        record = CdrCall(
            source="2101234567",
            destination="s",
            disposition="ANSWERED",
            started_at=datetime(2026, 6, 26, 19, 55),
            duration_seconds=20,
            channel="PJSIP/cosmote-00000001",
        )

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                endpoints=[
                    AmiEndpoint(
                        extension="cosmote",
                        device_state="Registered",
                        label="Cosmote",
                        role="trunk",
                        number="2105550000",
                    )
                ],
                recent_calls=[record],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertIn(
            "2101234567 called 2105550000.",
            [call["title"] for call in payload["calls"]],
        )

    def test_voicemail_spool_adds_voicemail_calls(self) -> None:
        with TemporaryDirectory() as directory:
            message_path = Path(directory) / "default" / "120" / "INBOX"
            message_path.mkdir(parents=True)
            (message_path / "msg0000.txt").write_text(
                'callerid="Maria"\norigtime=1782493200\n',
                encoding="utf-8",
            )
            messages = read_recent_voicemails(directory)

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                voicemails=messages,
            ),
            display_name="Office PBX",
            extension_names={"120": "Support"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        self.assertEqual(payload["calls"][0]["kind"], "voicemail")
        self.assertEqual(payload["calls"][0]["title"], "Maria left Support a voicemail.")

    def test_history_diagnostics_reports_cdr_and_voicemail_visibility(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            cdr_path = root / "Master.csv"
            cdr_path.write_text(
                '"","101","102","from-internal","101","PJSIP/101","PJSIP/102","Dial","","2026-06-26 20:00:00","2026-06-26 20:00:02","2026-06-26 20:01:02","62","60","ANSWERED","","1"\n',
                encoding="utf-8",
            )
            voicemail_path = root / "voicemail" / "default" / "120" / "INBOX"
            voicemail_path.mkdir(parents=True)
            (voicemail_path / "msg0000.txt").write_text(
                'callerid="Maria"\norigtime=1782493200\n',
                encoding="utf-8",
            )

            diagnostics = history_diagnostics(
                str(cdr_path),
                str(root / "voicemail"),
            )

        self.assertTrue(diagnostics["cdrCsvExists"])
        self.assertTrue(diagnostics["cdrCsvReadable"])
        self.assertEqual(diagnostics["cdrRecentRowsReadable"], 1)
        self.assertTrue(diagnostics["voicemailPathExists"])
        self.assertEqual(diagnostics["voicemailMessagesReadable"], 1)

    def test_history_readers_tolerate_permission_denied_paths(self) -> None:
        with patch.object(Path, "is_file", side_effect=PermissionError("denied")):
            self.assertEqual(read_recent_cdr_calls("/private/Master.csv"), [])
            diagnostics = history_diagnostics("/private/Master.csv", "/tmp/voicemail")

        self.assertFalse(diagnostics["cdrCsvExists"])
        self.assertFalse(diagnostics["cdrCsvReadable"])
        self.assertIn("denied", diagnostics["cdrCsvAccessError"])

        with patch.object(Path, "is_dir", side_effect=PermissionError("denied")):
            self.assertEqual(read_recent_voicemails("/private/voicemail"), [])
            diagnostics = history_diagnostics("/tmp/Master.csv", "/private/voicemail")

        self.assertFalse(diagnostics["voicemailPathExists"])
        self.assertFalse(diagnostics["voicemailPathReadable"])
        self.assertIn("denied", diagnostics["voicemailPathAccessError"])

    def test_pulse_engine_adds_tip_for_repeated_missed_calls(self) -> None:
        calls = [
            CdrCall(
                source="101",
                destination="120",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 30),
                duration_seconds=0,
            ),
            CdrCall(
                source="102",
                destination="120",
                disposition="BUSY",
                started_at=datetime(2026, 6, 26, 19, 40),
                duration_seconds=0,
            ),
        ]

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=calls,
                endpoints=[AmiEndpoint(extension="120", device_state="Reachable")],
            ),
            display_name="Office PBX",
            extension_names={"120": "Support"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        tips = [signal for signal in payload["signals"] if signal["category"] == "recommendation"]
        self.assertEqual(tips[0]["kind"], "missed_call_pattern")
        self.assertEqual(tips[0]["title"], "Support missed 2 recent calls.")

    def test_pulse_engine_deduplicates_cdr_legs_for_one_missed_call(self) -> None:
        calls = [
            CdrCall(
                source="2100000000",
                destination="120",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 30, 1),
                duration_seconds=0,
                channel="PJSIP/trunk-00000001",
                destination_channel="PJSIP/120-00000002",
                last_app="Dial",
                last_data="PJSIP/120,30",
            ),
            CdrCall(
                source="2100000000",
                destination="120",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 30, 2),
                duration_seconds=0,
                channel="PJSIP/trunk-00000001",
                destination_channel="PJSIP/120-00000003",
                last_app="Dial",
                last_data="PJSIP/120,30",
            ),
        ]

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=calls,
                endpoints=[AmiEndpoint(extension="120", device_state="Reachable")],
            ),
            display_name="Office PBX",
            extension_names={"120": "Support"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        tips = [
            signal
            for signal in payload["signals"]
            if signal["kind"] == "missed_call_pattern"
        ]
        insights = [
            signal
            for signal in payload["signals"]
            if signal["kind"] == "call_mix_insight"
        ]

        self.assertEqual(tips, [])
        self.assertEqual(insights[0]["technical"]["missed_calls"], "1")

    def test_pulse_engine_ignores_non_endpoint_missed_call_destinations(self) -> None:
        calls = [
            CdrCall(
                source="101",
                destination="1",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 30),
                duration_seconds=0,
            ),
            CdrCall(
                source="102",
                destination="1",
                disposition="BUSY",
                started_at=datetime(2026, 6, 26, 19, 40),
                duration_seconds=0,
            ),
            CdrCall(
                source="103",
                destination="120",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 50),
                duration_seconds=0,
            ),
            CdrCall(
                source="104",
                destination="120",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 55),
                duration_seconds=0,
            ),
        ]

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=calls,
                endpoints=[AmiEndpoint(extension="120", device_state="Reachable")],
            ),
            display_name="Office PBX",
            extension_names={"120": "Support"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        tips = [signal for signal in payload["signals"] if signal["category"] == "recommendation"]
        self.assertEqual(len(tips), 1)
        self.assertEqual(tips[0]["technical"]["extension"], "120")

    def test_pulse_engine_resolves_ivr_option_to_dialed_phones(self) -> None:
        calls = [
            CdrCall(
                source="2100000000",
                destination="1",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 30),
                duration_seconds=0,
                last_app="Dial",
                last_data="PJSIP/102&PJSIP/103,30",
            ),
            CdrCall(
                source="2100000001",
                destination="1",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 40),
                duration_seconds=0,
                last_app="Dial",
                last_data="PJSIP/102&PJSIP/103,30",
            ),
        ]

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=calls,
                endpoints=[
                    AmiEndpoint(extension="102", device_state="Reachable"),
                    AmiEndpoint(extension="103", device_state="Reachable"),
                ],
            ),
            display_name="Office PBX",
            extension_names={"102": "MicroSIP", "103": "Linphone"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        titles = [
            signal["title"]
            for signal in payload["signals"]
            if signal["category"] == "recommendation"
        ]
        self.assertIn("MicroSIP missed 2 recent calls.", titles)
        self.assertIn("Linphone missed 2 recent calls.", titles)

    def test_pulse_engine_resolves_s_extension_to_dialed_phone(self) -> None:
        calls = [
            CdrCall(
                source="2100000000",
                destination="s",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 30),
                duration_seconds=0,
                last_app="Dial",
                last_data="SIP/102,25",
            ),
            CdrCall(
                source="2100000001",
                destination="s",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 40),
                duration_seconds=0,
                last_app="Dial",
                last_data="SIP/102,25",
            ),
        ]

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=calls,
                endpoints=[AmiEndpoint(extension="102", device_state="Reachable")],
            ),
            display_name="Office PBX",
            extension_names={"102": "MicroSIP"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        tips = [signal for signal in payload["signals"] if signal["category"] == "recommendation"]
        self.assertEqual(len(tips), 1)
        self.assertEqual(tips[0]["title"], "MicroSIP missed 2 recent calls.")

    def test_pulse_engine_adds_call_mix_insight(self) -> None:
        calls = [
            CdrCall(
                source="101",
                destination="102",
                disposition="ANSWERED",
                started_at=datetime(2026, 6, 26, 19, 30),
                duration_seconds=60,
            ),
            CdrCall(
                source="103",
                destination="104",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 40),
                duration_seconds=0,
            ),
        ]

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=calls,
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        insights = [signal for signal in payload["signals"] if signal["category"] == "insight"]
        self.assertEqual(insights[0]["kind"], "call_mix_insight")
        self.assertEqual(insights[0]["technical"]["answered_calls"], "1")
        self.assertEqual(insights[0]["technical"]["missed_calls"], "1")

    def test_pulse_engine_adds_security_signal_for_failed_call_cluster(self) -> None:
        calls = [
            CdrCall(
                source=str(index),
                destination="900",
                disposition="FAILED",
                started_at=datetime(2026, 6, 26, 19, 50 + index),
                duration_seconds=0,
            )
            for index in range(3)
        ]

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=calls,
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        security = [signal for signal in payload["signals"] if signal["category"] == "security"]
        self.assertEqual(security[0]["kind"], "failed_call_cluster")
        self.assertEqual(security[0]["technical"]["attempts"], "3")

    def test_old_failed_calls_do_not_create_a_security_cluster(self) -> None:
        calls = [
            CdrCall(
                source=str(index),
                destination="900",
                disposition="FAILED",
                started_at=datetime(2026, 6, 26, 19, index),
                duration_seconds=0,
            )
            for index in range(3)
        ]
        payload = build_home_payload(
            AmiSnapshot(reachable=True, agent_version="test", recent_calls=calls),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        kinds = {signal["kind"] for signal in payload["signals"]}
        self.assertNotIn("failed_call_cluster", kinds)

    def test_security_log_events_create_authentication_signal_without_sensitive_data(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                security_events=[
                    SecurityEvent("InvalidPassword", "AMI", datetime(2026, 6, 26, 19, 50)),
                    SecurityEvent("InvalidAccountID", "SIP", datetime(2026, 6, 26, 19, 52)),
                    SecurityEvent("ChallengeResponseFailed", "AMI", datetime(2026, 6, 26, 19, 54)),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        security = [signal for signal in payload["signals"] if signal["category"] == "security"]
        authentication = next(signal for signal in security if signal["kind"] == "authentication_failure_cluster")
        self.assertEqual(authentication["technical"]["attempts"], "3")
        self.assertEqual(authentication["technical"]["services"], "AMI, SIP")
        self.assertNotIn("RemoteAddress", str(authentication))

    def test_security_log_reader_filters_old_entries_and_parses_acl_failures(self) -> None:
        with TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "security"
            log_path.write_text(
                '\n'.join(
                    [
                        '[2026-06-26 19:40:00] SECURITY[1]: SecurityEvent="FailedACL",Service="AMI",RemoteAddress="IPV4/TCP/10.0.0.5/5000"',
                        '[2026-06-26 19:55:00] SECURITY[1]: SecurityEvent="FailedACL",Service="SIP",RemoteAddress="IPV4/UDP/10.0.0.6/5060"',
                        '[2026-06-26 19:58:00] SECURITY[1]: SecurityEvent="InvalidPassword",Service="AMI",RemoteAddress="IPV4/TCP/10.0.0.7/5001"',
                    ]
                ),
                encoding="utf-8",
            )

            events = read_recent_security_events(
                str(log_path),
                now=datetime(2026, 6, 26, 20, 0),
            )

        self.assertEqual([(event.kind, event.service) for event in events], [("FailedACL", "SIP"), ("InvalidPassword", "AMI")])

    def test_malformed_request_cluster_becomes_security_signal(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                security_events=[
                    SecurityEvent("RequestBadFormat", "AMI", datetime(2026, 6, 26, 19, 51)),
                    SecurityEvent("RequestBadFormat", "AMI", datetime(2026, 6, 26, 19, 53)),
                    SecurityEvent("RequestBadFormat", "AMI", datetime(2026, 6, 26, 19, 55)),
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        kinds = {signal["kind"] for signal in payload["signals"]}
        self.assertIn("malformed_request_cluster", kinds)

    def test_unavailable_trunk_stays_in_health_not_security(self) -> None:
        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                endpoints=[
                    AmiEndpoint(
                        extension="sip-provider",
                        device_state="Unavailable",
                        role="trunk",
                    )
                ],
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        trunk = next(signal for signal in payload["signals"] if signal["kind"] == "trunk_unavailable")
        self.assertEqual(trunk["category"], "health")
        self.assertFalse(any(signal["kind"] == "trunk_security_watch" for signal in payload["signals"]))

    def test_home_payload_can_carry_every_current_signal_category(self) -> None:
        calls = [
            CdrCall(
                source="101",
                destination="120",
                disposition="NO ANSWER",
                started_at=datetime(2026, 6, 26, 19, 30),
                duration_seconds=0,
            ),
            CdrCall(
                source="102",
                destination="120",
                disposition="BUSY",
                started_at=datetime(2026, 6, 26, 19, 40),
                duration_seconds=0,
            ),
            CdrCall(
                source="901",
                destination="900",
                disposition="FAILED",
                started_at=datetime(2026, 6, 26, 19, 45),
                duration_seconds=0,
            ),
            CdrCall(
                source="902",
                destination="900",
                disposition="FAILED",
                started_at=datetime(2026, 6, 26, 19, 46),
                duration_seconds=0,
            ),
            CdrCall(
                source="903",
                destination="900",
                disposition="FAILED",
                started_at=datetime(2026, 6, 26, 19, 47),
                duration_seconds=0,
            ),
        ]

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                channels=[
                    AmiChannel(
                        channel="PJSIP/101-00000042",
                        extension="120",
                        caller="Reception",
                        connected="Support",
                        state="Up",
                        endpoint="101",
                        caller_number="101",
                    )
                ],
                endpoints=[
                    AmiEndpoint(extension="101", device_state="Reachable"),
                    AmiEndpoint(extension="120", device_state="Reachable"),
                    AmiEndpoint(extension="200", device_state="Unavailable"),
                ],
                recent_calls=calls,
            ),
            display_name="Office PBX",
            extension_names={
                "101": "Reception",
                "120": "Support",
                "200": "Warehouse",
            },
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        categories = {signal["category"] for signal in payload["signals"]}
        self.assertEqual(
            categories,
            {
                "activity",
                "health",
                "security",
                "insight",
                "recommendation",
            },
        )

    def test_pulse_engine_learns_weekday_volume_pattern(self) -> None:
        calls: list[CdrCall] = []
        for day in (1, 2, 3, 4):
            calls.append(
                CdrCall(
                    source=str(day),
                    destination="120",
                    disposition="ANSWERED",
                    started_at=datetime(2026, 6, day, 9),
                    duration_seconds=30,
                )
            )
        for day in (5, 12, 19):
            for index in range(4):
                calls.append(
                    CdrCall(
                        source=str(100 + index),
                        destination="120",
                        disposition="ANSWERED",
                        started_at=datetime(2026, 6, day, 10, index),
                        duration_seconds=30,
                    )
                )
        for index in range(9):
            calls.append(
                CdrCall(
                    source=str(200 + index),
                    destination="120",
                    disposition="ANSWERED",
                    started_at=datetime(2026, 6, 26, 10, index),
                    duration_seconds=30,
                )
            )

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=calls,
            ),
            display_name="Office PBX",
            extension_names={},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        titles = [
            signal["title"]
            for signal in payload["signals"]
            if signal["kind"] == "weekday_volume_pattern"
        ]
        self.assertIn("Today is busier than this weekday usually is.", titles)

    def test_pulse_engine_recommends_when_missed_rate_is_higher_than_usual(self) -> None:
        calls: list[CdrCall] = []
        for day in range(10, 20):
            for index in range(2):
                calls.append(
                    CdrCall(
                        source=f"{day}{index}",
                        destination="120",
                        disposition="ANSWERED",
                        started_at=datetime(2026, 6, day, 10, index),
                        duration_seconds=30,
                    )
                )
        for index in range(6):
            calls.append(
                CdrCall(
                    source=str(200 + index),
                    destination="120",
                    disposition="NO ANSWER" if index < 4 else "ANSWERED",
                    started_at=datetime(2026, 6, 26, 11, index),
                    duration_seconds=0,
                )
            )

        payload = build_home_payload(
            AmiSnapshot(
                reachable=True,
                agent_version="test",
                recent_calls=calls,
                endpoints=[AmiEndpoint(extension="120", device_state="Reachable")],
            ),
            display_name="Office PBX",
            extension_names={"120": "Support"},
            now=datetime(2026, 6, 26, 20, tzinfo=ZoneInfo("Europe/Athens")),
        )

        tips = [
            signal
            for signal in payload["signals"]
            if signal["kind"] == "missed_rate_pattern"
        ]
        self.assertEqual(tips[0]["title"], "Missed calls are higher than usual today.")
        self.assertEqual(tips[0]["technical"]["today_missed_calls"], "4")


if __name__ == "__main__":
    unittest.main()
