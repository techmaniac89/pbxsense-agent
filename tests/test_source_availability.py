from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, patch

from pbxsense_agent.ami import AmiClient, AmiActionResponseError, AmiError
from pbxsense_agent.engine import build_engine_signals
from pbxsense_agent.freeswitch import FreeSwitchClient, FreeSwitchError, _pipe_rows, _queue_observation, _complete_rows
from pbxsense_agent.grandstream import GrandstreamUcmClient
from pbxsense_agent.history_collection import HistoryCollector
from pbxsense_agent.observations import PbxQueue, PbxSnapshot
from pbxsense_agent.pulse import ActivityTracker, build_home_payload
from pbxsense_agent.settings import AgentSettings
from pbxsense_agent.source_status import SourceStatus
from pbxsense_agent.yeastar import YeastarClient, YeastarError


class SourceAvailabilityTest(unittest.TestCase):
    def fs(self):
        client = FreeSwitchClient(AgentSettings.from_env())
        client._connect = MagicMock()
        client._authenticate = MagicMock()
        return client

    def test_freeswitch_inventory_survives_absence_failure_and_recovery(self):
        client = self.fs()
        responses = ['{"row_count":1,"rows":[{"reg_user":"101","display_name":"Desk"}]}',
                     '{"row_count":0}', FreeSwitchError("lost"), '{}',
                     '{"row_count":1,"rows":[{"reg_user":"101"}]}']
        client._api = MagicMock(side_effect=responses)
        first, down, failed, malformed, recovered = [client._endpoints([]) for _ in responses]
        self.assertEqual(first[0].device_state, "Reachable")
        self.assertEqual(down[0].health_status, "down")
        self.assertEqual(down[0].label, "Desk")
        self.assertEqual(failed[0].health_status, "unknown")
        self.assertEqual(malformed[0].health_status, "unknown")
        self.assertEqual(recovered[0].device_state, "Reachable")
        self.assertEqual(client._sources.export()["phones"]["state"], "ready")

    def test_registration_partial_or_invalid_json_is_not_a_confirmed_empty_read(self):
        for response in ({"row_count": 2, "rows": [{}]}, {"rows": [None]}, {}):
            with self.subTest(response=response), self.assertRaises(FreeSwitchError):
                _complete_rows(response)
        self.assertEqual(_complete_rows({"row_count": 0}), [])

    def test_freeswitch_queue_members_wait_and_agent_states(self):
        members = _pipe_rows("state|joined_epoch\nWaiting|900\nTrying|950\nAnswered|800\nAbandoned|700\n+OK")
        agents = _pipe_rows("name|status|state|ready_time\na|Available|Waiting|0\nb|Available|In a queue call|0\nc|On Break|Waiting|0\nd|Logged Out|Waiting|0\ne|Available|Waiting|1100\na|Available|Waiting|0\n+OK")
        with patch("pbxsense_agent.freeswitch.time.time", return_value=1000):
            queue = _queue_observation("support", members, agents)
        self.assertEqual(queue, PbxQueue("support", 2, 100, 1, 1, 1, 5))
        with self.assertRaises(FreeSwitchError):
            _pipe_rows("state|name\nWaiting\n+OK")

    def test_freeswitch_queue_failure_keeps_prior_data_and_retries(self):
        client = self.fs()
        client._api = MagicMock(side_effect=["name|strategy\nsupport|longest-idle-agent\n+OK",
            "state|joined_epoch\nWaiting|900\n+OK", "name|status|state\na|Available|Waiting\n+OK",
            FreeSwitchError("invalid command"), "+OK"])
        with patch("pbxsense_agent.freeswitch.time.time", return_value=1000):
            first = client._queues()
        self.assertEqual(client._queues(), first)
        self.assertEqual(client._sources.export()["queues"]["state"], "unsupported")
        self.assertEqual(client._queues(), [])
        self.assertEqual(client._sources.export()["queues"]["state"], "ready")

    def test_unsafe_queue_name_is_never_sent_in_a_command(self):
        client = self.fs()
        client._api = MagicMock(return_value="name|strategy\nbad name|x\n+OK")
        self.assertEqual(client._queues(), [])
        self.assertEqual(client._api.call_count, 1)
        self.assertEqual(client._sources.export()["queues"]["state"], "temporarily_unavailable")

    def test_ami_and_grandstream_actions_distinguish_denial_unsupported_zero_and_transport(self):
        for cls in (AmiClient, GrandstreamUcmClient):
            client = cls(AgentSettings.from_env())
            client._collect_action_events = MagicMock(side_effect=[
                AmiActionResponseError("Permission denied SECRET"),
                AmiActionResponseError("Invalid/unknown command SECRET"), [], AmiError("network SECRET")])
            for expected in ("permission_denied", "unsupported", "ready"):
                self.assertEqual(client._collect_optional_action_events(MagicMock(), action="QueueStatus", complete_event="done"), [])
                self.assertEqual(client._sources.export()["QueueStatus"]["state"], expected)
            with self.assertRaises(AmiError):
                client._collect_optional_action_events(MagicMock(), action="QueueStatus", complete_event="done")
            self.assertNotIn("SECRET", str(client._sources.export()))

    def test_source_failure_preserves_last_success_age_without_refreshing_it(self):
        tracker = SourceStatus()
        with patch("pbxsense_agent.source_status.time.monotonic", return_value=10):
            tracker.record("cdr")
        with patch("pbxsense_agent.source_status.time.monotonic", return_value=35):
            tracker.record("cdr", "temporarily_unavailable")
            self.assertEqual(tracker.export()["cdr"], {"state":"temporarily_unavailable", "lastSuccessAgeSeconds":25})

    def test_missing_file_history_retains_records_and_recovers(self):
        with TemporaryDirectory() as directory:
            path = Path(directory, "cdr.csv")
            path.touch()
            settings = replace(AgentSettings.from_env(), pbx_type="asterisk", cdr_csv_path=str(path),
                               voicemail_path="", asterisk_security_log_path="")
            clock = [0]
            records = [MagicMock()]
            collector = HistoryCollector(poll_interval=30, monotonic=lambda: clock[0], read_calls=MagicMock(return_value=records))
            first = collector.enrich(PbxSnapshot(True, "test"), settings)
            self.assertEqual(first.sources["cdr"]["state"], "ready")
            self.assertEqual(first.sources["voicemail"]["state"], "not_configured")
            path.unlink()
            clock[0] = 30
            missing = collector.enrich(PbxSnapshot(True, "test"), settings)
            self.assertIs(missing.recent_calls, records)
            self.assertEqual(missing.sources["cdr"]["state"], "temporarily_unavailable")
            path.touch()
            clock[0] = 60
            self.assertEqual(collector.enrich(PbxSnapshot(True, "test"), settings).sources["cdr"]["state"], "ready")

    def test_queue_failure_is_not_a_queue_cleared_activity(self):
        now = datetime(2026, 10, 9, 12)
        tracker = ActivityTracker()
        tracker.observe(PbxSnapshot(True, "test", queues=[PbxQueue("support", 2)]), now)
        failed = PbxSnapshot(True, "test", sources={"queues":{"state":"temporarily_unavailable"}})
        self.assertFalse(any(e["kind"] == "pbx_queue_cleared_activity" for e in tracker.observe(failed, now + timedelta(seconds=2))))
        ready = PbxSnapshot(True, "test", queues=[PbxQueue("support", 0)], sources={"queues":{"state":"ready"}})
        self.assertTrue(any(e["kind"] == "pbx_queue_cleared_activity" for e in tracker.observe(ready, now + timedelta(seconds=3))))

    def test_unknown_queue_coverage_does_not_produce_zero_agent_insight_or_target_moment(self):
        options = dict(endpoints=[], queues=[PbxQueue("support", 2)], recent_calls=[], voicemails=[], security_events=[],
                       extension_names={}, now=datetime(2026,10,9,18))
        signals = build_engine_signals(**options, data_sources={"queueMembers":{"state":"unsupported"}})
        self.assertNotIn("queue_demand_vs_agents", {s["kind"] for s in signals})
        options["queues"] = [PbxQueue("support", 0)]
        signals = build_engine_signals(**options, data_sources={"queues":{"state":"temporarily_unavailable"}})
        self.assertNotIn("queues_finished_within_target", {s["kind"] for s in signals})

    def test_yeastar_failed_queue_detail_retains_complete_prior_generation(self):
        client = YeastarClient(AgentSettings.from_env())
        client._cached_queues = [PbxQueue("support", 3)]
        client._api = MagicMock(side_effect=[{"data":[{"id":1,"number":"support"}]}, YeastarError("denied")])
        self.assertEqual(client._queues(), [PbxQueue("support", 3)])
        self.assertEqual(client._sources.export()["queues"]["state"], "temporarily_unavailable")

    def test_home_additive_source_metadata_does_not_alias_snapshot(self):
        snapshot = PbxSnapshot(True, "test", sources={"queues":{"state":"unsupported", "lastSuccessAgeSeconds":None}})
        payload = build_home_payload(snapshot, display_name="PBX", extension_names={}, now=datetime(2026,10,9,12),
                                     timezone_name="UTC", pbx_type="cucm", pbx_host="localhost", pbx_port=8443)
        self.assertEqual(payload["dataSources"], snapshot.sources)
        payload["dataSources"]["queues"]["state"] = "ready"
        self.assertEqual(snapshot.sources["queues"]["state"], "unsupported")

    def test_queue_cleared_does_not_claim_no_abandonments_without_history(self):
        now = datetime(2026,10,9,12)
        tracker = ActivityTracker()
        tracker.observe(PbxSnapshot(True, "test", queues=[PbxQueue("support", 2)]), now)
        result = tracker.observe(PbxSnapshot(True, "test", queues=[PbxQueue("support", 0)],
                                 sources={"cdr":{"state":"not_configured"}}), now + timedelta(seconds=5))
        self.assertIn("pbx_queue_cleared_activity", {s["kind"] for s in result})
        self.assertNotIn("busy_period_completed_without_abandonment", {s["kind"] for s in result})

