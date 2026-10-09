from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, patch

from pbxsense_agent.ami import AmiClient, AmiActionResponseError, AmiError
from pbxsense_agent.engine import build_engine_signals
from pbxsense_agent.freeswitch import FreeSwitchClient, FreeSwitchError, _pipe_rows, _queue_observation, _complete_rows, _read_json_cdr_calls
from pbxsense_agent.grandstream import GrandstreamUcmClient
from pbxsense_agent.history_collection import HistoryCollector
from pbxsense_agent.history import read_recent_cdr_calls, read_recent_cucm_calls, read_recent_voicemails
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

    def test_real_cdr_reader_failure_retains_cache_without_committing_fingerprint(self):
        clock = [0]
        collector = HistoryCollector(poll_interval=30, monotonic=lambda: clock[0])
        settings = replace(AgentSettings.from_env(), pbx_type="asterisk", cdr_csv_path="cdr", voicemail_path="", asterisk_security_log_path="")
        row = ['', '101', '102', '', '', '', '', '', '', '2026-10-09 12:00:00', '', '', '30', '', 'ANSWERED']
        with patch.object(collector, "_available", side_effect=lambda name, path: name == "cdr"), \
             patch("pbxsense_agent.history._is_file", return_value=True), \
             patch("pbxsense_agent.history._recent_cdr_rows", side_effect=[[row], PermissionError("denied"), []]) as reader, \
             patch("pbxsense_agent.history_collection.file_signature", return_value=("cdr", 1, 1)):
            first = collector.enrich(PbxSnapshot(True, "test"), settings)
            old_signature = collector._cdr_signature
            collector._cdr_signature = None
            clock[0] = 30
            failed = collector.enrich(PbxSnapshot(True, "test"), settings)
            self.assertIs(failed.recent_calls, first.recent_calls)
            self.assertIsNone(collector._cdr_signature)
            self.assertEqual(failed.sources['cdr']['state'], 'temporarily_unavailable')
            clock[0] = 60
            recovered = collector.enrich(PbxSnapshot(True, "test"), settings)
            self.assertEqual(recovered.recent_calls, [])
            self.assertEqual(recovered.sources['cdr']['state'], 'ready')
            self.assertEqual(collector._cdr_signature, old_signature)
            self.assertEqual(reader.call_count, 3)

    def test_legacy_reader_stays_best_effort_but_collector_reader_is_strict(self):
        with patch("pbxsense_agent.history._is_file", return_value=True), \
             patch("pbxsense_agent.history._recent_cdr_rows", side_effect=PermissionError("denied")):
            self.assertEqual(read_recent_cdr_calls("cdr"), [])
            with self.assertRaises(OSError):
                read_recent_cdr_calls("cdr", strict=True)

    def test_freeswitch_failed_disk_read_retains_last_records(self):
        client = self.fs()
        client._settings = replace(client._settings, freeswitch_cdr_json_path="cdr", freeswitch_voicemail_path="")
        records = [MagicMock()]
        client._cached_recent_calls = records
        with patch("pbxsense_agent.freeswitch._is_dir", return_value=True), \
             patch("pbxsense_agent.freeswitch.os.access", return_value=True), \
             patch("pbxsense_agent.freeswitch._read_json_cdr_calls", side_effect=PermissionError("denied")):
            self.assertEqual(client._history()[0], records)
            self.assertEqual(client._sources.export()['cdr']['state'], 'temporarily_unavailable')

    def test_yeastar_incomplete_queue_lists_and_statuses_do_not_clear_data(self):
        bad_lists = [{}, {'data':{}}, {'data':[None]}, {'data':[{'id':0}]}]
        bad_statuses = [{}, {'waiting_calls':None}, {'waiting_calls':-1}, {'waiting_list':{}}, {'waiting_list':[None]}]
        for response in bad_lists:
            client = YeastarClient(AgentSettings.from_env())
            client._cached_queues = [PbxQueue('support', 3)]
            client._api = MagicMock(return_value=response)
            self.assertEqual(client._queues(), [PbxQueue('support', 3)])
            self.assertEqual(client._sources.export()['queues']['state'], 'temporarily_unavailable')
        for response in bad_statuses:
            client._api = MagicMock(side_effect=[{'data':[{'id':1}]}, response])
            self.assertEqual(client._queues(), [PbxQueue('support', 3)])
        client._api = MagicMock(return_value={'data':[]})
        self.assertEqual(client._queues(), [])
        self.assertEqual(client._sources.export()['queues']['state'], 'ready')

    def test_home_labels_unknown_queue_and_live_sources(self):
        options = dict(display_name='PBX', extension_names={}, now=datetime(2026,10,9,12), timezone_name='UTC',
                       pbx_type='cucm', pbx_host='localhost', pbx_port=8443)
        snapshot = PbxSnapshot(True, 'test', queues=[PbxQueue('support', 0)], sources={
            'queues':{'state':'temporarily_unavailable'}, 'liveCalls':{'state':'not_configured'}})
        payload = build_home_payload(snapshot, **options)
        self.assertEqual(payload['queues'][0]['status'], 'unknown')
        self.assertNotIn('No callers', payload['queues'][0]['statusText'])
        self.assertEqual(payload['now']['title'], 'Live calls are not monitored.')
        payload = build_home_payload(replace(snapshot, queues=[PbxQueue('support', 2)],
                                  sources={'queueMembers':{'state':'unsupported'}}), **options)
        self.assertEqual(payload['queues'][0]['status'], 'waiting')
        self.assertFalse(payload['queues'][0]['membersKnown'])
        self.assertNotIn('No members', payload['queues'][0]['detail'])

    def test_strict_directory_scan_failures_are_not_empty_history(self):
        with patch('pbxsense_agent.history._is_dir', return_value=True), \
             patch('pbxsense_agent.history.os.scandir', side_effect=PermissionError('denied')):
            with self.assertRaises(OSError):
                read_recent_cucm_calls('cdr', '', strict=True)
            with self.assertRaises(OSError):
                read_recent_voicemails('voicemail', strict=True)
        with patch('pbxsense_agent.freeswitch._safe_is_dir', return_value=True), \
             patch('pbxsense_agent.freeswitch.os.scandir', side_effect=PermissionError('denied')):
            with self.assertRaises(OSError):
                _read_json_cdr_calls('cdr', strict=True)

