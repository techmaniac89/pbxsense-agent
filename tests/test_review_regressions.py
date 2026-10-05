import asyncio
import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pbxsense_agent.history import read_recent_cdr_calls
from pbxsense_agent.presence_history import EndpointLastActiveTracker
from pbxsense_agent.internet_relay import SecureInternetRelay
from pbxsense_agent import main
from pbxsense_agent.relay import AgentRelay


class ReviewRegressionTest(unittest.TestCase):
    def test_heartbeat_and_outbox_report_network_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            relay = AgentRelay(url="https://relay.example", identity_path=str(Path(directory) / "id.json"),
                               display_name="PBX", storage_secret="test-key")
            relay._state["agent_id"] = "agent-one"
            relay._state["outbox"] = [{"kind": "events", "payload": {"id": "one"}}]
            with patch.object(relay, "_request", side_effect=OSError("offline")):
                self.assertFalse(relay.heartbeat())
                self.assertFalse(relay.observe([]))
            self.assertEqual(len(relay._state["outbox"]), 1)

    def test_bad_cdr_field_does_not_hide_other_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Master.csv"
            row = ["", "101", "102", "internal", "", "", "", "Dial", "",
                   "2026-10-05 10:00:00", "", "", "60", "60", "ANSWERED"]
            with path.open("w", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["X" * (csv.field_size_limit() + 1)])
                writer.writerow(row)
            calls = read_recent_cdr_calls(str(path))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0].source, "101")

    def test_presence_state_recovers_wrong_shapes_and_invalid_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "presence.json"
            for value in ([], None, 42, "invalid"):
                path.write_text(json.dumps(value))
                self.assertEqual(EndpointLastActiveTracker(str(path)).snapshot(), {})
            path.write_text(json.dumps({"101": "2026-10-05T10:00:00", "102": "invalid", "103": []}))
            self.assertEqual(set(EndpointLastActiveTracker(str(path)).snapshot()), {"101"})

    def test_failed_internet_exchange_returns_failure_then_recovers(self):
        relay = SecureInternetRelay(enabled=True, agent_version="test",
                                    exchange=lambda _: (_ for _ in ()).throw(OSError("offline")))
        self.assertFalse(relay.poll())
        self.assertFalse(relay.status()["connected"])
        relay._exchange = lambda _: {}
        self.assertTrue(relay.poll())
        self.assertTrue(relay.status()["connected"])

    def test_internet_loop_records_caught_failure(self):
        relay = SecureInternetRelay(enabled=True, agent_version="test",
                                    exchange=lambda _: (_ for _ in ()).throw(OSError("offline")))
        async def stop(_):
            raise asyncio.CancelledError
        with patch.object(main, "internet_relay", relay), patch.object(main, "_record_runtime_result") as record, patch.object(main.asyncio, "sleep", stop):
            with self.assertRaises(asyncio.CancelledError):
                asyncio.run(main._internet_relay_loop())
        self.assertFalse(record.call_args.kwargs["ok"])
