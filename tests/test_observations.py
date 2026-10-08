from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from pathlib import Path
import ast
import unittest
from typing import get_type_hints

from pbxsense_agent import observations, pulse
from pbxsense_agent.ami import AmiClient
from pbxsense_agent.connectors import MockConnector, PBXConnector
from pbxsense_agent.cucm import CucmClient
from pbxsense_agent.freeswitch import FreeSwitchClient
from pbxsense_agent.grandstream import GrandstreamUcmClient
from pbxsense_agent.mock import mock_snapshot
from pbxsense_agent.yeastar import YeastarClient


class ObservationTest(unittest.TestCase):
    def test_legacy_names_are_exact_aliases(self):
        for kind in ("Channel", "Endpoint", "Queue", "Snapshot"):
            with self.subTest(kind=kind):
                self.assertIs(getattr(pulse, "Ami" + kind), getattr(observations, "Pbx" + kind))

    def test_snapshot_field_contract_and_owned_defaults_are_preserved(self):
        expected = ["reachable", "agent_version", "channels", "endpoints", "queues",
                    "recent_calls", "voicemails", "security_events", "error"]
        self.assertEqual([f.name for f in fields(observations.PbxSnapshot)], expected)
        first = observations.PbxSnapshot(True, "test")
        second = observations.PbxSnapshot(False, "test", error="offline")
        for name in expected[2:-1]:
            self.assertEqual(getattr(first, name), [])
            self.assertIsNot(getattr(first, name), getattr(second, name))
        with self.assertRaises(FrozenInstanceError):
            first.reachable = False
        self.assertEqual(replace(second, reachable=True).error, "offline")

    def test_all_connector_interfaces_use_neutral_snapshot(self):
        for cls in (PBXConnector, MockConnector, AmiClient, GrandstreamUcmClient,
                    FreeSwitchClient, YeastarClient, CucmClient):
            with self.subTest(connector=cls.__name__):
                self.assertIs(get_type_hints(cls.snapshot)["return"], observations.PbxSnapshot)
        self.assertIsInstance(mock_snapshot(), observations.PbxSnapshot)

    def test_legacy_construction_preserves_public_payload(self):
        snapshot = mock_snapshot()
        legacy = pulse.AmiSnapshot(**{f.name: getattr(snapshot, f.name) for f in fields(snapshot)})
        now = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
        options = dict(display_name="Test PBX", extension_names={}, now=now,
                       timezone_name="UTC", pbx_type="mock", pbx_host="localhost", pbx_port=0)
        self.assertEqual(pulse.build_home_payload(snapshot, **options),
                         pulse.build_home_payload(legacy, **options))

    def test_observation_module_has_no_connector_or_payload_dependency(self):
        tree = ast.parse(Path(observations.__file__).read_text(encoding="utf-8"))
        dependencies = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertFalse(dependencies & {"pulse", "connectors", "main", "ami", "freeswitch", "cucm", "yeastar"})
