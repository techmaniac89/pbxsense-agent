import unittest
from unittest.mock import Mock, patch

from pbxsense_agent.ami import AmiClient, AmiEvent, AmiActionResponseError, _endpoint_role, _endpoints_from_events
from pbxsense_agent.settings import AgentSettings
from pbxsense_agent.observations import PbxSnapshot
from pbxsense_agent.pulse import build_home_payload, _endpoint_unavailable


class EndpointRoleTest(unittest.TestCase):
    def test_names_and_descriptions_never_establish_a_role(self):
        for name in ('101', 'openai-live', 'fusionpbx', 'Cosmote', 'my-trunk'):
            self.assertEqual(_endpoint_role(name, {'Description': 'SIP trunk provider'}), 'unknown')
            self.assertEqual(_endpoint_role(name, {'MaxContacts': '1'}), 'extension')
            self.assertEqual(_endpoint_role(name, {'MaxContacts': '0', 'HasIdentify': 'yes'}), 'unknown')
            self.assertEqual(_endpoint_role(name, {'Context': 'from-trunk'}), 'trunk')
        self.assertEqual(_endpoint_role('static-phone', {'MaxContacts': '0'}), 'unknown')

    def test_unclassified_endpoints_are_not_phones_or_phone_alerts(self):
        endpoints = _endpoints_from_events([AmiEvent('EndpointList', {'ObjectName': 'anything', 'DeviceState': 'Unavailable'})])
        self.assertEqual(endpoints[0].role, 'unknown')
        self.assertFalse(_endpoint_unavailable(endpoints[0]))
        payload = build_home_payload(PbxSnapshot(reachable=True, agent_version='test', endpoints=endpoints), display_name='PBX', extension_names={})
        self.assertEqual(payload['people'], [])
        self.assertFalse(any(s.get('kind') == 'endpoint_unavailable' for s in payload['signals']))

    def test_config_collection_is_bounded_cached_and_redacted(self):
        client = AmiClient(AgentSettings.from_env())
        details = [AmiEvent('EndpointDetail', {'Context': 'from-trunk', 'Password': 'do-not-cache'}),
                   AmiEvent('AorDetail', {'MaxContacts': '0'}),
                   AmiEvent('IdentifyDetail', {'Match': '10.0.0.1'})]
        events = [AmiEvent('EndpointList', {'ObjectName': f'peer-{i}'}) for i in range(8)]
        with patch.object(client, '_collect_action_events', return_value=details) as query:
            client._enrich_endpoint_config(Mock(), events)
            self.assertEqual(query.call_count, 5)
            client._enrich_endpoint_config(Mock(), events)
            self.assertEqual(query.call_count, 8)
            client._enrich_endpoint_config(Mock(), events)
            self.assertEqual(query.call_count, 8)
        self.assertNotIn('do-not-cache', repr(client._role_config))
        self.assertTrue(all(_endpoint_role('', e.fields) == 'trunk' for e in events))

    def test_rejected_configuration_does_not_fall_back_to_names(self):
        client = AmiClient(AgentSettings.from_env())
        events = [AmiEvent('EndpointList', {'ObjectName': 'Cosmote'})]
        with patch.object(client, '_collect_action_events', side_effect=AmiActionResponseError('Permission denied')):
            client._enrich_endpoint_config(Mock(), events)
        self.assertEqual(_endpoints_from_events(events)[0].role, 'unknown')

    def test_legacy_sip_peer_uses_dynamic_and_context_configuration(self):
        client = AmiClient(AgentSettings.from_env())
        events = [AmiEvent('PeerEntry', {'ObjectName': 'named-anything'})]
        with patch.object(client, '_send_action'), patch.object(client, '_read_until_response', return_value={'Response': 'Success', 'Dynamic': 'Y', 'Secret': 'hidden'}):
            client._enrich_endpoint_config(Mock(), events)
        self.assertEqual(_endpoints_from_events(events)[0].role, 'extension')
        self.assertNotIn('hidden', repr(client._role_config))
