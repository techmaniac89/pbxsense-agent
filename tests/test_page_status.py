from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from starlette.requests import Request
from pbxsense_agent import main
from pbxsense_agent.page_status import capability_statuses, push_pairing_status, readable_timestamp, page_timezone
from pbxsense_agent.observations import PbxSnapshot, PbxEndpoint


class PageStatusTest(unittest.TestCase):
    def test_readable_dates_follow_configured_pbx_timezone_and_dst(self):
        summer = datetime(2026, 7, 23, 12, 42, tzinfo=timezone.utc).timestamp()
        winter = datetime(2026, 1, 23, 12, 42, tzinfo=timezone.utc).timestamp()
        self.assertEqual(readable_timestamp(summer, 'Europe/Athens'), '23 July 2026 at 15:42 · GMT+03:00')
        self.assertEqual(readable_timestamp(winter, 'Europe/Athens'), '23 January 2026 at 14:42 · GMT+02:00')
        self.assertIn('GMT+05:30', readable_timestamp(summer, 'Asia/Kolkata'))
        self.assertIn('GMT-04:00', readable_timestamp(summer, 'America/New_York'))
        self.assertIn('fallback', page_timezone('bad/timezone')[1])
        self.assertIn('not configured', page_timezone('')[1])
        self.assertEqual(readable_timestamp(0, 'Europe/Athens'), 'Not yet observed')
    def test_empty_successful_sources_are_available(self):
        snapshot = PbxSnapshot(reachable=True, agent_version='test', sources={
            key: {'state': 'ready'} for key in ('liveCalls', 'phones', 'trunks', 'queues', 'cdr')})
        self.assertTrue(all(text == 'Available' for _, text, _ in capability_statuses(snapshot)))
        self.assertTrue(all(text == 'Needs attention' for _, text, _ in capability_statuses(snapshot, stale=True)))

    def test_configured_failed_and_unsupported_sources_are_distinct(self):
        snapshot = PbxSnapshot(reachable=True, agent_version='test', sources={
            'cdr': {'state': 'not_configured'}, 'queues': {'state': 'unsupported'},
            'phones': {'state': 'permission_denied'}})
        labels = {label: text for label, text, _ in capability_statuses(snapshot)}
        self.assertEqual(labels['Call history'], 'Not configured')
        self.assertEqual(labels['Queues'], 'Not supported')
        self.assertEqual(labels['Phones'], 'Needs attention')
        self.assertEqual(labels['Live calls'], 'Not yet verified')

    def test_ami_ambiguous_trunk_inventory_is_not_available(self):
        snapshot = PbxSnapshot(reachable=True, agent_version='test', endpoints=[PbxEndpoint('peer', 'Reachable', role='unknown')],
            sources={'PJSIPShowEndpoints': {'state': 'ready'}})
        self.assertIn(('Trunks', 'Needs attention', 'attention'), capability_statuses(snapshot, pbx_type='asterisk'))

    def test_relay_enrollment_never_implies_notification_delivery_ready(self):
        self.assertEqual(push_pairing_status({})[0], 'Not configured')
        status = {'configured': True, 'enrolled': True}
        self.assertEqual(push_pairing_status(status)[0], 'Check app registration')
        self.assertEqual(push_pairing_status(status, qr_has_activation=True)[0], 'Available for pairing')
        self.assertEqual(push_pairing_status(status, qr_has_activation=False)[0], 'Not included in this QR')
        self.assertEqual(push_pairing_status({**status, 'lastOutboxError': 'failure'}, qr_has_activation=True)[0], 'Needs attention')

    def test_home_simplifies_diagnostics_and_conditionally_displays_roles(self):
        request = Request({'type': 'http', 'method': 'GET', 'path': '/', 'headers': [],
            'query_string': b'', 'scheme': 'http', 'server': ('localhost', 8765), 'client': ('127.0.0.1', 1)})
        snapshot = PbxSnapshot(reachable=True, agent_version='test')
        state = SimpleNamespace(snapshot=snapshot, observed_at=datetime.now(timezone.utc))
        with patch.object(main, '_require_token'), patch.object(main, '_agent_status', return_value={'ok': True}), \
             patch.object(main, '_refresh_home_state', return_value=state), patch.object(main.push_relay, 'status', return_value={}):
            page = main.index(request)
            self.assertIn('Last successful PBX update', page)
            self.assertIn('Agent running since', page)
            self.assertIn('PBX capabilities', page)
            self.assertNotIn('Connection check', page)
            self.assertIn('<div class="section-heading">Endpoint roles</div>', page)
            self.assertNotIn('Pairing and notifications', page)
            snapshot.endpoints.append(PbxEndpoint('peer', 'Unknown', role='unknown'))
            self.assertIn('1 endpoint needs classification', main.index(request))
