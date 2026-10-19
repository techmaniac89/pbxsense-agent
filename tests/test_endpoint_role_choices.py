from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest
from types import SimpleNamespace

from fastapi import HTTPException
from starlette.requests import Request
from pbxsense_agent.endpoint_roles import EndpointRoles
from pbxsense_agent.observations import PbxEndpoint, PbxSnapshot
from pbxsense_agent.pulse import build_home_payload, _endpoint_unavailable
from pbxsense_agent import main


class EndpointRoleChoicesTest(unittest.TestCase):
    def test_lan_role_forms_include_session_csrf_and_accept_null_origin(self):
        with TemporaryDirectory() as directory:
            store = EndpointRoles(Path(directory) / 'roles.json')
            snapshot = PbxSnapshot(reachable=True, agent_version='test', endpoints=[PbxEndpoint('peer', 'Reachable', role='unknown')])
            with patch.object(main, '_endpoint_role_store', return_value=store), \
                 patch.object(main, '_endpoint_role_scope', return_value='pbx'), \
                 patch.object(main, '_refresh_home_state', return_value=SimpleNamespace(snapshot=snapshot)), \
                 patch.object(main, '_has_valid_local_web_cookie', return_value=True), \
                 patch.object(main, '_local_web_csrf_value', return_value='session-proof'), \
                 patch.object(main, '_require_token'):
                def request(query=b'', method='POST'):
                    return Request({'type': 'http', 'method': method, 'path': '/endpoints/role',
                        'headers': [(b'host', b'192.168.0.254:8765'), (b'origin', b'null')],
                        'query_string': query, 'scheme': 'http',
                        'server': ('192.168.0.254', 8765), 'client': ('192.168.0.2', 1234)})
                page = main.endpoint_roles_page(request(method='GET'))
                self.assertEqual(page.count('csrf=session-proof'), 3)
                self.assertNotIn('>Ignore<', page)
                for role in ('extension', 'trunk', 'auto'):
                    result = main.set_endpoint_role(request(f'endpoint=peer&role={role}&csrf=session-proof'.encode()))
                    self.assertEqual(result.status_code, 303)
                for token in ('', '&csrf=incorrect'):
                    with self.assertRaises(HTTPException) as error:
                        main.set_endpoint_role(request(f'endpoint=peer&role=trunk{token}'.encode()))
                    self.assertEqual(error.exception.status_code, 403)

    def test_roles_survive_reload_and_are_pbx_scoped(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'roles.json'
            store = EndpointRoles(path)
            snapshot = PbxSnapshot(reachable=True, agent_version='test', endpoints=[PbxEndpoint('peer', 'Reachable', role='unknown')])
            for role in ('trunk', 'extension'):
                store.set('pbx-one', 'peer', role)
                store = EndpointRoles(path)
                updated = store.apply(snapshot, 'pbx-one')
                self.assertEqual(updated.endpoints[0].role, role)
                self.assertEqual(store.apply(snapshot, 'pbx-two').endpoints[0].role, 'unknown')
                payload = build_home_payload(updated, display_name='PBX', extension_names={})
                self.assertEqual(len(payload['people']), int(role == 'extension'))
            store.set('pbx-one', 'peer', 'auto')
            self.assertEqual(EndpointRoles(path).choices('pbx-one'), {})

    def test_invalid_roles_are_rejected_without_changing_saved_choices(self):
        with TemporaryDirectory() as directory:
            store = EndpointRoles(Path(directory) / 'roles.json')
            store.set('pbx', 'peer', 'trunk')
            for name, role in (('peer', 'bogus'), ('peer', 'ignore'), ('\npeer', 'extension'), ('', 'trunk')):
                with self.assertRaises(ValueError):
                    store.set('pbx', name, role)
            self.assertEqual(store.choices('pbx'), {'peer': 'trunk'})

    def test_legacy_ignore_reverts_to_automatic(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'roles.json'
            path.write_text('{"pbx":{"old-peer":"ignore","trunk":"trunk"}}')
            store = EndpointRoles(path)
            self.assertEqual(store.choices('pbx'), {'trunk': 'trunk'})

    def test_mutation_requires_administrator_not_app_access(self):
        request = Request({'type': 'http', 'method': 'POST', 'path': '/endpoints/role',
            'headers': [], 'query_string': b'endpoint=peer&role=trunk',
            'scheme': 'http', 'server': ('localhost', 8765), 'client': ('127.0.0.1', 1)})
        with patch.object(main, '_has_valid_local_web_cookie', return_value=False):
            with self.assertRaises(HTTPException) as error:
                main.set_endpoint_role(request)
        self.assertEqual(error.exception.status_code, 403)
