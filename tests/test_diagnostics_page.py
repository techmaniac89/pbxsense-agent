import unittest
from starlette.requests import Request
from pbxsense_agent.diagnostics_page import diagnostics_sections
from pbxsense_agent import main


class DiagnosticsPageTest(unittest.TestCase):
    def test_nested_sources_are_readable_and_safe(self):
        page = diagnostics_sections({'tcpConnected': True, 'timeoutSeconds': 3,
            'dataSources': {'cdr': {'state': 'permission_denied', 'lastSuccessAgeSeconds': 25}},
            'error': '<script>alert(1)</script>'}, 'Europe/Athens')
        for text in ('Server connection', '>Yes<', '3 seconds', 'Data availability', 'Call history', 'Permission required', '25 seconds ago'):
            self.assertIn(text, page)
        self.assertNotIn('<script>', page)
        self.assertNotIn('tcpConnected', page)
        self.assertNotIn('<pre>', page)
        self.assertIn('<details class="panel diagnostic-section"><summary>PBX connection</summary>', page)
        self.assertIn('<details class="panel diagnostic-section"><summary>Data availability</summary>', page)
        self.assertNotIn('<details class="panel diagnostic-section" open', page)
        self.assertIn('<section class="panel"><h2>Call history</h2>', page)

    def test_html_diagnostics_keep_raw_json_link_without_dump(self):
        request = Request({'type': 'http', 'method': 'GET', 'path': '/diagnostics',
            'headers': [], 'query_string': b'', 'scheme': 'http',
            'server': ('localhost', 8765), 'client': ('127.0.0.1', 1)})
        page = main._json_page(request, 'Diagnostics', {'loginAccepted': True}, navigation_current='diagnostics')
        self.assertIn('Credentials accepted', page)
        self.assertIn('<section class="hero-card">', page)
        self.assertNotIn('<section class="json-card">', page)
        self.assertIn('format=json', page)
        self.assertNotIn('<pre>', page)
