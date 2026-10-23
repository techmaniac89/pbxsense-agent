import asyncio
from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi import HTTPException, Request

from pbxsense_agent import main
from pbxsense_agent.browser_access import BrowserAccessGrants
from pbxsense_agent.credentials import AppCredentials
from pbxsense_agent.settings import AgentSettings


def request(path="/", *, method="GET", host="127.0.0.1", scheme="http", headers=()):
    return Request({"type": "http", "method": method, "scheme": scheme, "path": path,
                    "query_string": b"", "headers": list(headers),
                    "client": (host, 1234), "server": ("agent.example", 8765)})


class BrowserAccessTest(unittest.TestCase):
    def test_create_code_uses_primary_style_and_status_is_on_right(self):
        with patch.object(main, '_require_token'):
            page = main.browser_access(request()).body.decode()
        self.assertIn('class="actions"', page)
        self.assertNotIn('authorize-actions', page)
        self.assertNotIn('button.button {{ cursor: pointer; font: inherit; }}', Path(main.__file__).read_text())
        self.assertIn('id="create-code" class="button primary"', page)
        self.assertLess(page.index('id="create-code"'), page.index('href="/">Agent status'))

    def test_browser_icons_use_valid_svg_and_ico_formats(self):
        self.assertIn('xmlns="http://www.w3.org/2000/svg"', main.favicon().body.decode())
        icon = main.browser_favicon()
        self.assertEqual(icon.body[:6], b'\x00\x00\x01\x00\x01\x00')
        self.assertEqual(icon.body[22:30], b'\x89PNG\r\n\x1a\n')
        self.assertEqual(icon.media_type, 'image/x-icon')

    def test_authorization_navigation_and_shared_fixed_frame(self):
        source = Path(main.__file__).read_text(encoding='utf-8')
        self.assertIn('<a class="button" href="/">Agent status</a>', source)
        self.assertNotIn('Back to home</a>', source)
        self.assertIn('grid-template-columns: minmax(0, 1fr);', source)
        self.assertIn('.page-content {{ width: 100%; min-width: 0; }}', source)

    def test_trusted_lan_is_explicit_and_defaults_disabled(self):
        with patch.dict('os.environ', {}, clear=True):
            self.assertFalse(AgentSettings.from_env().trusted_lan_http)
        with patch.dict('os.environ', {'PBXSENSE_TRUSTED_LAN_HTTP':'true'}, clear=True):
            self.assertTrue(AgentSettings.from_env().trusted_lan_http)

    def test_warning_and_card_share_one_layout_item_with_small_gap(self):
        with patch.object(main, 'settings', replace(main.settings, trusted_lan_http=True)):
            page = main._page(title='test', body='<section class="hero-card">Card</section>')
            self.assertIn('<div class="page-content"><div class="status attention" role="note" style="margin:0 0 8px">', page)
            self.assertIn('publicly.</div><section class="hero-card">', page)
        source = Path(main.__file__).read_text(encoding='utf-8')
        self.assertIn('<a class="button" href="/browser-access">Authorize a browser</a>', source)

    def test_authorize_button_shares_home_navigation_row(self):
        navigation = main._agent_navigation_html(request(), current='home', primary='pair')
        self.assertEqual(navigation.count('<div class="actions">'), 1)
        self.assertIn('href="/browser-access">Authorize a browser</a>', navigation)
        self.assertIn('href="/pair"', navigation)
        self.assertIn('href="/diagnostics"', navigation)
        self.assertLess(navigation.index('href="/browser-access"'), navigation.index('href="/diagnostics"'))
        self.assertNotIn('/browser-access', main._agent_navigation_html(request(), current='apps', primary='pair'))

    def test_trusted_lan_allows_only_explicit_private_peer_ranges(self):
        with patch.object(main, 'settings', replace(main.settings, trusted_lan_http=True, public_url='')):
            for host in ('192.168.0.2', '10.1.2.3', '172.16.0.2', 'fd00::2', '::ffff:192.168.0.2'):
                self.assertTrue(main._browser_session_transport_allowed(request(host=host)), host)
            for host in ('8.8.8.8', '172.15.0.2', '192.0.2.1', '169.254.1.1', 'fe80::2', '2001:db8::1', 'bad-host'):
                self.assertFalse(main._browser_session_transport_allowed(request(host=host,
                    headers=[(b'x-forwarded-for', b'192.168.0.2')])), host)

    def test_trusted_lan_code_exchange_keeps_single_use_and_private_cookie(self):
        with TemporaryDirectory() as directory, \
                patch.object(main, 'settings', replace(main.settings, token='permanent-secret', trusted_lan_http=True, public_url='')), \
                patch.object(main, '_app_credentials', AppCredentials(Path(directory) / 'credentials', 'test')), \
                patch.object(main, '_browser_access_grants', BrowserAccessGrants()):
            page = main.browser_session(request('/session', host='192.168.0.2'))
            self.assertEqual(page.status_code, 200)
            self.assertIn(b'Trusted-LAN HTTP is enabled', page.body)
            self.assertNotIn(b'permanent-secret', page.body)
            code = main._browser_access_grants.issue()
            req = request('/session', host='192.168.0.2', method='POST',
                          headers=[(b'authorization', f'Bearer {code}'.encode())])
            result = asyncio.run(main.authorize_browser_session(req))
            cookie = result.headers['set-cookie'].lower()
            self.assertIn('httponly', cookie)
            self.assertIn('samesite=strict', cookie)
            self.assertNotIn('; secure', cookie)
            with self.assertRaises(HTTPException):
                asyncio.run(main.authorize_browser_session(req))
            with self.assertRaises(HTTPException):
                asyncio.run(main.authorize_browser_session(request('/session', host='192.168.0.2', method='POST',
                    headers=[(b'authorization', b'Bearer permanent-secret')])))

    def test_grants_are_single_use_expiring_bounded_and_hash_only(self):
        now = [0]
        grants = BrowserAccessGrants(clock=lambda: now[0], capacity=1)
        code = grants.issue()
        self.assertNotIn(code, grants._grants)
        with self.assertRaises(ValueError):
            grants.issue()
        self.assertFalse(grants.consume("wrong-code"))
        self.assertTrue(grants.consume(code))
        self.assertFalse(grants.consume(code))
        expired = grants.issue()
        now[0] = 900
        self.assertFalse(grants.consume(expired))
        self.assertFalse(BrowserAccessGrants().consume(grants.issue()))

    def test_html_authorization_error_is_guidance_but_api_remains_json(self):
        with patch.object(main, "settings", replace(main.settings, token="private-secret")):
            html = asyncio.run(main.browser_authorization_error(
                request(headers=[(b"accept", b"text/html")]), HTTPException(401, "token required")))
            self.assertEqual(html.status_code, 401)
            self.assertIn(b"Authorize this browser", html.body)
            self.assertNotIn(b"private-secret", html.body)
            api = asyncio.run(main.browser_authorization_error(request(), HTTPException(401, "token required")))
            self.assertEqual(json.loads(api.body), {"detail": "token required"})

    def test_lan_http_has_no_code_input_and_session_exchange_stays_blocked(self):
        with patch.object(main, "settings", replace(main.settings, token="private-secret", public_url="")):
            req = request("/session", host="192.168.0.2")
            page = main.browser_session(req)
            self.assertEqual(page.status_code, 403)
            self.assertIn(b"SSH tunnel", page.body)
            self.assertNotIn(b'type="password"', page.body)
            with self.assertRaises(HTTPException) as denied:
                asyncio.run(main.authorize_browser_session(req))
            self.assertEqual(denied.exception.status_code, 403)

    def test_anonymous_and_cross_origin_visitors_cannot_issue_codes(self):
        with patch.object(main, "settings", replace(main.settings, token="private-secret")), \
                patch.object(main, "_has_valid_local_web_cookie", return_value=False):
            with self.assertRaises(HTTPException) as denied:
                main.create_browser_access(request("/browser-access", method="POST"))
            self.assertEqual(denied.exception.status_code, 403)
        with patch.object(main, "settings", replace(main.settings, token="private-secret")), \
                patch.object(main, "_has_valid_local_web_cookie", return_value=True):
            with self.assertRaises(HTTPException):
                main.create_browser_access(request("/browser-access", method="POST",
                                                   headers=[(b"origin", b"https://other.example")]))

    def test_authorized_browser_code_exchanges_for_cookie_only_once(self):
        with TemporaryDirectory() as directory, \
                patch.object(main, "settings", replace(main.settings, token="private-secret", public_url="")), \
                patch.object(main, "_app_credentials", AppCredentials(Path(directory) / "credentials", "test")), \
                patch.object(main, "_browser_access_grants", BrowserAccessGrants()):
            cookie = main._local_web_cookie_value()
            issued = main.create_browser_access(request("/browser-access", method="POST", headers=[
                (b"cookie", f"{main.LOCAL_WEB_COOKIE}={cookie}".encode()),
                (b"origin", b"http://agent.example:8765"),
            ]))
            code = json.loads(issued.body)["code"]
            req = request("/session", method="POST", headers=[(b"authorization", f"Bearer {code}".encode())])
            response = asyncio.run(main.authorize_browser_session(req))
            self.assertIn("httponly", response.headers["set-cookie"].lower())
            with self.assertRaises(HTTPException):
                asyncio.run(main.authorize_browser_session(req))

    def test_secure_page_keeps_manual_entry_and_setup_fragment_exchange(self):
        with patch.object(main, "settings", replace(main.settings, token="private-secret", public_url="")):
            page = main.browser_session(request("/session"))
            self.assertIn(b'type="password"', page.body)
            self.assertIn(b"window.history.replaceState", page.body)
            self.assertNotIn(b"private-secret", page.body)
