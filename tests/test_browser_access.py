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


def request(path="/", *, method="GET", host="127.0.0.1", scheme="http", headers=()):
    return Request({"type": "http", "method": method, "scheme": scheme, "path": path,
                    "query_string": b"", "headers": list(headers),
                    "client": (host, 1234), "server": ("agent.example", 8765)})


class BrowserAccessTest(unittest.TestCase):
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
