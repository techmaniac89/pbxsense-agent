from __future__ import annotations

import ast
import asyncio
import json
import time
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import HTTPException, Request, WebSocket
from starlette.responses import Response

from pbxsense_agent import main as agent_main
from pbxsense_agent.connectors import MockConnector
from pbxsense_agent.diagnostics import (
    ami_diagnostic_statuses,
    connector_diagnostic_statuses,
)


def _request(
    *,
    method: str = "GET",
    path: str = "/",
    query: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
    client: tuple[str, int] = ("127.0.0.1", 50000),
    scheme: str = "http",
) -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": scheme,
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": query,
        "headers": headers or [],
        "client": client,
        "server": ("agent.test", 8765),
    }
    return Request(scope)


def _websocket(
    *,
    query: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
    client: tuple[str, int] = ("127.0.0.1", 50000),
) -> WebSocket:
    async def receive() -> dict[str, object]:
        return {"type": "websocket.disconnect", "code": 1000}

    async def send(_: dict[str, object]) -> None:
        return None

    return WebSocket({
        "type": "websocket",
        "scheme": "ws",
        "path": "/live",
        "raw_path": b"/live",
        "query_string": query,
        "headers": headers or [],
        "client": client,
        "server": ("agent.test", 8765),
        "subprotocols": [],
    }, receive, send)


class MainRouteStructureTest(unittest.TestCase):
    def test_file_signature_changes_only_with_history_file_metadata(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "Master.csv"
            missing = agent_main._file_signature(str(path))
            path.write_text("first\n", encoding="utf-8")
            first = agent_main._file_signature(str(path))
            second = agent_main._file_signature(str(path))
            path.write_text("first\nsecond\n", encoding="utf-8")
            changed = agent_main._file_signature(str(path))

            self.assertEqual(missing, (str(path), 0, 0))
            self.assertEqual(first, second)
            self.assertNotEqual(first, changed)

    def test_voicemail_signature_changes_without_reading_message_contents(self) -> None:
        with TemporaryDirectory() as directory:
            inbox = Path(directory) / "default" / "100" / "INBOX"
            inbox.mkdir(parents=True)
            message = inbox / "msg0000.txt"
            message.write_text("callerid=Alice\n", encoding="utf-8")
            first = agent_main._voicemail_signature(directory)
            second = agent_main._voicemail_signature(directory)
            message.write_text("callerid=Bob\nlonger=yes\n", encoding="utf-8")
            changed = agent_main._voicemail_signature(directory)

            self.assertEqual(first, second)
            self.assertNotEqual(first, changed)

    def test_home_payload_is_cached_until_the_snapshot_refreshes(self) -> None:
        original_connector = agent_main.connector
        original_state = agent_main._cached_home_state
        original_payloads = dict(agent_main._cached_home_payloads)
        try:
            agent_main.connector = MockConnector()
            with agent_main._snapshot_lock:
                agent_main._cached_home_state = None
                agent_main._cached_home_payloads.clear()
            first = agent_main._home_payload()
            second = agent_main._home_payload()
            self.assertIs(first, second)

            agent_main._refresh_home_state()
            third = agent_main._home_payload()
            self.assertIsNot(first, third)
        finally:
            agent_main.connector = original_connector
            with agent_main._snapshot_lock:
                agent_main._cached_home_state = original_state
                agent_main._cached_home_payloads.clear()
                agent_main._cached_home_payloads.update(original_payloads)

    def test_refresh_home_state_returns_a_snapshot_tuple(self) -> None:
        # Regression: the snapshot loop reads state[0] to find the snapshot,
        # so _refresh_home_state must return the state tuple (it previously
        # dropped the return value, making every poll fail with
        # "TypeError: 'NoneType' object is not subscriptable").
        original_connector = agent_main.connector
        try:
            agent_main.connector = MockConnector()
            with agent_main._snapshot_lock:
                agent_main._cached_home_state = None
            state = agent_main._refresh_home_state()
            self.assertIsInstance(state, tuple)
            self.assertGreaterEqual(len(state), 10)
            self.assertTrue(state[0].reachable)
        finally:
            agent_main.connector = original_connector

    def test_liveness_and_readiness_are_separate(self) -> None:
        self.assertEqual(agent_main.health_live()["status"], "ok")
        with agent_main._runtime_lock:
            original = dict(agent_main._runtime_state)
            agent_main._runtime_state.clear()
        try:
            response = agent_main.health_ready()
            self.assertEqual(response.status_code, 503)
            self.assertEqual(json.loads(response.body)["status"], "not_ready")

            with agent_main._runtime_lock:
                agent_main._runtime_state["snapshot"] = {
                    "lastCompletedAt": time.time(),
                    "lastSuccessAt": time.time(),
                    "consecutiveFailures": 0,
                    "lastError": "",
                }
            response = agent_main.health_ready()
            self.assertEqual(response.status_code, 200)
            self.assertEqual(json.loads(response.body)["status"], "ready")
        finally:
            with agent_main._runtime_lock:
                agent_main._runtime_state.clear()
                agent_main._runtime_state.update(original)

    def test_runtime_failures_are_counted_and_success_clears_error(self) -> None:
        with agent_main._runtime_lock:
            original = dict(agent_main._runtime_state)
            agent_main._runtime_state.clear()
            agent_main._runtime_state["snapshot"] = {
                "lastLogAtMonotonic": time.monotonic(),
            }
        try:
            agent_main._record_runtime_result("snapshot", ok=False, error="parse failed")
            agent_main._record_runtime_result("snapshot", ok=False, error="parse failed")
            failed = agent_main._runtime_diagnostics()["snapshot"]
            self.assertEqual(failed["consecutiveFailures"], 2)
            self.assertEqual(failed["lastError"], "parse failed")

            agent_main._record_runtime_result("snapshot", ok=True)
            recovered = agent_main._runtime_diagnostics()["snapshot"]
            self.assertEqual(recovered["consecutiveFailures"], 0)
            self.assertEqual(recovered["lastError"], "")
        finally:
            with agent_main._runtime_lock:
                agent_main._runtime_state.clear()
                agent_main._runtime_state.update(original)

    def test_ami_diagnostics_progressively_describe_unattempted_checks(self) -> None:
        self.assertEqual(
            ami_diagnostic_statuses({
                "tcpConnected": False,
                "bannerReceived": False,
                "loginAccepted": False,
            }),
            (
                ("PBX port", "Unreachable"),
                ("AMI protocol", "Not attempted"),
                ("Authentication", "Not attempted"),
            ),
        )

    def test_ami_banner_is_optional_when_login_succeeds(self) -> None:
        self.assertEqual(
            ami_diagnostic_statuses({
                "tcpConnected": True,
                "bannerReceived": False,
                "loginAccepted": True,
            }),
            (
                ("PBX port", "Reachable"),
                ("AMI protocol", "Optional (login accepted)"),
                ("Authentication", "Accepted"),
            ),
        )

    def test_agent_page_hides_outbound_registration_evidence_field(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertNotIn('"Outbound registration evidence"', source)

    def test_freeswitch_diagnostics_use_esl_vocabulary(self) -> None:
        statuses = connector_diagnostic_statuses({
            "pbxType": "freeswitch",
            "tcpConnected": True,
            "loginAccepted": True,
            "commandAccepted": True,
        })

        self.assertEqual(
            statuses,
            (
                ("PBX port", "Reachable"),
                ("ESL authentication", "Accepted"),
                ("ESL command", "Accepted"),
            ),
        )
        self.assertNotIn("AMI", " ".join(label for label, _ in statuses))

    def test_grandstream_diagnostics_identify_ucm_ami(self) -> None:
        statuses = connector_diagnostic_statuses({
            "pbxType": "grandstream",
            "tcpConnected": True,
            "bannerReceived": True,
            "loginAccepted": True,
        })

        self.assertEqual(statuses[1], ("UCM AMI protocol", "Detected"))

    def test_api_and_cucm_diagnostics_do_not_get_ami_rows(self) -> None:
        self.assertEqual(
            connector_diagnostic_statuses({"pbxType": "yeastar", "apiReachable": True}),
            (),
        )
        self.assertEqual(
            connector_diagnostic_statuses({"pbxType": "cucm", "axlReachable": True}),
            (),
        )
    def test_pair_route_has_a_direct_html_return(self) -> None:
        """Keep later route declarations from accidentally splitting pair()."""
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        pair_function = next(
            node
            for node in module.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "pair"
        )

        direct_returns = [node for node in pair_function.body if isinstance(node, ast.Return)]

        self.assertTrue(direct_returns, "The /pair route must directly return its rendered page")

    def test_pair_page_keeps_copy_control_for_pairing_text(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertIn('id="copy-pairing-text"', source)
        self.assertIn('id="copy-feedback"', source)
        self.assertIn("navigator.clipboard.writeText", source)
        self.assertIn("copyFeedback.classList.add('visible')", source)

    def test_enrolled_pairing_falls_back_to_a_usable_local_qr(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertNotIn("activation_pending", source)
        self.assertNotIn("Preparing secure pairing", source)
        self.assertIn('<div class="qr">{qr_svg}</div>', source)
        self.assertIn("Local pairing ready", source)
        self.assertIn(
            "Push setup will continue through this Agent.",
            source,
        )

    def test_empty_paired_app_states_use_the_neutral_gold_card(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertGreaterEqual(source.count('class="status empty"'), 2)
        self.assertIn(".status.empty", source)

    def test_home_snapshot_exposes_relay_identity_for_live_recreation_detection(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertIn('payload["connection"]["pushRelayAgentId"]', source)

    def test_relay_supports_scoped_app_push_registration(self) -> None:
        source = Path("push_relay/app.py").read_text(encoding="utf-8")

        self.assertIn(
            '@app.post("/v1/agents/{agent_id}/devices/{device_id}/registration")',
            source,
        )
        self.assertIn("_authenticate_relay_device(agent_id, device_id, request)", source)
        self.assertIn('return {"delivered": True, "deviceId": device_id}', source)

    def test_push_relay_has_cost_and_enrollment_guardrails(self) -> None:
        source = Path("push_relay/app.py").read_text(encoding="utf-8")

        self.assertIn("PBXSENSE_RELAY_ENROLLMENT_MODE", source)
        self.assertIn('"/v1/internal/enrollment-tickets"', source)
        self.assertIn("MAX_DEVICES_PER_AGENT", source)
        self.assertIn("MAX_EVENTS_PER_AGENT_PER_HOUR", source)
        self.assertIn("MAX_AGENTS_PER_ACCOUNT", source)
        self.assertIn("def _consume_durable_event_quota", source)
        self.assertIn("@firestore.transactional\ndef _increment_durable_quota", source)
        self.assertIn('"PBXSENSE_RELAY_ENROLLMENT_MODE", "closed"', source)
        self.assertIn("MAX_SECURE_SNAPSHOT_BYTES", source)
        self.assertIn("Request rate limit exceeded", source)
        self.assertIn('"activation:"', source)
        self.assertIn("limit=12", source)
        self.assertIn("_verify_public_key_request(public_key, request)", source)
        self.assertIn('@app.get("/v1/internal/usage")', source)
        self.assertIn('@app.get("/admin/usage"', source)
        self.assertIn("def _usage_update", source)
        self.assertIn('db.collection("usageDaily")', source)
        self.assertIn("usageArchivedDate", source)
        self.assertIn("PBXSENSE_RELAY_REMOTE_APP_POLL_SECONDS", source)
        self.assertIn('"privacy": "Agent identifiers are one-way hashes;', source)

    def test_relay_operations_dashboard_exposes_actionable_safe_metrics(self) -> None:
        source = Path("push_relay/app.py").read_text(encoding="utf-8")

        self.assertIn("def _record_notification_usage", source)
        self.assertIn("notificationAccepted", source)
        self.assertIn("notificationFailed", source)
        self.assertIn("notificationLatencyMs", source)
        self.assertIn("remoteSnapshotUnavailable", source)
        self.assertIn('db.collection("relayOperations")', source)
        self.assertIn("lastHeartbeatSweepAt", source)
        self.assertIn("quotaWarningAgents", source)
        self.assertIn("appsExpiringSoon", source)
        self.assertIn("snapshotCapableApps", source)
        self.assertIn("Workload proxy", source)
        self.assertIn("before free tier, discounts, taxes", source)
        self.assertIn("Push acceptance is Firebase acceptance", source)

    def test_relay_mutations_are_atomic_replay_safe_and_secret_separated(self) -> None:
        source = Path("push_relay/app.py").read_text(encoding="utf-8")
        agent = Path("pbxsense_agent/relay.py").read_text(encoding="utf-8")

        self.assertIn("@firestore.transactional\ndef _claim_activation_transaction", source)
        self.assertIn("@firestore.transactional\ndef _register_agent_device_transaction", source)
        self.assertIn("_require_replay_protected_signature(agent_id, agent, request)", source)
        self.assertIn("Replayed secure Agent request", source)
        self.assertIn("PBXSENSE_RELAY_TICKET_SECRET must differ", source)
        self.assertIn("_admin_cookie_value()", source)
        self.assertIn("hops[-2]", source)
        self.assertIn("async for chunk in request.stream()", source)
        self.assertIn('"X-PBXSense-Nonce": nonce', agent)
        self.assertIn('"X-PBXSense-Signature-V2"', agent)

    def test_push_relay_deduplicates_tokens_and_tags_notification_episodes(self) -> None:
        source = Path("push_relay/app.py").read_text(encoding="utf-8")

        self.assertIn("def _unique_devices_by_token", source)
        self.assertGreaterEqual(source.count("_unique_devices_by_token(["), 2)
        self.assertIn('"notificationId": event_id', source)
        self.assertIn('_optional_identifier(event.get("notificationTag")) or event_id', source)
        self.assertIn("messaging.AndroidNotification(tag=notification_tag)", source)

    def test_live_websocket_sends_quiet_heartbeats(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertIn("LIVE_HEARTBEAT_INTERVAL_SECONDS = 10", source)
        self.assertIn('{"type": "heartbeat", "data": {}}', source)

    def test_paired_app_card_uses_customer_facing_device_details(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertIn('app_version.split("+", 1)[0]', source)
        self.assertIn('"Model": model or "Not reported"', source)
        self.assertNotIn("model.casefold() != name.strip().casefold()", source)
        self.assertNotIn("Push registration details for this Agent only.", source)

    def test_paired_apps_show_recent_secure_relay_presence(self) -> None:
        agent_source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")
        relay_source = Path("push_relay/app.py").read_text(encoding="utf-8")

        self.assertIn('"Connection": "Connected now"', agent_source)
        self.assertIn('"connectedNow": (', relay_source)
        self.assertIn('"lastConnectedAt": firestore.SERVER_TIMESTAMP', relay_source)

    def test_pair_page_detects_internet_only_registration(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertIn("const initialDeviceRevision", source)
        self.assertIn("status.deviceRevision !== initialDeviceRevision", source)
        self.assertIn('"deviceRevision": _registered_device_revision', source)

    def test_paired_apps_can_be_removed_individually(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertIn('@app.post("/apps/remove")', source)
        self.assertIn('device.get("revokeId")', source)
        self.assertIn('"csrf": _local_web_csrf_value()', source)
        self.assertIn("Remove this app?", source)
        self.assertIn("Remove app</button>", source)

    def test_cookie_authenticated_writes_require_same_origin(self) -> None:
        original = agent_main.settings
        agent_main.settings = replace(original, token="test-token", public_url="")
        try:
            cookie = agent_main._local_web_cookie_value()
            headers = [
                (b"cookie", f"{agent_main.LOCAL_WEB_COOKIE}={cookie}".encode()),
                (b"origin", b"http://attacker.test"),
            ]
            with self.assertRaises(HTTPException) as raised:
                agent_main._require_safe_cookie_mutation(
                    _request(method="POST", path="/apps/remove", headers=headers)
                )
            self.assertEqual(raised.exception.status_code, 403)

            same_origin = [
                (b"cookie", f"{agent_main.LOCAL_WEB_COOKIE}={cookie}".encode()),
                (b"origin", b"http://agent.test:8765"),
            ]
            agent_main._require_safe_cookie_mutation(
                _request(method="POST", path="/apps/remove", headers=same_origin)
            )

            csrf_headers = [
                (b"cookie", f"{agent_main.LOCAL_WEB_COOKIE}={cookie}".encode()),
            ]
            csrf = agent_main._local_web_csrf_value().encode("ascii")
            agent_main._require_safe_cookie_mutation(
                _request(
                    method="POST",
                    path="/apps/remove",
                    query=b"deviceId=device_1&csrf=" + csrf,
                    headers=csrf_headers,
                )
            )
        finally:
            agent_main.settings = original

    def test_browser_cookie_transport_is_scoped_to_its_security_boundary(self) -> None:
        original = agent_main.settings
        agent_main.settings = replace(original, token="test-token", public_url="")
        try:
            self.assertTrue(
                agent_main._browser_session_transport_allowed(_request())
            )
            self.assertFalse(agent_main._browser_session_transport_allowed(
                _request(client=("192.168.1.25", 50000), scheme="http")
            ))
            self.assertTrue(agent_main._browser_session_transport_allowed(
                _request(client=("192.168.1.25", 50000), scheme="https")
            ))

            cookie = agent_main._local_web_cookie_value()
            self.assertTrue(agent_main._websocket_authorized(_websocket(headers=[
                (b"cookie", f"{agent_main.LOCAL_WEB_COOKIE}={cookie}".encode())
            ])))
            self.assertFalse(agent_main._websocket_authorized(_websocket(
                query=b"token=test-token",
                client=("8.8.8.8", 50000),
            )))
        finally:
            agent_main.settings = original

    def test_admin_browser_session_is_long_lived_and_renews(self) -> None:
        original = agent_main.settings
        agent_main.settings = replace(original, token="test-token", public_url="")
        try:
            request = _request(headers=[
                (b"accept", b"text/html"),
                (b"cookie", (
                    f"{agent_main.LOCAL_WEB_COOKIE}="
                    f"{agent_main._local_web_cookie_value()}"
                ).encode())
            ])

            async def call_next(_: Request) -> Response:
                return Response("ok")

            response = asyncio.run(agent_main.protect_agent_responses(request, call_next))
            self.assertIn(agent_main.LOCAL_WEB_COOKIE, response.headers["set-cookie"])
            self.assertEqual(response.headers["cache-control"], "no-store, private")
            self.assertEqual(response.headers["referrer-policy"], "no-referrer")
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertEqual(response.headers["x-frame-options"], "DENY")
            self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        finally:
            agent_main.settings = original

    def test_query_tokens_are_rejected_but_bearer_tokens_are_accepted(self) -> None:
        original = agent_main.settings
        agent_main.settings = replace(original, token="test-token")
        try:
            with self.assertRaises(HTTPException) as raised:
                agent_main._require_token(_request(query=b"token=test-token"))
            self.assertEqual(raised.exception.status_code, 401)

            agent_main._require_token(_request(headers=[
                (b"authorization", b"Bearer test-token")
            ]))
            self.assertTrue(agent_main._websocket_authorized(_websocket(headers=[
                (b"authorization", b"Bearer test-token")
            ])))
        finally:
            agent_main.settings = original

    def test_browser_setup_credential_is_single_use(self) -> None:
        original = agent_main.settings
        with TemporaryDirectory() as directory:
            agent_main.settings = replace(
                original,
                token="test-token",
                browser_bootstrap_token="setup-token",
                browser_bootstrap_expires_at=int(agent_main.time.time()) + 60,
                browser_bootstrap_state_path=str(Path(directory) / "used"),
            )
            request = _request(
                method="POST",
                path="/session",
                headers=[(b"authorization", b"Bearer setup-token")],
            )
            try:
                response = asyncio.run(agent_main.authorize_browser_session(request))
                self.assertIn(agent_main.LOCAL_WEB_COOKIE, response.headers["set-cookie"])
                with self.assertRaises(HTTPException) as raised:
                    asyncio.run(agent_main.authorize_browser_session(request))
                self.assertEqual(raised.exception.status_code, 401)
            finally:
                agent_main.settings = original

    def test_agent_page_hides_relay_version_and_offers_discord(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertNotIn('("internetRelayProtocol", "Secure relay version", False)', source)
        self.assertNotIn('href="mailto:techmaniac89@gmail.com"', source)
        self.assertIn('href="https://discord.gg/5GgsSRasQB"', source)
        self.assertIn('aria-label="Join PBXSense on Discord"', source)
        self.assertIn('class="discord-badge"', source)
        self.assertIn('class="footer-meta"', source)

    def test_pair_and_diagnostics_reuse_home_navigation_and_footer(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertIn('current="pair"', source)
        self.assertIn('primary="apps"', source)
        self.assertIn('navigation_current="diagnostics"', source)
        self.assertIn(
            'excluded=("pair", "apps") if navigation_current == "diagnostics" else ()',
            source,
        )
        self.assertIn("include_agent_footer=True", source)
        self.assertIn(
            '("pushRelayActivationError", "Pairing relay error", False)',
            source,
        )
        self.assertGreaterEqual(source.count("{_agent_footer_html()}"), 3)
        self.assertIn(
            'label_overrides={"pair": "Add another app"}',
            source,
        )
        self.assertIn('excluded=("diagnostics",)', source)
        self.assertNotIn(
            '<div class="section-heading"><span>Paired apps</span>',
            source,
        )
        self.assertIn(
            ".device-list {{ display: grid; gap: 12px; margin-top: 24px; }}",
            source,
        )
        self.assertNotIn("<span>Please wait<small>", source)
        self.assertIn('navigation_current == "diagnostics"', source)


if __name__ == "__main__":
    unittest.main()
