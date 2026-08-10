from __future__ import annotations

import ast
import unittest
from pathlib import Path

from pbxsense_agent.diagnostics import (
    ami_diagnostic_statuses,
    connector_diagnostic_statuses,
)


class MainRouteStructureTest(unittest.TestCase):
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
        self.assertIn("Remove this app?", source)
        self.assertIn("Remove app</button>", source)

    def test_cookie_authenticated_writes_require_same_origin(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertIn("def _require_safe_cookie_mutation", source)
        self.assertIn("Same-origin request required", source)

    def test_browser_cookie_transport_is_scoped_to_its_security_boundary(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertGreaterEqual(source.count("secure=_local_web_cookie_secure(request)"), 2)
        self.assertIn("def _local_web_cookie_secure", source)
        self.assertIn("urlparse(settings.public_url).scheme", source)
        websocket_auth = source[source.index("def _websocket_authorized") :]
        self.assertIn("is_private_or_loopback_host(client_host)", websocket_auth)
        self.assertGreaterEqual(source.count("_require_safe_cookie_mutation(request)"), 3)

    def test_admin_browser_session_is_long_lived_and_renews(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertIn("LOCAL_WEB_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365 * 10", source)
        self.assertIn("async def renew_local_admin_session", source)

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
