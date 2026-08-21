from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from html import escape
from pathlib import Path
from urllib.parse import urlencode, urlparse

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from starlette.responses import StreamingResponse

from .connectors import connector_for_settings
from .cucm import enrich_cucm_trunks_with_history
from .diagnostics import connector_diagnostic_statuses
from .history import (
    cucm_history_diagnostics,
    history_diagnostics,
    read_recent_cdr_calls,
    read_recent_cucm_calls,
    read_recent_security_events,
    read_recent_voicemails,
    security_diagnostics,
)
from .internet_relay import SecureInternetRelay
from .live import home_live_events
from .mock import mock_snapshot
from .network import is_loopback_host, is_private_or_loopback_host
from .pulse import (
    ActivityTracker,
    EndpointAvailabilitySignalTracker,
    EndpointAggregateTipTracker,
    SignalNotificationEpisodeTracker,
    _now,
    build_home_payload,
)
from .presence_history import EndpointLastActiveTracker
from .recordings import find_recording
from .relay import AgentRelay
from .relay import PRESENCE_HEARTBEAT_INTERVAL_SECONDS
from .settings import AgentSettings
from .version import AGENT_RELEASE_CHANNEL, AGENT_VERSION

settings = AgentSettings.from_env()
logger = logging.getLogger("pbxsense_agent.runtime")
connector = connector_for_settings(settings)
activity_tracker = ActivityTracker(
    phone_outage_confirmation=timedelta(
        seconds=settings.endpoint_outage_confirmation_seconds
    ),
    phone_recovery_confirmation=timedelta(
        seconds=settings.endpoint_recovery_confirmation_seconds
    )
)
endpoint_availability_tracker = EndpointAvailabilitySignalTracker(
    outage_confirmation=timedelta(
        seconds=settings.endpoint_outage_confirmation_seconds
    ),
    recovery_confirmation=timedelta(
        seconds=settings.endpoint_recovery_confirmation_seconds
    ),
)
trunk_availability_tracker = EndpointAvailabilitySignalTracker(
    outage_confirmation=timedelta(
        seconds=settings.trunk_outage_confirmation_seconds
    ),
    recovery_confirmation=timedelta(0),
    role="trunk",
)
endpoint_aggregate_tip_tracker = EndpointAggregateTipTracker(
    timedelta(seconds=max(0, settings.quality_frequency_seconds))
)
endpoint_last_active_tracker = EndpointLastActiveTracker(settings.endpoint_activity_path)
signal_notification_episode_tracker = SignalNotificationEpisodeTracker()
push_relay = AgentRelay(
    url=settings.relay_url,
    identity_path=settings.relay_identity_path,
    display_name=settings.display_name,
    timeout_seconds=settings.relay_timeout_seconds,
    enrollment_ticket=settings.relay_enrollment_ticket,
    storage_secret=settings.relay_state_key or settings.token,
    legacy_storage_secrets=(settings.token,) if settings.relay_state_key else (),
)
internet_relay = SecureInternetRelay(
    enabled=settings.internet_relay_enabled,
    exchange=push_relay.secure_exchange,
    agent_version=AGENT_VERSION,
    snapshot_provider=lambda: _home_payload(),
    snapshot_publisher=push_relay.publish_secure_snapshot,
)
app = FastAPI(title="PBXSense Agent", version=AGENT_VERSION)
LOCAL_WEB_COOKIE = "pbxsense_agent_local_web"
# Browser authorization is effectively installation-lived and is renewed on
# every HTML visit. Token rotation or clearing browser site data revokes it.
LOCAL_WEB_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365 * 10
LIVE_INTERVAL_SECONDS = 1
LIVE_HEARTBEAT_INTERVAL_SECONDS = 10
SNAPSHOT_POLL_INTERVAL_SECONDS = settings.snapshot_poll_seconds
HISTORY_POLL_INTERVAL_SECONDS = settings.history_poll_seconds
RELAY_PUBLISH_INTERVAL_SECONDS = 5
_snapshot_task: asyncio.Task[None] | None = None
_relay_publish_task: asyncio.Task[None] | None = None
_relay_heartbeat_task: asyncio.Task[None] | None = None
_internet_relay_task: asyncio.Task[None] | None = None
_watchdog_task: asyncio.Task[None] | None = None
_snapshot_lock = threading.Lock()
_browser_bootstrap_lock = threading.Lock()
_cached_home_state: tuple | None = None
_cached_history: tuple[list, list, list] = ([], [], [])
_history_refreshed_at = 0.0
_cdr_history_signature: tuple[str, int, int] | None = None
_voicemail_history_signature: tuple[tuple[str, int, int], ...] | None = None
_security_history_signature: tuple[str, int, int] | None = None
_runtime_lock = threading.Lock()
_runtime_state: dict[str, dict[str, object]] = {}
_cached_home_payloads: dict[int, dict[str, object]] = {}
RUNTIME_ERROR_LOG_INTERVAL_SECONDS = 60
WATCHDOG_INTERVAL_SECONDS = 5


@app.middleware("http")
async def protect_agent_responses(request: Request, call_next):
    response = await call_next(request)
    if (
        request.method == "GET"
        and _wants_html(request)
        and _has_valid_local_web_cookie(request)
    ):
        response.set_cookie(
            LOCAL_WEB_COOKIE,
            _local_web_cookie_value(),
            max_age=LOCAL_WEB_COOKIE_MAX_AGE_SECONDS,
            httponly=True,
            secure=_local_web_cookie_secure(request),
            samesite="strict",
        )
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.on_event("startup")
async def start_relay_publisher() -> None:
    global _internet_relay_task, _relay_heartbeat_task, _relay_publish_task, _snapshot_task, _watchdog_task
    if settings.mode != "mock" and not settings.token:
        raise RuntimeError(
            "PBXSENSE_AGENT_TOKEN is required outside mock mode; run the installer "
            "or generate a token before starting the Agent"
        )
    _snapshot_task = asyncio.create_task(_snapshot_loop())
    if settings.relay_url:
        _relay_publish_task = asyncio.create_task(_relay_publish_loop())
        _relay_heartbeat_task = asyncio.create_task(_relay_heartbeat_loop())
        if settings.internet_relay_enabled:
            _internet_relay_task = asyncio.create_task(_internet_relay_loop())
    _watchdog_task = asyncio.create_task(_background_task_watchdog())


@app.on_event("shutdown")
async def stop_relay_publisher() -> None:
    tasks = [
        task
        for task in (
            _snapshot_task,
            _relay_publish_task,
            _relay_heartbeat_task,
            _internet_relay_task,
            _watchdog_task,
        )
        if task is not None
    ]
    for task in tasks:
        task.cancel()
    for task in tasks:
        try:
            await task
        except asyncio.CancelledError:
            pass


async def _snapshot_loop() -> None:
    while True:
        try:
            state = await asyncio.to_thread(_refresh_home_state)
            snapshot = state[0]
            _record_runtime_result(
                "snapshot",
                ok=bool(snapshot.reachable),
                error=str(snapshot.error or "") if not snapshot.reachable else "",
            )
        except Exception:
            # Connector failures normally produce an unreachable snapshot. An
            # unexpected parser/filesystem failure must not stop later polls.
            _record_runtime_result(
                "snapshot", ok=False,
                error="The snapshot loop failed unexpectedly.", log_exception=True,
            )
        await asyncio.sleep(SNAPSHOT_POLL_INTERVAL_SECONDS)


async def _relay_publish_loop() -> None:
    while True:
        try:
            payload = await asyncio.to_thread(_home_payload)
            people = payload.get("people", [])
            connection = payload.get("connection", {})
            await asyncio.to_thread(
                push_relay.observe,
                payload.get("signals", []),
                total_phones=len(people) if isinstance(people, list) else 0,
                connection_ok=(
                    isinstance(connection, dict)
                    and connection.get("kind") != "reconnecting"
                ),
            )
            _record_runtime_result("pushRelayPublisher", ok=True)
        except Exception:
            _record_runtime_result(
                "pushRelayPublisher", ok=False,
                error="The push relay publisher is temporarily unavailable.",
                log_exception=True,
            )
        await asyncio.sleep(RELAY_PUBLISH_INTERVAL_SECONDS)


async def _relay_heartbeat_loop() -> None:
    """Keep presence independent from PBX polling and signal generation."""
    while True:
        try:
            heartbeat_ok = await asyncio.to_thread(push_relay.heartbeat)
            _record_runtime_result(
                "pushRelayHeartbeat",
                ok=heartbeat_ok is not False,
                error="Relay heartbeat was not accepted." if heartbeat_ok is False else "",
            )
        except Exception:
            # Network and enrollment failures are retried on the next cadence.
            _record_runtime_result(
                "pushRelayHeartbeat", ok=False,
                error="The push relay heartbeat is temporarily unavailable.",
                log_exception=True,
            )
        await asyncio.sleep(PRESENCE_HEARTBEAT_INTERVAL_SECONDS)


async def _internet_relay_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(internet_relay.poll)
            _record_runtime_result("internetRelay", ok=True)
        except Exception:
            _record_runtime_result(
                "internetRelay", ok=False,
                error="The Internet Relay poll is temporarily unavailable.",
                log_exception=True,
            )
        await asyncio.sleep(settings.internet_relay_poll_seconds)


async def _background_task_watchdog() -> None:
    global _internet_relay_task, _relay_heartbeat_task, _relay_publish_task, _snapshot_task
    while True:
        await asyncio.sleep(WATCHDOG_INTERVAL_SECONDS)
        tasks: list[tuple[str, str, object]] = [
            ("snapshot", "_snapshot_task", _snapshot_loop),
        ]
        if settings.relay_url:
            tasks.extend([
                ("pushRelayPublisher", "_relay_publish_task", _relay_publish_loop),
                ("pushRelayHeartbeat", "_relay_heartbeat_task", _relay_heartbeat_loop),
            ])
            if settings.internet_relay_enabled:
                tasks.append(("internetRelay", "_internet_relay_task", _internet_relay_loop))
        for name, variable, factory in tasks:
            task = globals().get(variable)
            if isinstance(task, asyncio.Task) and not task.done():
                continue
            error = "Background task stopped unexpectedly and was restarted."
            if isinstance(task, asyncio.Task) and not task.cancelled():
                try:
                    task.exception()
                except (asyncio.CancelledError, asyncio.InvalidStateError):
                    pass
            _record_runtime_result(name, ok=False, error=error, log_exception=True)
            globals()[variable] = asyncio.create_task(factory())


def _record_runtime_result(
    name: str,
    *,
    ok: bool,
    error: str = "",
    log_exception: bool = False,
) -> None:
    now_wall = time.time()
    now_monotonic = time.monotonic()
    should_log = False
    with _runtime_lock:
        state = _runtime_state.setdefault(name, {})
        state["lastCompletedAt"] = now_wall
        if ok:
            state["lastSuccessAt"] = now_wall
            state["consecutiveFailures"] = 0
            state["lastError"] = ""
        else:
            state["lastFailureAt"] = now_wall
            state["consecutiveFailures"] = int(state.get("consecutiveFailures", 0)) + 1
            state["lastError"] = error[:500] or "Unknown background-task failure."
            last_log_at = float(state.get("lastLogAtMonotonic", 0.0))
            should_log = now_monotonic - last_log_at >= RUNTIME_ERROR_LOG_INTERVAL_SECONDS
            if should_log:
                state["lastLogAtMonotonic"] = now_monotonic
    if should_log:
        logger.error("%s loop failure: %s", name, error or "unknown error", exc_info=log_exception)


def _runtime_diagnostics() -> dict[str, object]:
    with _runtime_lock:
        return {name: dict(value) for name, value in _runtime_state.items()}


def _readiness() -> tuple[bool, str]:
    with _runtime_lock:
        snapshot = dict(_runtime_state.get("snapshot", {}))
    last_completed = float(snapshot.get("lastCompletedAt", 0.0))
    stale_after = max(
        10.0,
        settings.snapshot_poll_seconds * 3 + settings.timeout_seconds,
    )
    if last_completed <= 0:
        return False, "The first PBX snapshot has not completed."
    if time.time() - last_completed > stale_after:
        return False, "The PBX snapshot loop is stale."
    if int(snapshot.get("consecutiveFailures", 0)) > 0:
        return False, str(snapshot.get("lastError") or "The PBX connector is unavailable.")
    return True, "The Agent is polling the PBX normally."


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    _require_token(request)
    diagnostics = _agent_status()
    ok = diagnostics["ok"]
    status_text = "Connected" if ok else "Needs attention"
    status_detail = (
        f"The Agent can talk to {settings.display_name} and PBXSense can use live snapshots."
        if ok
        else f"The Agent is running, but {settings.display_name} still needs a little attention."
    )
    diagnostic_message = diagnostics.get(
        "message",
        diagnostics.get("error", "The latest check completed."),
    )
    diagnostic_html = f"""
        <section class="panel">
          <div class="section-heading">
            <span>Connection check</span>
            <small>{escape(connector.diagnostics_label)}</small>
          </div>
          <dl class="diagnostics">{_diagnostic_rows(diagnostics, diagnostic_message)}</dl>
        </section>
        """

    return _page(
        title="PBXSense Agent",
        body=f"""
          <section class="hero-card">
            {_brand_html()}
            <div class="status {'ok' if ok else 'attention'}">
              <span class="dot"></span>
              <span>{status_text}<small>{status_detail}</small></span>
            </div>
            {_agent_navigation_html(request, current="home", primary="pair")}
            {diagnostic_html}
            {_agent_footer_html()}
          </section>
        """,
    )


def _browser_session_page() -> str:
    return _page(
        title="Authorize PBXSense Agent",
        body="""
          <section class="hero-card">
            <div class="brand">
              <div>
                <h1>Authorize this browser</h1>
                <p class="subtitle" id="session-status">Checking the secure setup link...</p>
              </div>
            </div>
            <p>This page exchanges the setup link for a protected browser session. The short-lived setup credential is removed from browser history before it is sent.</p>
            <script>
              (() => {
                const status = document.getElementById("session-status");
                const fragment = new URLSearchParams(window.location.hash.slice(1));
                const token = fragment.get("token") || "";
                window.history.replaceState(null, "", window.location.pathname);
                if (!token) {
                  status.textContent = "This setup link is incomplete. Run the installer again to print a fresh link.";
                  return;
                }
                fetch("/session", {
                  method: "POST",
                  credentials: "same-origin",
                  headers: {Authorization: `Bearer ${token}`},
                }).then((response) => {
                  if (!response.ok) throw new Error("not authorized");
                  window.location.replace("/");
                }).catch(() => {
                  status.textContent = "The setup credential was not accepted. Run the installer again to print a fresh link.";
                });
              })();
            </script>
          </section>
        """,
    )


def _page(*, title: str, body: str) -> str:
    return f"""<!doctype html>
    <html lang="en">
      <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        <title>{escape(title)}</title>
        <style>
          :root {{
            color-scheme: dark;
            --bg: #151310;
            --panel: #211d18;
            --panel-soft: #2a241e;
            --ink: #f8efe0;
            --muted: #c1ad93;
            --line: #493c2f;
            --sage: #8eb486;
            --sage-dark: #263b2b;
            --coral: #f09a83;
            --gold: #d8ae62;
          }}
          * {{ box-sizing: border-box; }}
          body {{
            margin: 0;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background:
              radial-gradient(circle at top left, rgba(216, 174, 98, 0.16), transparent 30rem),
              radial-gradient(circle at bottom right, rgba(142, 180, 134, 0.12), transparent 34rem),
              linear-gradient(180deg, #18140f 0%, var(--bg) 100%);
            color: var(--ink);
          }}
          main {{
            min-height: 100vh;
            max-width: 920px;
            margin: 0 auto;
            padding: 42px 20px;
            display: grid;
            align-items: center;
          }}
          .hero-card, .json-card {{
            background: rgba(33, 29, 24, 0.94);
            border: 1px solid var(--line);
            border-radius: 26px;
            padding: 28px;
            box-shadow: 0 18px 46px rgba(0, 0, 0, 0.34);
          }}
          .brand {{
            display: flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 24px;
          }}
          .mark {{
            width: 52px;
            height: 52px;
            display: grid;
            place-items: center;
            border-radius: 18px;
            background: #152d26;
            color: #75d49b;
            box-shadow: inset 0 0 0 1px rgba(117, 212, 155, 0.24);
          }}
          .mark svg {{ width: 30px; height: 30px; }}
          h1 {{ margin: 0; font-size: clamp(30px, 6vw, 44px); letter-spacing: 0; }}
          .subtitle {{ margin: 4px 0 0; color: var(--muted); font-weight: 650; }}
          .status {{
            display: flex;
            align-items: center;
            gap: 14px;
            margin: 18px 0 22px;
            padding: 16px;
            border-radius: 20px;
            font-weight: 750;
          }}
          .status.ok {{ background: rgba(142, 180, 134, 0.17); color: #b7d6af; }}
          .status.empty {{ background: rgba(216, 174, 98, 0.17); color: #efd08d; }}
          .status.attention {{ background: rgba(240, 154, 131, 0.17); color: #ffb29f; }}
          .dot {{
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background: currentColor;
            box-shadow: 0 0 0 7px rgba(142, 180, 134, 0.14);
            flex: 0 0 auto;
          }}
          .status small {{
            display: block;
            margin-top: 2px;
            color: var(--muted);
            font-weight: 600;
          }}
          .actions {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 18px;
          }}
          .button {{
            display: inline-flex;
            align-items: center;
            min-height: 42px;
            padding: 0 16px;
            border-radius: 999px;
            background: #30281f;
            color: #d9c8ad;
            text-decoration: none;
            font-weight: 800;
            border: 1px solid var(--line);
          }}
          .button.primary {{
            background: var(--sage);
            color: #11170f;
            border-color: transparent;
          }}
          .panel {{
            margin-top: 24px;
            padding: 18px;
            border: 1px solid var(--line);
            border-radius: 20px;
            background: var(--panel-soft);
          }}
          .pairing-code {{
            padding: 14px;
            border-radius: 16px;
            background: #191612;
            border: 1px solid var(--line);
            color: var(--muted);
            overflow-wrap: anywhere;
            font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
            font-size: 12px;
          }}
          button.button {{ cursor: pointer; font: inherit; }}
          .button.danger {{
            background: rgba(240, 154, 131, 0.12);
            color: #ffb29f;
            border-color: rgba(240, 154, 131, 0.34);
          }}
          .pairing-text-row {{
            display: grid;
            grid-template-columns: minmax(0, 1fr) 44px;
            gap: 10px;
            align-items: stretch;
            margin-top: 18px;
          }}
          .copy-button {{
            position: relative;
            display: grid;
            place-items: center;
            padding: 0;
            border: 1px solid var(--line);
            border-radius: 16px;
            background: #30281f;
            color: var(--ink);
            cursor: pointer;
          }}
          .copy-button:hover {{ background: #3a3026; }}
          .copy-button svg {{ width: 19px; height: 19px; }}
          .copy-feedback {{
            position: absolute;
            right: -2px;
            bottom: calc(100% + 10px);
            padding: 7px 10px;
            border: 1px solid var(--line);
            border-radius: 10px;
            background: #30281f;
            color: var(--ink);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.28);
            font-size: 12px;
            font-weight: 750;
            line-height: 1;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transform: translateY(4px) scale(0.96);
            transition: opacity 150ms ease, transform 150ms ease;
          }}
          .copy-feedback::after {{
            content: "";
            position: absolute;
            top: 100%;
            right: 14px;
            border: 6px solid transparent;
            border-top-color: #30281f;
          }}
          .copy-feedback.visible {{
            opacity: 1;
            transform: translateY(0) scale(1);
          }}
          .qr {{
            width: min(280px, 100%);
            margin-top: 18px;
            padding: 12px;
            border-radius: 20px;
            background: #fffaf1;
            border: 1px solid #6a5742;
          }}
          .qr svg {{ width: 100%; height: auto; display: block; }}
          .section-heading {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 8px;
            font-weight: 850;
          }}
          .section-heading small {{
            color: var(--muted);
            font-weight: 750;
          }}
          .diagnostics {{ margin: 0; }}
          .diagnostics div {{
            display: grid;
            grid-template-columns: minmax(86px, 0.45fr) 1fr;
            gap: 16px;
            padding: 10px 0;
            border-bottom: 1px solid #3d3228;
          }}
          .diagnostics div:last-child {{ border-bottom: 0; }}
          .device-list {{ display: grid; gap: 12px; margin-top: 24px; }}
          .device-card {{
            padding: 16px;
            border: 1px solid var(--line);
            border-radius: 18px;
            background: #191612;
          }}
          .device-card-header {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 14px;
            margin-bottom: 12px;
          }}
          .device-card-title {{ min-width: 0; }}
          .device-card h2 {{ margin: 0 0 4px; font-size: 18px; }}
          .device-card p {{ margin: 0; color: var(--muted); }}
          .device-card .diagnostics div {{ grid-template-columns: minmax(100px, 0.4fr) 1fr; }}
          .device-actions {{ flex: 0 0 auto; margin: 0; }}
          .device-actions .button {{ min-height: 36px; padding: 0 13px; }}
          dt {{ color: var(--muted); }}
          dd {{ margin: 0; font-weight: 650; overflow-wrap: anywhere; }}
          .footer {{
            display: flex;
            align-items: end;
            justify-content: space-between;
            gap: 16px;
            margin-top: 18px;
            color: var(--muted);
            font-size: 13px;
          }}
          .footer-meta {{ display: grid; gap: 3px; }}
          .footer small {{ font-size: inherit; }}
          .footer-actions {{
            display: inline-flex;
            align-items: center;
            gap: 10px;
            flex: 0 0 auto;
          }}
          .discord-badge {{
            display: inline-flex;
            align-items: center;
            gap: 7px;
            min-height: 40px;
            padding: 0 14px;
            border: 1px solid rgba(255, 255, 255, 0.14);
            border-radius: 999px;
            background: #5865f2;
            color: #fff;
            text-decoration: none;
            font-size: 13px;
            font-weight: 800;
            box-shadow: 0 8px 22px rgba(88, 101, 242, 0.22);
            transition: background-color 180ms ease, border-color 180ms ease, transform 180ms ease;
          }}
          .discord-badge svg {{ width: 18px; height: 18px; fill: currentColor; }}
          .discord-badge:hover {{
            border-color: rgba(255, 255, 255, 0.28);
            background: #6875f5;
            color: #fff;
            transform: translateY(-1px);
          }}
          pre {{
            margin: 24px 0 0;
            padding: 18px;
            border-radius: 18px;
            background: #100d0a;
            color: #f8efe0;
            overflow: auto;
            line-height: 1.55;
            font-size: 13px;
          }}
          code {{ font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; }}
          @media (max-width: 520px) {{
            main {{ align-items: start; padding-top: 24px; }}
            .hero-card, .json-card {{ padding: 22px; border-radius: 22px; }}
            .footer {{ align-items: start; }}
            .footer-actions {{ flex-wrap: wrap; justify-content: end; }}
            .diagnostics div {{ grid-template-columns: 1fr; gap: 3px; }}
            .footer {{ align-items: center; }}
          }}
        </style>
      </head>
      <body>
        <main>
          {body}
        </main>
      </body>
    </html>"""


@app.get("/health")
def health() -> dict[str, str]:
    """Backward-compatible process liveness probe."""
    return {
        "status": "ok",
        "service": "pbxsense-agent",
    }


@app.get("/health/live")
def health_live() -> dict[str, str]:
    """Unauthenticated process liveness probe without operational details."""
    return {"status": "ok", "service": "pbxsense-agent"}


@app.get("/health/ready")
def health_ready() -> JSONResponse:
    """Report whether the PBX polling path is current and usable."""
    ready, detail = _readiness()
    return JSONResponse(
        {"status": "ready" if ready else "not_ready", "service": "pbxsense-agent", "detail": detail},
        status_code=200 if ready else 503,
    )


@app.get("/favicon.svg", include_in_schema=False)
def favicon() -> Response:
    return Response(_beacon_svg(), media_type="image/svg+xml")


@app.get("/session", response_class=HTMLResponse, include_in_schema=False)
def browser_session(request: Request):
    """Render a token-free browser bootstrap page on a protected transport."""
    if not settings.token:
        return RedirectResponse("/", status_code=303)
    if not _browser_session_transport_allowed(request):
        raise HTTPException(
            status_code=403,
            detail="Browser setup requires loopback HTTP or private HTTPS",
        )
    return HTMLResponse(_browser_session_page())


@app.post("/session", include_in_schema=False)
async def authorize_browser_session(request: Request) -> JSONResponse:
    """Exchange a fragment-supplied bearer token for the local admin cookie."""
    if not settings.token:
        return JSONResponse({"authorized": True})
    if not _browser_session_transport_allowed(request):
        raise HTTPException(
            status_code=403,
            detail="Browser setup requires loopback HTTP or private HTTPS",
        )
    authorization = request.headers.get("authorization", "")
    bootstrap_token = (
        authorization[7:].strip()
        if authorization.lower().startswith("bearer ")
        else ""
    )
    try:
        authorized = _consume_browser_bootstrap(bootstrap_token)
    except OSError as exc:
        raise HTTPException(
            status_code=503, detail="Browser setup state could not be saved"
        ) from exc
    if not authorized:
        raise HTTPException(
            status_code=401, detail="Browser setup credential is invalid or expired"
        )
    response = JSONResponse({"authorized": True})
    response.set_cookie(
        LOCAL_WEB_COOKIE,
        _local_web_cookie_value(),
        max_age=LOCAL_WEB_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        secure=_local_web_cookie_secure(request),
        samesite="strict",
    )
    return response


@app.get("/home")
def home(request: Request):
    _require_token(request)
    payload = _home_payload(moment_hours=_moment_hours(request))
    if _wants_html(request):
        return HTMLResponse(_json_page(request, "PBXSense home snapshot", payload))
    return JSONResponse(payload)


@app.get("/pair", response_class=HTMLResponse)
def pair(request: Request):
    _require_token(request)
    payload = _pairing_payload(request)
    qr_svg = _qr_svg(payload)
    relay_status = push_relay.status()
    registration_attempt_revision = int(
        relay_status.get("deviceRegistrationAttemptRevision", 0)
    )
    registration_revision = int(relay_status.get("deviceRegistrationRevision", 0))
    initial_device_revision = _registered_device_revision(push_relay.devices())
    apps_query = {"waitForDevice": "1"}
    paired_apps_url = "/apps?" + urlencode(apps_query)
    relay_degraded = (
        relay_status.get("configured") is True
        and "activation=" not in payload
    )
    pairing_attention = relay_degraded and relay_status.get("enrolled") is not True
    if relay_status.get("enrolled") is True:
        pairing_status = "Add another app"
        pairing_detail = (
            "Scan this QR on the additional phone. It will register its own push-notification device with this Agent."
            if not relay_degraded
            else "Scan this QR while the additional phone is on the Agent's network. Push setup will continue through this Agent."
        )
    elif relay_degraded:
        pairing_status = "Local pairing ready"
        pairing_detail = (
            "The push relay is temporarily unavailable. Local pairing still works; refresh before pairing to include closed-app push."
        )
    else:
        pairing_status = "Pairing ready"
        pairing_detail = "Scan this QR with PBXSense setup, or paste the pairing text."
    return _page(
        title="Pair PBXSense",
        body=f"""
          <section class="hero-card">
            {_brand_html()}
            <div id="pairing-status" class="status {'attention' if pairing_attention else 'ok'}">
              <span class="dot"></span>
              <span>{pairing_status}<small>{pairing_detail}</small></span>
            </div>
            {_agent_navigation_html(
                request,
                current="pair",
                primary="apps",
                excluded=("diagnostics",),
            )}
            <div class="qr">{qr_svg}</div>
            <div class="pairing-text-row">
              <div id="pairing-text" class="pairing-code">{escape(payload)}</div>
              <button id="copy-pairing-text" class="copy-button" type="button" title="Copy pairing text" aria-label="Copy pairing text">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <rect x="8" y="8" width="11" height="11" rx="2" fill="none" stroke="currentColor" stroke-width="2"/>
                  <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                </svg>
                <span id="copy-feedback" class="copy-feedback" role="status" aria-live="polite">Copied</span>
              </button>
            </div>
            <script>
              (() => {{
                const copyButton = document.getElementById('copy-pairing-text');
                const copyFeedback = document.getElementById('copy-feedback');
                let feedbackTimer;
                copyButton.addEventListener('click', async () => {{
                  const value = document.getElementById('pairing-text').textContent;
                  try {{
                    await navigator.clipboard.writeText(value);
                  }} catch (_) {{
                    const field = document.createElement('textarea');
                    field.value = value;
                    field.style.position = 'fixed';
                    field.style.opacity = '0';
                    document.body.appendChild(field);
                    field.select();
                    document.execCommand('copy');
                    field.remove();
                  }}
                  copyButton.title = 'Copied';
                  copyButton.setAttribute('aria-label', 'Pairing text copied');
                  copyFeedback.classList.add('visible');
                  window.clearTimeout(feedbackTimer);
                  feedbackTimer = window.setTimeout(() => {{
                    copyFeedback.classList.remove('visible');
                    copyButton.title = 'Copy pairing text';
                    copyButton.setAttribute('aria-label', 'Copy pairing text');
                  }}, 1600);
                }});
                const initialRevision = {registration_revision};
                const initialAttemptRevision = {registration_attempt_revision};
                const initialDeviceRevision = {json.dumps(initial_device_revision)};
                const statusUrl = "/push/devices/status";
                const appsUrl = {json.dumps(paired_apps_url)};
                const poll = async () => {{
                  try {{
                    const response = await fetch(statusUrl, {{ cache: 'no-store' }});
                    if (response.ok) {{
                      const status = await response.json();
                      if (Number(status.attemptRevision) > initialAttemptRevision) {{
                        const card = document.getElementById('pairing-status');
                        card.className = 'status ok';
                        card.innerHTML = '<span class="dot"></span><span>Finishing pairing...<small>Waiting for the registered app details.</small></span>';
                      }}
                      if (Number(status.registrationRevision) > initialRevision) {{
                        window.location.replace(appsUrl);
                        return;
                      }}
                      if (status.deviceRevision && status.deviceRevision !== initialDeviceRevision) {{
                        window.location.replace(appsUrl);
                        return;
                      }}
                    }}
                  }} catch (_) {{
                    // Pairing remains usable while the browser or Agent reconnects.
                  }}
                  window.setTimeout(poll, 1500);
                }};
                window.setTimeout(poll, 1500);
              }})();
            </script>
            {_agent_footer_html()}
          </section>
        """,
    )


@app.get("/apps", response_class=HTMLResponse)
def paired_apps(request: Request):
    _require_token(request)
    result = push_relay.devices()
    devices = result.get("devices", [])
    wait_for_device = request.query_params.get("waitForDevice") == "1"
    details = ""
    if result.get("state") == "notEnrolled" and wait_for_device:
        summary = _waiting_for_registered_app()
    elif result.get("state") == "notEnrolled":
        summary = """
          <div class="status empty">
            <span class="dot"></span>
            <span>No registered apps<small>Pair your first app. If this Agent was rebuilt and apps are missing, restore its previous relay identity or pair them again.</small></span>
          </div>
        """
    elif result.get("available") is not True:
        summary = f"""
          <div class="status attention">
            <span class="dot"></span>
            <span>Apps unavailable<small>{escape(str(result.get('error', 'The push relay is unavailable.')))}</small></span>
          </div>
        """
    elif (not isinstance(devices, list) or not devices) and wait_for_device:
        summary = _waiting_for_registered_app()
    elif not isinstance(devices, list) or not devices:
        summary = """
          <div class="status empty">
            <span class="dot"></span>
            <span>No registered apps<small>Pair an app to register it for push notifications.</small></span>
          </div>
        """
    else:
        summary = f"""
          <div class="status ok">
            <span class="dot"></span>
            <span>{len(devices)} registered {'app' if len(devices) == 1 else 'apps'}<small>Push registration details.</small></span>
          </div>
        """
        details = f"""
          <div class="device-list">{''.join(_device_card(device, request) for device in devices if isinstance(device, dict))}</div>
        """
    removal = request.query_params.get("removal", "")
    removal_notice = (
        '<div class="status ok"><span class="dot"></span><span>App removed'
        '<small>This app will no longer receive notifications from this Agent.</small></span></div>'
        if removal == "removed"
        else '<div class="status attention"><span class="dot"></span><span>App was not removed'
        '<small>The relay could not complete the request. Try again.</small></span></div>'
        if removal == "failed"
        else ""
    )
    return _page(
        title="Paired PBXSense apps",
        body=f"""
          <section class="hero-card">
            {_brand_html()}
            {removal_notice}
            {summary}
            {_agent_navigation_html(
                request,
                current="apps",
                primary="pair",
                excluded=("diagnostics",),
                label_overrides={"pair": "Add another app"},
            )}
            {details}
            {_agent_footer_html()}
          </section>
        """,
    )


@app.post("/apps/remove")
def remove_paired_app(request: Request):
    _require_token(request)
    _require_safe_cookie_mutation(request)
    device_id = request.query_params.get("deviceId", "").strip()
    removed = bool(device_id) and push_relay.remove_device(
        fcm_token="", relay_device_id=device_id
    )
    query = {"removal": "removed" if removed else "failed"}
    return RedirectResponse("/apps?" + urlencode(query), status_code=303)


def _waiting_for_registered_app() -> str:
    return """
      <div class="status ok">
        <span class="dot"></span>
        <span>Finishing pairing...<small>Waiting for the registered app details.</small></span>
      </div>
      <script>window.setTimeout(() => window.location.reload(), 1500);</script>
    """


def _device_card(device: dict[str, object], request: Request) -> str:
    name = str(device.get("deviceName") or device.get("deviceModel") or "PBXSense app")
    model = str(device.get("deviceModel") or "").strip()
    app_version = str(device.get("appVersion") or "").strip()
    if app_version:
        app_version = app_version.split("+", 1)[0]
    platform = str(device.get("platform") or "Unknown platform")
    os_version = str(device.get("osVersion") or "")
    subtitle = f"{platform.title()}{f' {os_version}' if os_version else ''}"
    notifications = []
    if device.get("meaningfulEnabled", True):
        notifications.append("Meaningful signals")
    if device.get("activityEnabled", True):
        notifications.append("PBX activity")
    rows = {
        "Connection": "Connected now" if device.get("connectedNow") is True else "Not connected recently",
        "Model": model or "Not reported",
        "App version": app_version or "Not reported",
        "Notifications": ", ".join(notifications) if notifications else "Disabled",
        "Last registered": str(device.get("updatedAt") or "Not reported"),
        "Registration ID": str(device.get("id") or "Unknown"),
    }
    revoke_id = str(device.get("revokeId") or "").strip()
    remove_query = {
        "deviceId": revoke_id,
        "csrf": _local_web_csrf_value(),
    }
    remove_action = (
        f'<form class="device-actions" method="post" action="/apps/remove?{urlencode(remove_query)}" '
        'onsubmit="return confirm(\'Remove this app? It will stop receiving notifications from this Agent.\')">'
        '<button class="button danger" type="submit">Remove app</button></form>'
        if revoke_id else ""
    )
    return f"""
      <article class="device-card">
        <div class="device-card-header">
          <div class="device-card-title">
            <h2>{escape(name)}</h2>
            <p>{escape(subtitle)}</p>
          </div>
          {remove_action}
        </div>
        <dl class="diagnostics">{''.join(f'<div><dt>{escape(label)}</dt><dd>{escape(value)}</dd></div>' for label, value in rows.items())}</dl>
      </article>
    """


@app.get("/diagnostics/ami")
def ami_diagnostics(request: Request):
    _require_token(request)
    return _diagnostics_response(request)


@app.get("/diagnostics")
def diagnostics(request: Request):
    _require_token(request)
    return _diagnostics_response(request)


@app.get("/recordings/{recording_id}")
def recording(recording_id: str, request: Request):
    _require_token(request)
    if settings.pbx_type == "yeastar":
        try:
            content, filename, media_type = connector.download_recording(recording_id)
        except OSError as exc:
            raise HTTPException(
                status_code=404,
                detail="The requested recording is unavailable.",
            ) from exc
        safe_filename = filename.replace('"', "'").replace("\r", "").replace("\n", "")
        return StreamingResponse(
            content=content,
            media_type=media_type if media_type != "application/octet-stream" else "audio/wav",
            headers={"Content-Disposition": f'inline; filename="{safe_filename}"'},
        )

    root = _recordings_path()
    path = find_recording(root, recording_id)
    if path is None:
        raise HTTPException(status_code=404, detail="Recording was not found in the configured root")
    return FileResponse(path, filename=path.name)


def _public_diagnostics(value: object, *, field: str = "") -> object:
    """Remove exception details before diagnostics cross the HTTP boundary."""
    sensitive_fields = {"error", "exception", "traceback", "lastError"}
    if isinstance(value, dict):
        cleaned: dict[str, object] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text in sensitive_fields:
                cleaned[key_text] = (
                    "The check failed. Review the Agent service logs for details."
                    if item
                    else ""
                )
            else:
                cleaned[key_text] = _public_diagnostics(item, field=key_text)
        return cleaned
    if isinstance(value, list):
        return [_public_diagnostics(item, field=field) for item in value]
    if isinstance(value, tuple):
        return [_public_diagnostics(item, field=field) for item in value]
    return value


def _diagnostics_response(request: Request):
    payload = connector.diagnostics()
    payload["internetRelay"] = internet_relay.status()
    ready, readiness_detail = _readiness()
    payload["runtime"] = {
        "ready": ready,
        "detail": readiness_detail,
        "loops": _runtime_diagnostics(),
    }
    if settings.pbx_type in {"asterisk", "grandstream"}:
        cdr_path, voicemail_path = _history_paths()
        payload["history"] = history_diagnostics(
            cdr_path,
            voicemail_path,
        )
        payload["security"] = security_diagnostics(_security_log_path())
    elif settings.pbx_type == "cucm":
        payload["history"] = cucm_history_diagnostics(
            settings.cucm_cdr_path, settings.cucm_cmr_path
        )
    payload = _public_diagnostics(payload)
    if _wants_html(request):
        return HTMLResponse(
            _json_page(
                request,
                "PBXSense diagnostics",
                payload,
                navigation_current="diagnostics",
                include_agent_footer=True,
            )
        )
    return JSONResponse(payload)


@app.websocket("/live")
async def live(websocket: WebSocket) -> None:
    if not _websocket_authorized(websocket):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    moment_hours = _websocket_moment_hours(websocket)
    try:
        previous_payload = await asyncio.to_thread(
            _home_payload,
            moment_hours=moment_hours,
        )
        await websocket.send_json({"type": "home_snapshot", "data": previous_payload})
        last_message_at = time.monotonic()
        while True:
            await asyncio.sleep(LIVE_INTERVAL_SECONDS)
            current_payload = await asyncio.to_thread(
                _home_payload,
                moment_hours=moment_hours,
            )
            if current_payload != previous_payload:
                events = home_live_events(previous_payload, current_payload)
                if events:
                    for event in events:
                        await websocket.send_json(event)
                    last_message_at = time.monotonic()
                else:
                    await websocket.send_json({"type": "home_snapshot", "data": current_payload})
                    last_message_at = time.monotonic()
                previous_payload = current_payload
                continue
            for event in home_live_events(previous_payload, current_payload):
                await websocket.send_json(event)
                last_message_at = time.monotonic()
            if time.monotonic() - last_message_at >= LIVE_HEARTBEAT_INTERVAL_SECONDS:
                await websocket.send_json({"type": "heartbeat", "data": {}})
                last_message_at = time.monotonic()
            previous_payload = current_payload
    except WebSocketDisconnect:
        return


def _home_payload(*, moment_hours: int = 24) -> dict:
    global _cached_home_state
    with _snapshot_lock:
        if _cached_home_state is None:
            _refresh_home_state_locked()
        state = _cached_home_state
        cached = _cached_home_payloads.get(moment_hours)
        if cached is None:
            cached = _home_payload_from_state(state, moment_hours=moment_hours)
            _cached_home_payloads[moment_hours] = cached
        return cached


def _refresh_home_state() -> tuple:
    with _snapshot_lock:
        return _refresh_home_state_locked()


def _refresh_home_state_locked() -> tuple:
    global _cached_home_state, _cached_history, _history_refreshed_at
    global _cdr_history_signature, _security_history_signature
    global _voicemail_history_signature
    snapshot = connector.snapshot()
    if settings.pbx_type in {"asterisk", "grandstream", "cucm"}:
        now_monotonic = time.monotonic()
        if (
            _history_refreshed_at == 0
            or now_monotonic - _history_refreshed_at >= HISTORY_POLL_INTERVAL_SECONDS
        ):
            if settings.pbx_type == "cucm":
                _cached_history = (
                    read_recent_cucm_calls(
                        settings.cucm_cdr_path,
                        settings.cucm_cmr_path,
                        limit=1000,
                    ),
                    [],
                    [],
                )
            else:
                cdr_path, voicemail_path = _history_paths()
                recent_calls, voicemails, security_events = _cached_history
                cdr_signature = _file_signature(cdr_path)
                if _cdr_history_signature != cdr_signature:
                    recent_calls = read_recent_cdr_calls(cdr_path, limit=1000)
                    _cdr_history_signature = cdr_signature
                voicemail_signature = _voicemail_signature(voicemail_path)
                if _voicemail_history_signature != voicemail_signature:
                    voicemails = read_recent_voicemails(voicemail_path)
                    _voicemail_history_signature = voicemail_signature
                security_path = _security_log_path()
                security_signature = _file_signature(security_path)
                if _security_history_signature != security_signature:
                    security_events = read_recent_security_events(security_path)
                    _security_history_signature = security_signature
                else:
                    security_cutoff = datetime.now() - timedelta(minutes=15)
                    security_events = [
                        event for event in security_events
                        if event.occurred_at is not None
                        and event.occurred_at >= security_cutoff
                    ]
                _cached_history = (
                    recent_calls,
                    voicemails,
                    security_events,
                )
            _history_refreshed_at = now_monotonic
        recent_calls, voicemails, security_events = _cached_history
        endpoints = snapshot.endpoints
        if settings.pbx_type == "cucm":
            endpoints = enrich_cucm_trunks_with_history(endpoints, recent_calls)
        snapshot = snapshot.__class__(
            reachable=snapshot.reachable,
            agent_version=snapshot.agent_version,
            channels=snapshot.channels,
            endpoints=endpoints,
            queues=snapshot.queues,
            recent_calls=recent_calls,
            voicemails=voicemails,
            security_events=security_events,
            error=snapshot.error,
        )
    observed_at = _now(settings.timezone)
    moment_events = activity_tracker.observe(snapshot, observed_at)
    endpoint_unavailability_signals = endpoint_availability_tracker.observe(
        snapshot,
        observed_at,
    )
    endpoint_notification_ids = endpoint_availability_tracker.notification_ids()
    endpoint_unavailability_evidence = endpoint_availability_tracker.signal_endpoints()
    endpoint_signal_lifecycle = endpoint_availability_tracker.signal_lifecycle()
    trunk_unavailability_signals = trunk_availability_tracker.observe(
        snapshot,
        observed_at,
    )
    show_aggregate_tip = endpoint_aggregate_tip_tracker.observe(snapshot, observed_at)
    endpoint_last_active = endpoint_last_active_tracker.observe(snapshot, observed_at)
    _cached_home_state = (
        snapshot,
        observed_at,
        moment_events,
        endpoint_unavailability_signals,
        endpoint_notification_ids,
        endpoint_unavailability_evidence,
        endpoint_signal_lifecycle,
        trunk_unavailability_signals,
        show_aggregate_tip,
        endpoint_last_active,
    )
    _cached_home_payloads.clear()
    return _cached_home_state


def _file_signature(path: str) -> tuple[str, int, int]:
    """Return cheap change evidence for an append-oriented history file."""
    if not path:
        return ("", 0, 0)
    try:
        stat = Path(path).stat()
        return (path, stat.st_size, stat.st_mtime_ns)
    except OSError:
        return (path, 0, 0)


def _voicemail_signature(path: str) -> tuple[tuple[str, int, int], ...]:
    """Fingerprint voicemail metadata without reopening message contents."""
    if not path:
        return ()
    root = Path(path)
    try:
        entries = []
        for item in root.glob("**/INBOX/msg*.txt"):
            stat = item.stat()
            entries.append((str(item), stat.st_size, stat.st_mtime_ns))
        return tuple(sorted(entries))
    except OSError:
        return ()


def _home_payload_from_state(state: tuple, *, moment_hours: int) -> dict:
    snapshot, observed_at, moment_events, endpoint_signals, endpoint_notification_ids, endpoint_unavailability_evidence, endpoint_signal_lifecycle, trunk_signals, show_aggregate_tip, endpoint_last_active = state
    payload = build_home_payload(
        snapshot,
        display_name=settings.display_name,
        extension_names=settings.extension_names,
        now=observed_at,
        timezone_name=settings.timezone,
        pbx_type=settings.pbx_type,
        pbx_host=_pbx_host(),
        pbx_port=_pbx_port(),
        moment_hours=moment_hours,
        moment_events=moment_events,
        endpoint_unavailability_signals=endpoint_signals,
        endpoint_notification_ids=endpoint_notification_ids,
        endpoint_unavailability_evidence=endpoint_unavailability_evidence,
        endpoint_signal_lifecycle=endpoint_signal_lifecycle,
        trunk_unavailability_signals=trunk_signals,
        endpoint_last_active=endpoint_last_active,
    )
    if not show_aggregate_tip:
        payload["signals"] = [
            signal for signal in payload["signals"]
            if signal.get("id") != "sig_tip_multiple_endpoints_unavailable"
        ]
    signal_notification_episode_tracker.observe(payload["signals"])
    payload["connection"]["releaseChannel"] = AGENT_RELEASE_CHANNEL
    payload["connection"]["pushRelayAgentId"] = str(
        push_relay.status().get("agentId", "")
    )
    payload["internetRelay"] = internet_relay.status()
    return payload


@app.post("/push/devices")
async def register_push_device(request: Request) -> dict[str, object]:
    """Forward this paired phone's FCM token to the enrolled relay Agent."""
    _require_token(request)
    _require_safe_cookie_mutation(request)
    payload = await _bounded_json_object(request)
    fcm_token = str(payload.get("fcmToken", "")).strip()
    _require_bounded_text(fcm_token, "fcmToken", 4096)
    for field, limit in (
        ("platform", 32),
        ("appVersion", 120),
        ("deviceModel", 120),
        ("deviceName", 120),
        ("osVersion", 120),
        ("relayDeviceId", 96),
        ("encryptionPublicKey", 100),
    ):
        value = str(payload.get(field, "")).strip()
        if value:
            _require_bounded_text(value, field, limit)
    muted_signal_ids = payload.get("mutedSignalIds", [])
    if not isinstance(muted_signal_ids, list) or len(muted_signal_ids) > 100:
        raise HTTPException(status_code=400, detail="mutedSignalIds must be a bounded list")
    normalized_muted_signal_ids: list[str] = []
    for value in muted_signal_ids:
        item = str(value).strip()
        _require_bounded_text(item, "mutedSignalIds", 160)
        if item:
            normalized_muted_signal_ids.append(item)
    return await asyncio.to_thread(
        push_relay.register_device,
        fcm_token=fcm_token,
        meaningful=bool(payload.get("meaningfulEnabled", True)),
        activity=bool(payload.get("activityEnabled", True)),
        muted_signal_ids=normalized_muted_signal_ids,
        platform=str(payload.get("platform", "android")),
        app_version=str(payload.get("appVersion", "")),
        device_model=str(payload.get("deviceModel", "")),
        device_name=str(payload.get("deviceName", "")),
        os_version=str(payload.get("osVersion", "")),
        relay_device_id=str(payload.get("relayDeviceId", "")),
        encryption_public_key=str(payload.get("encryptionPublicKey", "")),
    )


@app.get("/push/devices/status")
def push_device_registration_status(request: Request) -> dict[str, int | str]:
    """Let the protected Pair page detect a completed app registration."""
    _require_token(request)
    status = push_relay.status()
    return {
        "attemptRevision": int(status.get("deviceRegistrationAttemptRevision", 0)),
        "registrationRevision": int(status.get("deviceRegistrationRevision", 0)),
        "deviceRevision": _registered_device_revision(push_relay.devices()),
    }


def _registered_device_revision(result: dict[str, object]) -> str:
    """Fingerprint the relay list so Internet-only pairing refreshes /pair."""
    if result.get("available") is not True:
        return ""
    devices = result.get("devices", [])
    if not isinstance(devices, list):
        return ""
    values = sorted(
        f"{device.get('id', '')}|{device.get('updatedAt', '')}"
        for device in devices
        if isinstance(device, dict)
    )
    return hashlib.sha256("\n".join(values).encode("utf-8")).hexdigest()[:20]


@app.post("/push/devices/revoke")
async def revoke_push_device(request: Request) -> dict[str, bool]:
    _require_token(request)
    _require_safe_cookie_mutation(request)
    payload = await _bounded_json_object(request)
    token = str(payload.get("fcmToken", "")).strip()
    relay_device_id = str(payload.get("relayDeviceId", "")).strip()
    if token:
        _require_bounded_text(token, "fcmToken", 4096)
    if relay_device_id:
        _require_bounded_text(relay_device_id, "relayDeviceId", 96)
    return {"revoked": push_relay.remove_device(
        fcm_token=token, relay_device_id=relay_device_id
    )}


async def _bounded_json_object(
    request: Request, *, max_bytes: int = 64 * 1024
) -> dict[str, object]:
    content_length = request.headers.get("content-length", "")
    if content_length.isdigit() and int(content_length) > max_bytes:
        raise HTTPException(status_code=413, detail="Request body is too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > max_bytes:
            raise HTTPException(status_code=413, detail="Request body is too large")
    raw = bytes(body)
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="JSON body required") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON object required")
    return payload


def _require_bounded_text(value: str, field: str, limit: int) -> None:
    if not value:
        raise HTTPException(status_code=400, detail=f"{field} is required")
    if len(value) > limit:
        raise HTTPException(status_code=400, detail=f"{field} is too long")


def _moment_hours(request: Request) -> int:
    return _valid_moment_hours(request.query_params.get("momentHours", ""))


def _websocket_moment_hours(websocket: WebSocket) -> int:
    return _valid_moment_hours(websocket.query_params.get("momentHours", ""))


def _valid_moment_hours(value: object) -> int:
    try:
        hours = int(str(value))
    except (TypeError, ValueError):
        return 24
    return hours if hours in {1, 3, 6, 12, 24} else 24


def _pbx_host() -> str:
    if settings.pbx_type == "cucm":
        return settings.cucm_host
    if settings.pbx_type == "freeswitch":
        return settings.freeswitch_host
    if settings.pbx_type == "yeastar":
        return settings.yeastar_base_url
    if settings.pbx_type == "grandstream":
        return settings.grandstream_ami_host
    return settings.host


def _pbx_port() -> int | str:
    if settings.pbx_type == "cucm":
        return 8443
    if settings.pbx_type == "freeswitch":
        return settings.freeswitch_port
    if settings.pbx_type == "yeastar":
        return "https"
    if settings.pbx_type == "grandstream":
        return settings.grandstream_ami_port
    return settings.port


def _history_paths() -> tuple[str, str]:
    if settings.pbx_type == "grandstream":
        return settings.grandstream_cdr_csv_path, settings.grandstream_voicemail_path
    return settings.cdr_csv_path, settings.voicemail_path


def _recordings_path() -> str:
    if settings.pbx_type == "freeswitch":
        return settings.freeswitch_recordings_path
    if settings.pbx_type == "grandstream":
        return settings.grandstream_recordings_path
    return settings.asterisk_recordings_path


def _security_log_path() -> str:
    if settings.pbx_type == "grandstream":
        return settings.grandstream_security_log_path
    return settings.asterisk_security_log_path


def _brand_html() -> str:
    return f"""
      <div class="brand">
        <div class="mark" aria-hidden="true">
          {_beacon_svg()}
        </div>
        <div>
          <h1>PBXSense Agent</h1>
          <p class="subtitle">{escape(settings.display_name)}</p>
        </div>
      </div>
    """


def _agent_navigation_html(
    request: Request,
    *,
    current: str,
    primary: str,
    excluded: tuple[str, ...] = (),
    label_overrides: dict[str, str] | None = None,
    extra_links: tuple[tuple[str, str, bool], ...] = (),
) -> str:
    labels = label_overrides or {}
    links = (
        ("pair", "Pair app", "/pair"),
        ("apps", "Paired apps", "/apps"),
        ("home", "Agent status", "/"),
        ("diagnostics", "Diagnostics", "/diagnostics"),
    )
    rendered = "".join(
        f'<a class="button{" primary" if is_primary else ""}" '
        f'href="{href}">{label}</a>'
        for label, href, is_primary in extra_links
    )
    rendered += "".join(
        f'<a class="button{" primary" if key == primary else ""}" '
        f'href="{href}">{labels.get(key, label)}</a>'
        for key, label, href in links
        if key != current and key not in excluded
    )
    return f'<div class="actions">{rendered}</div>'


def _agent_footer_html() -> str:
    return f"""
      <div class="footer">
        <span class="footer-meta">
          <span>PBX: {escape(settings.pbx_type)}</span>
          <small>Version {AGENT_VERSION} &middot; {AGENT_RELEASE_CHANNEL.title()}</small>
        </span>
        <span class="footer-actions">
          <a
            class="discord-badge"
            href="https://discord.gg/5GgsSRasQB"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Join PBXSense on Discord"
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M19.5 5.34A16.3 16.3 0 0 0 15.44 4l-.5 1.02a15.1 15.1 0 0 0-5.86 0L8.56 4A16.5 16.5 0 0 0 4.5 5.35C1.93 9.16 1.24 12.88 1.59 16.54a16.7 16.7 0 0 0 4.98 2.5l1.2-1.64c-.66-.25-1.3-.56-1.9-.92l.47-.36c3.66 1.7 7.63 1.7 11.25 0l.48.36c-.6.36-1.24.67-1.9.92l1.2 1.64a16.7 16.7 0 0 0 4.98-2.5c.42-4.24-.72-7.92-2.85-11.2ZM8.83 14.28c-1.1 0-2-1.02-2-2.27 0-1.25.88-2.27 2-2.27 1.13 0 2.03 1.03 2 2.27 0 1.25-.88 2.27-2 2.27Zm6.34 0c-1.1 0-2-1.02-2-2.27 0-1.25.88-2.27 2-2.27 1.13 0 2.03 1.03 2 2.27 0 1.25-.87 2.27-2 2.27Z"></path>
            </svg>
            <span>Discord</span>
          </a>
        </span>
      </div>
    """


def _beacon_svg() -> str:
    """Match the PBXBeaconIcon used by the companion Flutter app."""
    return """
      <svg viewBox="0 0 32 32" fill="none" role="img" aria-label="PBXSense beacon" color="#75d49b">
        <circle cx="16" cy="16" r="8.8" stroke="currentColor" stroke-width="2.4"
          stroke-linecap="round" stroke-dasharray="44.6 10.7" transform="rotate(17 16 16)" opacity="0.68"/>
        <circle cx="16" cy="16" r="13.9" stroke="currentColor" stroke-width="2.4"
          stroke-linecap="round" stroke-dasharray="54.9 32.4" transform="rotate(123 16 16)" opacity="0.45"/>
        <circle cx="16" cy="16" r="3.7" fill="currentColor"/>
      </svg>
    """


def _json_page(
    request: Request,
    title: str,
    payload: dict,
    *,
    navigation_current: str | None = None,
    include_agent_footer: bool = False,
) -> str:
    formatted = escape(json.dumps(payload, indent=2, ensure_ascii=False))
    raw_json_query = {"format": "json"}
    moment_hours = request.query_params.get("momentHours", "").strip()
    if moment_hours:
        raw_json_query["momentHours"] = moment_hours
    navigation = (
        _agent_navigation_html(
            request,
            current=navigation_current,
            primary="" if navigation_current == "diagnostics" else "home",
            excluded=("pair", "apps") if navigation_current == "diagnostics" else (),
            extra_links=(
                (
                    "Raw JSON",
                    f"?{urlencode(raw_json_query)}",
                    navigation_current == "diagnostics",
                ),
            ),
        )
        if navigation_current
        else f"""
            <div class="actions">
              <a class="button" href="/">Agent status</a>
              <a class="button primary" href="?{urlencode(raw_json_query)}">Raw JSON</a>
            </div>
        """
    )
    return _page(
        title=title,
        body=f"""
          <section class="json-card">
            {_brand_html()}
            {navigation}
            <pre><code>{formatted}</code></pre>
            {_agent_footer_html() if include_agent_footer else ""}
          </section>
        """,
    )


def _wants_html(request: Request) -> bool:
    if request.query_params.get("format") == "json":
        return False
    return "text/html" in request.headers.get("accept", "")


def _agent_status() -> dict:
    diagnostics = _public_diagnostics(connector.diagnostics())
    relay_status = internet_relay.status()
    push_status = push_relay.status()
    diagnostics["internetRelayState"] = (
        "Disabled"
        if relay_status["enabled"] is not True
        else "Connected"
        if relay_status["connected"] is True
        else "Connecting securely"
    )
    diagnostics["internetRelayProtocol"] = f"v{relay_status['protocolVersion']}"
    diagnostics["pushRelayActivationError"] = str(
        push_status.get("lastActivationError", "")
    ) or "None"
    diagnostics["ok"] = diagnostics.get("ok") is True or diagnostics.get("loginAccepted") is True
    if diagnostics["ok"] and not diagnostics.get("message"):
        diagnostics["message"] = f"{connector.diagnostics_label} connection check succeeded."
    return diagnostics


def _yes_no(value: object) -> str:
    return "Yes" if value is True else "No"


def _diagnostic_rows(diagnostics: dict, message: object) -> str:
    connection_statuses = connector_diagnostic_statuses(diagnostics)
    fields = (
        ("host", "Host", False),
        ("port", "Port", False),
        ("baseUrl", "API URL", False),
        ("apiVersion", "API version", False),
        ("clientIdConfigured", "Client ID configured", True),
        ("clientSecretConfigured", "Client secret configured", True),
        ("tokenAccepted", "API token", True),
        ("apiReachable", "API", True),
        ("credentialsConfigured", "Credentials", True),
        ("axlReachable", "AXL inventory", True),
        ("risPortReachable", "Phone registration", True),
        ("jtapiConfigured", "JTAPI configured", True),
        ("jtapiCredentialsConfigured", "JTAPI credentials", True),
        ("jtapiProcessRunning", "JTAPI bridge", True),
        ("jtapiReachable", "JTAPI stream", True),
        ("jtapiActiveCalls", "JTAPI active calls", False),
        ("liveCallsAvailable", "Live calls", True),
        ("tlsEnabled", "TLS enabled", True),
        ("tlsVerification", "TLS verification", True),
        ("outboundRegistrationsReported", "Outbound registrations reported", False),
        ("outboundRegistrationWarning", "Outbound registration note", False),
        ("internetRelayState", "Internet relay", False),
        ("pushRelayActivationError", "Pairing relay error", False),
    )
    rows: list[str] = []
    for label, value in connection_statuses:
        rows.append(f"<div><dt>{label}</dt><dd>{value}</dd></div>")
    for key, label, boolean in fields:
        if key not in diagnostics:
            continue
        value = _yes_no(diagnostics[key]) if boolean else escape(str(diagnostics[key]))
        rows.append(f"<div><dt>{label}</dt><dd>{value}</dd></div>")
    rows.append(f"<div><dt>Message</dt><dd>{escape(str(message))}</dd></div>")
    return "".join(rows)


def _require_token(request: Request) -> None:
    if not settings.token:
        return
    token = _request_token(request)
    if not hmac.compare_digest(token, settings.token):
        raise HTTPException(status_code=401, detail="PBXSense Agent token required")


def _is_trusted_request(request: Request) -> bool:
    client_host = request.client.host if request.client else ""
    return is_private_or_loopback_host(client_host)


def _browser_session_transport_allowed(request: Request) -> bool:
    client_host = request.client.host if request.client else ""
    return _is_trusted_request(request) and (
        is_loopback_host(client_host) or _local_web_cookie_secure(request)
    )


def _consume_browser_bootstrap(supplied: str) -> bool:
    configured = settings.browser_bootstrap_token
    if (
        not configured
        or not supplied
        or settings.browser_bootstrap_expires_at < int(time.time())
        or not hmac.compare_digest(supplied, configured)
    ):
        return False
    digest = hashlib.sha256(configured.encode("utf-8")).hexdigest()
    path = Path(settings.browser_bootstrap_state_path)
    with _browser_bootstrap_lock:
        try:
            if path.read_text(encoding="ascii").strip() == digest:
                return False
        except FileNotFoundError:
            pass
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(digest + "\n", encoding="ascii")
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            os.replace(temporary, path)
            try:
                path.chmod(0o600)
            except OSError:
                pass
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return True


def _local_web_cookie_secure(request: Request) -> bool:
    """Bind the browser session to HTTPS, including proxy TLS termination."""
    if settings.public_url:
        return urlparse(settings.public_url).scheme == "https"
    return request.url.scheme == "https"


def _has_valid_local_web_cookie(request: Request) -> bool:
    if not settings.token or not _is_trusted_request(request):
        return False
    cookie_value = request.cookies.get(LOCAL_WEB_COOKIE, "")
    return hmac.compare_digest(cookie_value, _local_web_cookie_value())


def _local_web_cookie_value() -> str:
    return hmac.new(
        settings.token.encode("utf-8"),
        b"pbxsense-local-web",
        hashlib.sha256,
    ).hexdigest()


def _local_web_csrf_value() -> str:
    return hmac.new(
        settings.token.encode("utf-8"),
        b"pbxsense-local-web-csrf",
        hashlib.sha256,
    ).hexdigest()


def _request_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    if _has_valid_local_web_cookie(request):
        return settings.token
    return request.headers.get("x-pbxsense-token", "").strip()


def _require_safe_cookie_mutation(request: Request) -> None:
    """Reject cross-origin browser writes when the local admin cookie is auth."""
    authorization = request.headers.get("authorization", "")
    if (
        authorization.lower().startswith("bearer ")
        or request.headers.get("x-pbxsense-token", "").strip()
        or not _has_valid_local_web_cookie(request)
    ):
        return
    supplied_csrf = request.query_params.get("csrf", "").strip()
    if supplied_csrf and hmac.compare_digest(
        supplied_csrf,
        _local_web_csrf_value(),
    ):
        return
    expected = f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
    origin = request.headers.get("origin", "").rstrip("/")
    if not origin:
        referer = request.headers.get("referer", "")
        parsed = urlparse(referer)
        origin = (
            f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
            if parsed.netloc else ""
        )
    if not origin or not hmac.compare_digest(origin, expected):
        raise HTTPException(status_code=403, detail="Same-origin request required")


def _websocket_authorized(websocket: WebSocket) -> bool:
    if not settings.token:
        return True
    authorization = websocket.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    else:
        token = ""
        cookie = websocket.cookies.get(LOCAL_WEB_COOKIE, "")
        client_host = websocket.client.host if websocket.client else ""
        if (
            is_private_or_loopback_host(client_host)
            and hmac.compare_digest(cookie, _local_web_cookie_value())
        ):
            token = settings.token
    return hmac.compare_digest(token, settings.token)


def _pairing_payload(request: Request) -> str:
    agent_url = settings.public_url or str(request.base_url).rstrip("/")
    query = {"agent": agent_url}
    if settings.token:
        query["token"] = settings.token
    try:
        activation = push_relay.activation()
    except Exception:
        # Relay enrollment enriches the QR with cloud push support, but local
        # pairing must remain available if optional relay state is unhealthy.
        activation = {}
    if activation:
        query["relay"] = settings.relay_url
        query["activation"] = activation["id"]
        query["activationSecret"] = activation["secret"]
    return "pbxsense://pair?" + urlencode(query)


def _qr_svg(payload: str) -> str:
    try:
        import qrcode
        import qrcode.image.svg

        image = qrcode.make(
            payload,
            image_factory=qrcode.image.svg.SvgPathImage,
            box_size=12,
            border=2,
        )
        return image.to_string(encoding="unicode")
    except Exception:
        return "<p>QR generation is unavailable in this Agent image.</p>"


def _status_background(ok: bool) -> str:
    return "#e5f0dc" if ok else "#ffe1d8"


def _status_color(ok: bool) -> str:
    return "#4f7549" if ok else "#aa4b3d"
