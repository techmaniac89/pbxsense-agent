from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import threading
import time
from datetime import timedelta
from html import escape
from urllib.parse import urlencode, urlparse

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response

from .connectors import connector_for_settings
from .diagnostics import ami_diagnostic_statuses
from .history import (
    history_diagnostics,
    read_recent_cdr_calls,
    read_recent_security_events,
    read_recent_voicemails,
    security_diagnostics,
)
from .internet_relay import SecureInternetRelay
from .live import home_live_events
from .mock import mock_snapshot
from .network import is_private_or_loopback_host
from .pulse import (
    ActivityTracker,
    EndpointAvailabilitySignalTracker,
    EndpointAggregateTipTracker,
    _now,
    build_home_payload,
)
from .recordings import find_recording
from .relay import AgentRelay
from .relay import PRESENCE_HEARTBEAT_INTERVAL_SECONDS
from .settings import AgentSettings
from .version import AGENT_RELEASE_CHANNEL, AGENT_VERSION

settings = AgentSettings.from_env()
connector = connector_for_settings(settings)
activity_tracker = ActivityTracker()
endpoint_availability_tracker = EndpointAvailabilitySignalTracker()
endpoint_aggregate_tip_tracker = EndpointAggregateTipTracker(
    timedelta(seconds=max(0, settings.quality_frequency_seconds))
)
push_relay = AgentRelay(
    url=settings.relay_url,
    identity_path=settings.relay_identity_path,
    display_name=settings.display_name,
    timeout_seconds=settings.relay_timeout_seconds,
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
LIVE_INTERVAL_SECONDS = 1
SNAPSHOT_POLL_INTERVAL_SECONDS = settings.snapshot_poll_seconds
HISTORY_POLL_INTERVAL_SECONDS = settings.history_poll_seconds
RELAY_PUBLISH_INTERVAL_SECONDS = 5
_snapshot_task: asyncio.Task[None] | None = None
_relay_publish_task: asyncio.Task[None] | None = None
_relay_heartbeat_task: asyncio.Task[None] | None = None
_internet_relay_task: asyncio.Task[None] | None = None
_snapshot_lock = threading.Lock()
_cached_home_state: tuple[object, object, list[dict], list[dict], bool] | None = None
_cached_history: tuple[list, list, list] = ([], [], [])
_history_refreshed_at = 0.0


@app.on_event("startup")
async def start_relay_publisher() -> None:
    global _internet_relay_task, _relay_heartbeat_task, _relay_publish_task, _snapshot_task
    _snapshot_task = asyncio.create_task(_snapshot_loop())
    if settings.relay_url:
        _relay_publish_task = asyncio.create_task(_relay_publish_loop())
        _relay_heartbeat_task = asyncio.create_task(_relay_heartbeat_loop())
        if settings.internet_relay_enabled:
            _internet_relay_task = asyncio.create_task(_internet_relay_loop())


@app.on_event("shutdown")
async def stop_relay_publisher() -> None:
    tasks = [
        task
        for task in (
            _snapshot_task,
            _relay_publish_task,
            _relay_heartbeat_task,
            _internet_relay_task,
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
            await asyncio.to_thread(_refresh_home_state)
        except Exception:
            # Connector failures normally produce an unreachable snapshot. An
            # unexpected parser/filesystem failure must not stop later polls.
            pass
        await asyncio.sleep(SNAPSHOT_POLL_INTERVAL_SECONDS)


async def _relay_publish_loop() -> None:
    while True:
        try:
            payload = await asyncio.to_thread(_home_payload)
            await asyncio.to_thread(push_relay.observe, payload.get("signals", []))
        except Exception:
            pass
        await asyncio.sleep(RELAY_PUBLISH_INTERVAL_SECONDS)


async def _relay_heartbeat_loop() -> None:
    """Keep presence independent from PBX polling and signal generation."""
    while True:
        try:
            await asyncio.to_thread(push_relay.heartbeat)
        except Exception:
            # Network and enrollment failures are retried on the next cadence.
            pass
        await asyncio.sleep(PRESENCE_HEARTBEAT_INTERVAL_SECONDS)


async def _internet_relay_loop() -> None:
    while True:
        await asyncio.to_thread(internet_relay.poll)
        await asyncio.sleep(settings.internet_relay_poll_seconds)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if redirect := _localhost_cookie_redirect(request):
        return redirect
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
            <div class="actions">
              <a class="button primary" href="/pair{_link_token_suffix(request)}">Pair app</a>
              <a class="button" href="/apps{_link_token_suffix(request)}">Paired apps</a>
              <a class="button" href="/diagnostics{_link_token_suffix(request)}">Diagnostics</a>
            </div>
            {diagnostic_html}
            <p class="footer">
              <span>PBX: {escape(settings.pbx_type)}</span>
              <small>Version {AGENT_VERSION} · {AGENT_RELEASE_CHANNEL.title()}</small>
            </p>
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
          .device-list {{ display: grid; gap: 12px; margin-top: 16px; }}
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
            display: grid;
            gap: 3px;
            margin-top: 18px;
            color: var(--muted);
            font-size: 13px;
          }}
          .footer small {{ font-size: inherit; }}
          pre {{
            margin: 18px 0 0;
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
            .diagnostics div {{ grid-template-columns: 1fr; gap: 3px; }}
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
    """Minimal unauthenticated probe; operational details remain protected."""
    return {
        "status": "ok",
        "service": "pbxsense-agent",
    }


@app.get("/favicon.svg", include_in_schema=False)
def favicon() -> Response:
    return Response(_beacon_svg(), media_type="image/svg+xml")


@app.get("/home")
def home(request: Request):
    if redirect := _localhost_cookie_redirect(request):
        return redirect
    _require_token(request)
    payload = _home_payload(moment_hours=_moment_hours(request))
    if _wants_html(request):
        return HTMLResponse(_json_page(request, "PBXSense home snapshot", payload))
    return JSONResponse(payload)


@app.get("/pair", response_class=HTMLResponse)
def pair(request: Request):
    if redirect := _localhost_cookie_redirect(request):
        return redirect
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
    if request.query_params.get("token", "").strip():
        apps_query["token"] = request.query_params["token"].strip()
    paired_apps_url = "/apps?" + urlencode(apps_query)
    relay_degraded = (
        relay_status.get("configured") is True
        and relay_status.get("enrolled") is not True
        and "activation=" not in payload
    )
    if relay_status.get("enrolled") is True:
        pairing_status = "Add another app"
        pairing_detail = (
            "Scan this QR on the additional phone. It will register its own push-notification device with this Agent."
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
            <div id="pairing-status" class="status {'attention' if relay_degraded else 'ok'}">
              <span class="dot"></span>
              <span>{pairing_status}<small>{pairing_detail}</small></span>
            </div>
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
            <div class="actions">
              <a class="button" href="/{_link_token_suffix(request)}">Agent status</a>
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
                const statusUrl = {json.dumps('/push/devices/status' + _link_token_suffix(request))};
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
          </section>
        """,
    )


@app.get("/apps", response_class=HTMLResponse)
def paired_apps(request: Request):
    if redirect := _localhost_cookie_redirect(request):
        return redirect
    _require_token(request)
    result = push_relay.devices()
    devices = result.get("devices", [])
    wait_for_device = request.query_params.get("waitForDevice") == "1"
    if result.get("state") == "notEnrolled" and wait_for_device:
        content = _waiting_for_registered_app()
    elif result.get("state") == "notEnrolled":
        content = """
          <div class="status empty">
            <span class="dot"></span>
            <span>No registered apps<small>Pair your first app. If this Agent was rebuilt and apps are missing, restore its previous relay identity or pair them again.</small></span>
          </div>
        """
    elif result.get("available") is not True:
        content = f"""
          <div class="status attention">
            <span class="dot"></span>
            <span>Apps unavailable<small>{escape(str(result.get('error', 'The push relay is unavailable.')))}</small></span>
          </div>
        """
    elif (not isinstance(devices, list) or not devices) and wait_for_device:
        content = _waiting_for_registered_app()
    elif not isinstance(devices, list) or not devices:
        content = """
          <div class="status empty">
            <span class="dot"></span>
            <span>No registered apps<small>Pair an app to register it for push notifications.</small></span>
          </div>
        """
    else:
        content = f"""
          <div class="status ok">
            <span class="dot"></span>
            <span>{len(devices)} registered {'app' if len(devices) == 1 else 'apps'}<small>Push registration details.</small></span>
          </div>
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
            <div class="section-heading"><span>Paired apps</span><small>Push relay</small></div>
            {removal_notice}
            {content}
            <div class="actions">
              <a class="button primary" href="/pair{_link_token_suffix(request)}">Add another app</a>
              <a class="button" href="/{_link_token_suffix(request)}">Agent status</a>
            </div>
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
    token = request.query_params.get("token", "").strip()
    if token:
        query["token"] = token
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
    remove_query = {"deviceId": revoke_id}
    query_token = request.query_params.get("token", "").strip()
    if query_token:
        remove_query["token"] = query_token
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
    if redirect := _localhost_cookie_redirect(request):
        return redirect
    _require_token(request)
    return _diagnostics_response(request)


@app.get("/recordings/{recording_id}")
def recording(recording_id: str, request: Request):
    _require_token(request)
    if settings.pbx_type == "yeastar":
        try:
            content, filename, media_type = connector.download_recording(recording_id)
        except OSError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(
            content=content,
            media_type=media_type if media_type != "application/octet-stream" else "audio/wav",
            headers={"Content-Disposition": f'inline; filename="{filename}"'},
        )

    root = _recordings_path()
    path = find_recording(root, recording_id)
    if path is None:
        raise HTTPException(status_code=404, detail="Recording was not found in the configured root")
    return FileResponse(path, filename=path.name)


def _diagnostics_response(request: Request):
    payload = connector.diagnostics()
    payload["internetRelay"] = internet_relay.status()
    if settings.pbx_type in {"asterisk", "grandstream"}:
        cdr_path, voicemail_path = _history_paths()
        payload["history"] = history_diagnostics(
            cdr_path,
            voicemail_path,
        )
        payload["security"] = security_diagnostics(_security_log_path())
    if _wants_html(request):
        return HTMLResponse(_json_page(request, "PBXSense diagnostics", payload))
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
                else:
                    await websocket.send_json({"type": "home_snapshot", "data": current_payload})
                previous_payload = current_payload
                continue
            for event in home_live_events(previous_payload, current_payload):
                await websocket.send_json(event)
            previous_payload = current_payload
    except WebSocketDisconnect:
        return


def _home_payload(*, moment_hours: int = 24) -> dict:
    global _cached_home_state
    with _snapshot_lock:
        if _cached_home_state is None:
            _refresh_home_state_locked()
        state = _cached_home_state
    return _home_payload_from_state(state, moment_hours=moment_hours)


def _refresh_home_state() -> None:
    with _snapshot_lock:
        _refresh_home_state_locked()


def _refresh_home_state_locked() -> tuple:
    global _cached_home_state, _cached_history, _history_refreshed_at
    snapshot = connector.snapshot()
    if settings.pbx_type in {"asterisk", "grandstream"}:
        now_monotonic = time.monotonic()
        if (
            _history_refreshed_at == 0
            or now_monotonic - _history_refreshed_at >= HISTORY_POLL_INTERVAL_SECONDS
        ):
            cdr_path, voicemail_path = _history_paths()
            _cached_history = (
                read_recent_cdr_calls(cdr_path, limit=1000),
                read_recent_voicemails(voicemail_path),
                read_recent_security_events(_security_log_path()),
            )
            _history_refreshed_at = now_monotonic
        recent_calls, voicemails, security_events = _cached_history
        snapshot = snapshot.__class__(
            reachable=snapshot.reachable,
            agent_version=snapshot.agent_version,
            channels=snapshot.channels,
            endpoints=snapshot.endpoints,
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
    show_aggregate_tip = endpoint_aggregate_tip_tracker.observe(snapshot, observed_at)
    _cached_home_state = (
        snapshot,
        observed_at,
        moment_events,
        endpoint_unavailability_signals,
        show_aggregate_tip,
    )
    return _cached_home_state


def _home_payload_from_state(state: tuple, *, moment_hours: int) -> dict:
    snapshot, observed_at, moment_events, endpoint_signals, show_aggregate_tip = state
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
    )
    if not show_aggregate_tip:
        payload["signals"] = [
            signal for signal in payload["signals"]
            if signal.get("id") != "sig_tip_multiple_endpoints_unavailable"
        ]
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
    return await asyncio.to_thread(
        push_relay.register_device,
        fcm_token=fcm_token,
        meaningful=bool(payload.get("meaningfulEnabled", True)),
        activity=bool(payload.get("activityEnabled", True)),
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
    raw = await request.body()
    if len(raw) > max_bytes:
        raise HTTPException(status_code=413, detail="Request body is too large")
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
    if settings.pbx_type == "freeswitch":
        return settings.freeswitch_host
    if settings.pbx_type == "yeastar":
        return settings.yeastar_base_url
    if settings.pbx_type == "grandstream":
        return settings.grandstream_ami_host
    return settings.host


def _pbx_port() -> int | str:
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
) -> str:
    formatted = escape(json.dumps(payload, indent=2, ensure_ascii=False))
    token_suffix = _link_token_suffix(request)
    raw_json_query = {"format": "json"}
    query_token = request.query_params.get("token", "").strip()
    if query_token:
        raw_json_query["token"] = query_token
    moment_hours = request.query_params.get("momentHours", "").strip()
    if moment_hours:
        raw_json_query["momentHours"] = moment_hours
    return _page(
        title=title,
        body=f"""
          <section class="json-card">
            {_brand_html()}
            <div class="actions">
              <a class="button" href="/{token_suffix}">Agent status</a>
              <a class="button primary" href="?{urlencode(raw_json_query)}">Raw JSON</a>
            </div>
            <pre><code>{formatted}</code></pre>
          </section>
        """,
    )


def _wants_html(request: Request) -> bool:
    if request.query_params.get("format") == "json":
        return False
    return "text/html" in request.headers.get("accept", "")


def _agent_status() -> dict:
    diagnostics = connector.diagnostics()
    relay_status = internet_relay.status()
    diagnostics["internetRelayState"] = (
        "Disabled"
        if relay_status["enabled"] is not True
        else "Connected"
        if relay_status["connected"] is True
        else "Connecting securely"
    )
    diagnostics["internetRelayProtocol"] = f"v{relay_status['protocolVersion']}"
    diagnostics["ok"] = diagnostics.get("ok") is True or diagnostics.get("loginAccepted") is True
    if diagnostics["ok"]:
        diagnostics["message"] = f"{connector.diagnostics_label} login succeeded."
    return diagnostics


def _yes_no(value: object) -> str:
    return "Yes" if value is True else "No"


def _diagnostic_rows(diagnostics: dict, message: object) -> str:
    ami_statuses = ami_diagnostic_statuses(diagnostics)
    fields = (
        ("host", "Host", False),
        ("port", "Port", False),
        ("baseUrl", "API URL", False),
        ("apiVersion", "API version", False),
        ("tokenAccepted", "API token", True),
        ("apiReachable", "API", True),
        ("commandAccepted", "Command", True),
        ("tlsVerification", "TLS verification", True),
        ("internetRelayState", "Internet relay", False),
        ("internetRelayProtocol", "Secure relay version", False),
    )
    rows: list[str] = []
    for label, value in ami_statuses:
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


def _localhost_cookie_redirect(request: Request) -> RedirectResponse | None:
    if not settings.token or not _wants_html(request) or not _is_trusted_request(request):
        return None
    query_token = request.query_params.get("token", "").strip()
    if query_token and hmac.compare_digest(query_token, settings.token):
        query = [(key, value) for key, value in request.query_params.multi_items() if key != "token"]
        target = str(request.url.replace(query=urlencode(query)))
        response = RedirectResponse(target)
        response.set_cookie(
            LOCAL_WEB_COOKIE,
            _local_web_cookie_value(),
            max_age=60 * 60 * 8,
            httponly=True,
            samesite="strict",
        )
        return response
    if _has_valid_local_web_cookie(request):
        return None
    return None


def _is_trusted_request(request: Request) -> bool:
    client_host = request.client.host if request.client else ""
    return is_private_or_loopback_host(client_host)


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


def _request_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    query_token = request.query_params.get("token", "").strip()
    if query_token:
        return query_token
    if _has_valid_local_web_cookie(request):
        return settings.token
    return request.headers.get("x-pbxsense-token", "").strip()


def _require_safe_cookie_mutation(request: Request) -> None:
    """Reject cross-origin browser writes when the local admin cookie is auth."""
    authorization = request.headers.get("authorization", "")
    if (
        authorization.lower().startswith("bearer ")
        or request.query_params.get("token", "").strip()
        or request.headers.get("x-pbxsense-token", "").strip()
        or not _has_valid_local_web_cookie(request)
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
        token = websocket.query_params.get("token", "").strip()
        if not token:
            cookie = websocket.cookies.get(LOCAL_WEB_COOKIE, "")
            if hmac.compare_digest(cookie, _local_web_cookie_value()):
                token = settings.token
    return hmac.compare_digest(token, settings.token)


def _link_token_suffix(request: Request) -> str:
    query_token = request.query_params.get("token", "").strip()
    if not query_token:
        return ""
    return "?" + urlencode({"token": query_token})


def _pairing_payload(request: Request) -> str:
    agent_url = str(request.base_url).rstrip("/")
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
