from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import timedelta
from html import escape
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response

from .connectors import connector_for_settings
from .history import (
    history_diagnostics,
    read_recent_cdr_calls,
    read_recent_security_events,
    read_recent_voicemails,
    security_diagnostics,
)
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
from .settings import AgentSettings
from .version import AGENT_VERSION

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
app = FastAPI(title="PBXSense Agent", version=AGENT_VERSION)
LOCAL_WEB_COOKIE = "pbxsense_agent_local_web"
LIVE_INTERVAL_SECONDS = 1
RELAY_PUBLISH_INTERVAL_SECONDS = 5
_relay_publish_task: asyncio.Task[None] | None = None

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["authorization", "x-pbxsense-token"],
)


@app.on_event("startup")
async def start_relay_publisher() -> None:
    global _relay_publish_task
    if settings.relay_url:
        _relay_publish_task = asyncio.create_task(_relay_publish_loop())


@app.on_event("shutdown")
async def stop_relay_publisher() -> None:
    if _relay_publish_task is not None:
        _relay_publish_task.cancel()
        try:
            await _relay_publish_task
        except asyncio.CancelledError:
            pass


async def _relay_publish_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(_home_payload)
            await asyncio.to_thread(push_relay.heartbeat)
        except Exception:
            # A connector failure is already represented by the normal health
            # signal; it must not permanently stop remote push processing.
            pass
        await asyncio.sleep(RELAY_PUBLISH_INTERVAL_SECONDS)


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
          <dl class="diagnostics">
            <div><dt>Host</dt><dd>{escape(str(diagnostics.get("host", "")))}</dd></div>
            <div><dt>Port</dt><dd>{escape(str(diagnostics.get("port", "")))}</dd></div>
            <div><dt>TCP</dt><dd>{_yes_no(diagnostics.get("tcpConnected"))}</dd></div>
            <div><dt>Banner</dt><dd>{_yes_no(diagnostics.get("bannerReceived"))}</dd></div>
            <div><dt>Login</dt><dd>{_yes_no(diagnostics.get("loginAccepted"))}</dd></div>
            <div><dt>Message</dt><dd>{escape(str(diagnostic_message))}</dd></div>
          </dl>
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
              <a class="button" href="/home{_link_token_suffix(request)}">Home snapshot</a>
              <a class="button" href="/diagnostics{_link_token_suffix(request)}">Diagnostics</a>
            </div>
            {diagnostic_html}
            <p class="footer">
              <span>PBX: {escape(settings.pbx_type)}</span>
              <small>Version {AGENT_VERSION}</small>
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
            margin-top: 18px;
            padding: 14px;
            border-radius: 16px;
            background: #191612;
            border: 1px solid var(--line);
            color: var(--muted);
            overflow-wrap: anywhere;
            font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
            font-size: 12px;
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
def health(request: Request) -> dict[str, object]:
    _require_token(request)
    return {
        "status": "ok",
        "mode": settings.mode,
        "pbxType": settings.pbx_type,
        "authRequired": bool(settings.token),
        "pushRelay": push_relay.status(),
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
    return _page(
        title="Pair PBXSense",
        body=f"""
          <section class="hero-card">
            {_brand_html()}
            <div class="status ok">
              <span class="dot"></span>
              <span>Pairing ready<small>Scan this QR with PBXSense setup, or paste the pairing text.</small></span>
            </div>
            <div class="qr">{qr_svg}</div>
            <div class="pairing-code">{escape(payload)}</div>
            <div class="actions">
              <a class="button" href="/{_link_token_suffix(request)}">Agent status</a>
            </div>
          </section>
        """,
    )


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


def _home_payload(*, moment_hours: int = 24) -> dict:
    snapshot = connector.snapshot()
    if settings.pbx_type in {"asterisk", "grandstream"}:
        cdr_path, voicemail_path = _history_paths()
        snapshot = snapshot.__class__(
            reachable=snapshot.reachable,
            agent_version=snapshot.agent_version,
            channels=snapshot.channels,
            endpoints=snapshot.endpoints,
            queues=snapshot.queues,
            recent_calls=read_recent_cdr_calls(cdr_path, limit=1000),
            voicemails=read_recent_voicemails(voicemail_path),
            security_events=read_recent_security_events(_security_log_path()),
            error=snapshot.error,
        )
    observed_at = _now(settings.timezone)
    moment_events = activity_tracker.observe(snapshot, observed_at)
    endpoint_unavailability_signals = endpoint_availability_tracker.observe(
        snapshot,
        observed_at,
    )
    show_aggregate_tip = endpoint_aggregate_tip_tracker.observe(snapshot, observed_at)


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
        endpoint_unavailability_signals=endpoint_unavailability_signals,
    )
    if not show_aggregate_tip:
        payload["signals"] = [
            signal for signal in payload["signals"]
            if signal.get("id") != "sig_tip_multiple_endpoints_unavailable"
        ]
    push_relay.observe(payload.get("signals", []))
    return payload


@app.post("/push/devices")
async def register_push_device(request: Request) -> dict[str, object]:
    """Forward this paired phone's FCM token to the enrolled relay Agent."""
    _require_token(request)
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="JSON body required") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON object required")
    fcm_token = str(payload.get("fcmToken", "")).strip()
    if not fcm_token:
        raise HTTPException(status_code=400, detail="fcmToken is required")
    return push_relay.register_device(
        fcm_token=fcm_token,
        meaningful=bool(payload.get("meaningfulEnabled", True)),
        activity=bool(payload.get("activityEnabled", True)),
    )


@app.post("/push/devices/revoke")
async def revoke_push_device(request: Request) -> dict[str, bool]:
    _require_token(request)
    payload = await request.json()
    token = str(payload.get("fcmToken", "")).strip() if isinstance(payload, dict) else ""
    return {"revoked": push_relay.remove_device(fcm_token=token)}


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


def _json_page(request: Request, title: str, payload: dict) -> str:
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
    diagnostics["ok"] = diagnostics.get("ok") is True or diagnostics.get("loginAccepted") is True
    if diagnostics["ok"]:
        diagnostics["message"] = f"{connector.diagnostics_label} login succeeded."
    return diagnostics


def _yes_no(value: object) -> str:
    return "Yes" if value is True else "No"


def _require_token(request: Request) -> None:
    if not settings.token:
        return
    token = _request_token(request)
    if not hmac.compare_digest(token, settings.token):
        raise HTTPException(status_code=401, detail="PBXSense Agent token required")


def _localhost_cookie_redirect(request: Request) -> RedirectResponse | None:
    if not settings.token or request.query_params.get("token"):
        return None
    if _has_valid_local_web_cookie(request):
        return None
    if not _wants_html(request) or not _is_trusted_request(request):
        return None
    response = RedirectResponse(str(request.url))
    response.set_cookie(
        LOCAL_WEB_COOKIE,
        _local_web_cookie_value(),
        max_age=60 * 60 * 8,
        httponly=True,
        samesite="lax",
    )
    return response


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
    # The Agent is intended to live on a trusted LAN/VPN beside the PBX.
    # Private clients can inspect local Agent endpoints without token URLs.
    if _is_trusted_request(request):
        return settings.token
    if _has_valid_local_web_cookie(request):
        return settings.token
    return request.headers.get("x-pbxsense-token", "").strip()


def _websocket_authorized(websocket: WebSocket) -> bool:
    if not settings.token:
        return True
    client_host = websocket.client.host if websocket.client else ""
    # Match HTTP behavior for local app clients that do not put tokens on /live.
    if is_private_or_loopback_host(client_host):
        return True
    authorization = websocket.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    else:
        token = websocket.query_params.get("token", "").strip()
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
    activation = push_relay.activation()
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
