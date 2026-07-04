from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from html import escape
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .connectors import connector_for_settings
from .history import history_diagnostics, read_recent_cdr_calls, read_recent_voicemails
from .live import home_live_events
from .mock import mock_snapshot
from .network import is_private_or_loopback_host
from .pulse import build_home_payload
from .settings import AgentSettings
from .version import AGENT_VERSION

settings = AgentSettings.from_env()
connector = connector_for_settings(settings)
app = FastAPI(title="PBXPulse Agent", version=AGENT_VERSION)
LOCAL_WEB_COOKIE = "pbxpulse_agent_local_web"
LIVE_INTERVAL_SECONDS = 1

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["authorization", "x-pbxpulse-token"],
)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if redirect := _localhost_cookie_redirect(request):
        return redirect
    _require_token(request)
    diagnostics = _agent_status()
    ok = diagnostics["ok"]
    status_text = "Connected" if ok else "Needs attention"
    status_detail = (
        f"The Agent can talk to {settings.display_name} and PBXPulse can use live snapshots."
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
        title="PBXPulse Agent",
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
            <p class="footer">PBX: {escape(settings.pbx_type)} - Version {AGENT_VERSION}</p>
          </section>
        """,
    )


def _page(*, title: str, body: str) -> str:
    return f"""<!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
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
            background: #30281f;
            color: var(--coral);
            box-shadow: inset 0 0 0 1px rgba(216, 174, 98, 0.22);
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
            margin-top: 18px;
            color: var(--muted);
            font-size: 13px;
          }}
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
    }


@app.get("/home")
def home(request: Request):
    if redirect := _localhost_cookie_redirect(request):
        return redirect
    _require_token(request)
    payload = _home_payload(moment_hours=_moment_hours(request))
    if _wants_html(request):
        return HTMLResponse(_json_page(request, "PBXPulse home snapshot", payload))
    return JSONResponse(payload)


@app.get("/pair", response_class=HTMLResponse)
def pair(request: Request):
    if redirect := _localhost_cookie_redirect(request):
        return redirect
    _require_token(request)
    payload = _pairing_payload(request)
    qr_svg = _qr_svg(payload)
    return _page(
        title="Pair PBXPulse",
        body=f"""
          <section class="hero-card">
            {_brand_html()}
            <div class="status ok">
              <span class="dot"></span>
              <span>Pairing ready<small>Scan this QR with PBXPulse setup, or paste the pairing text.</small></span>
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


def _diagnostics_response(request: Request):
    payload = connector.diagnostics()
    if settings.pbx_type == "asterisk":
        payload["history"] = history_diagnostics(
            settings.cdr_csv_path,
            settings.voicemail_path,
        )
    if _wants_html(request):
        return HTMLResponse(_json_page(request, "PBXPulse diagnostics", payload))
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
            await websocket.send_json({"type": "home_snapshot", "data": current_payload})
            previous_payload = current_payload
            continue
        for event in home_live_events(previous_payload, current_payload):
            await websocket.send_json(event)
        previous_payload = current_payload


def _home_payload(*, moment_hours: int = 24) -> dict:
    snapshot = connector.snapshot()
    if settings.pbx_type == "asterisk" and snapshot.reachable:
        snapshot = snapshot.__class__(
            reachable=snapshot.reachable,
            agent_version=snapshot.agent_version,
            channels=snapshot.channels,
            endpoints=snapshot.endpoints,
            recent_calls=read_recent_cdr_calls(settings.cdr_csv_path, limit=1000),
            voicemails=read_recent_voicemails(settings.voicemail_path),
            error=snapshot.error,
        )
    return build_home_payload(
        snapshot,
        display_name=settings.display_name,
        extension_names=settings.extension_names,
        timezone_name=settings.timezone,
        pbx_type=settings.pbx_type,
        pbx_host=_pbx_host(),
        pbx_port=_pbx_port(),
        moment_hours=moment_hours,
    )


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
    return settings.host


def _pbx_port() -> int:
    if settings.pbx_type == "freeswitch":
        return settings.freeswitch_port
    return settings.port


def _brand_html() -> str:
    return f"""
      <div class="brand">
        <div class="mark" aria-hidden="true">
          <svg viewBox="0 0 32 32" fill="none" role="img">
            <path d="M16 26C9.8 20.7 6 16.9 6 12.1C6 8.4 8.8 6 12 6C14.1 6 15.4 7.1 16 8.7C16.6 7.1 17.9 6 20 6C23.2 6 26 8.4 26 12.1C26 16.9 22.2 20.7 16 26Z" fill="currentColor"/>
            <path d="M7 16H12L14 12L17 21L20 16H25" stroke="#5f7f59" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
        <div>
          <h1>PBXPulse Agent</h1>
          <p class="subtitle">{escape(settings.display_name)}</p>
        </div>
      </div>
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
        raise HTTPException(status_code=401, detail="PBXPulse Agent token required")


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
        b"pbxpulse-local-web",
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
    return request.headers.get("x-pbxpulse-token", "").strip()


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
    return "pbxpulse://pair?" + urlencode(query)


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
