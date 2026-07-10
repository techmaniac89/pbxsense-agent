from __future__ import annotations

import json
import ssl
import time
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .history import CdrCall, VoicemailMessage
from .pulse import AmiChannel, AmiEndpoint, AmiSnapshot
from .settings import AgentSettings
from .version import AGENT_VERSION


class YeastarError(OSError):
    pass


class YeastarClient:
    name = "yeastar"
    diagnostics_label = "Yeastar P-Series API"

    def __init__(self, settings: AgentSettings) -> None:
        self._settings = settings
        self._access_token = ""
        self._token_expires_at = 0.0
        self._cached_snapshot: AmiSnapshot | None = None
        self._snapshot_refresh_after = 0.0

    def snapshot(self) -> AmiSnapshot:
        if self._cached_snapshot and time.monotonic() < self._snapshot_refresh_after:
            return self._cached_snapshot
        try:
            endpoints = self._endpoints()
            snapshot = AmiSnapshot(
                reachable=True,
                agent_version=AGENT_VERSION,
                channels=self._channels(),
                endpoints=endpoints,
                recent_calls=self._cdr_calls(),
                voicemails=self._voicemails(endpoints),
            )
        except OSError as exc:
            snapshot = AmiSnapshot(reachable=False, agent_version=AGENT_VERSION, error=str(exc))
        self._cached_snapshot = snapshot
        # The web UI checks for updates every second. Keep cloud polling modest
        # while preserving a near-live view without a user-configured interval.
        self._snapshot_refresh_after = time.monotonic() + 2
        return snapshot

    def diagnostics(self) -> dict[str, object]:
        result: dict[str, object] = {
            "pbxType": "yeastar",
            "baseUrl": self._settings.yeastar_base_url,
            "apiVersion": self._settings.yeastar_api_version,
            "clientIdConfigured": bool(self._settings.yeastar_client_id),
            "clientSecretConfigured": bool(self._settings.yeastar_client_secret),
            "tlsVerification": self._settings.yeastar_verify_tls,
            "tokenAccepted": False,
            "apiReachable": False,
        }
        try:
            self._api("system/information")
            result["tokenAccepted"] = True
            result["apiReachable"] = True
        except OSError as exc:
            result["error"] = str(exc)
        result["ok"] = result["apiReachable"] is True
        return result

    def download_recording(self, recording_id: str) -> tuple[bytes, str, str]:
        response = self._api("recording/download", {"file": recording_id})
        resource = _string(response, "download_resource_url")
        if not resource:
            raise YeastarError("Yeastar did not return a recording download URL")
        separator = "&" if "?" in resource else "?"
        url = f"{self._settings.yeastar_base_url}{resource}{separator}access_token={self._token()}"
        request = Request(url, headers={"User-Agent": "PBXSense-Agent"})
        try:
            context = None if self._settings.yeastar_verify_tls else ssl._create_unverified_context()
            with urlopen(request, timeout=self._settings.timeout_seconds, context=context) as result:
                return (
                    result.read(),
                    _string(response, "file") or recording_id,
                    result.headers.get_content_type(),
                )
        except (HTTPError, URLError, TimeoutError) as exc:
            raise YeastarError(f"Yeastar recording download failed: {exc}") from exc

    def _endpoints(self) -> list[AmiEndpoint]:
        response = self._api("extension/search", {"page": 1, "page_size": 1000})
        endpoints: list[AmiEndpoint] = []
        for row in _rows(response):
            number = _string(row, "number")
            if not number:
                continue
            online = any(
                _integer(item.get("status")) == 1
                for item in _list(row.get("status_list"))
            ) or _integer(_object(row.get("online_status")).get("status")) == 1
            endpoints.append(
                AmiEndpoint(
                    extension=number,
                    device_state="Reachable" if online else "Unavailable",
                    label=_string(row, "caller_id_name", "name"),
                    presence=_string(
                        row,
                        "presence_status",
                        "presence",
                        "presence_state",
                    ),
                )
            )
        return endpoints

    def _channels(self) -> list[AmiChannel]:
        channels: list[AmiChannel] = []
        for call_type in ("inbound", "outbound", "internal"):
            response = self._api("call/query", {"type": call_type})
            channels.extend(_channels_from_call_response(response))
        return channels

    def _cdr_calls(self) -> list[CdrCall]:
        response = self._api(
            "cdr/list",
            {"page": 1, "page_size": 1000, "sort_by": "time", "order_by": "desc"},
        )
        calls: list[CdrCall] = []
        for row in _rows(response):
            calls.append(
                CdrCall(
                    source=_string(row, "call_from_number", "call_from"),
                    destination=_string(row, "call_to_number", "call_to"),
                    disposition=_string(row, "disposition").upper(),
                    started_at=_parse_datetime(_string(row, "time", "timestamp")),
                    duration_seconds=_integer(row.get("duration")),
                    recording_id=_string(row, "record_file"),
                )
            )
        return calls

    def _voicemails(self, endpoints: list[AmiEndpoint]) -> list[VoicemailMessage]:
        numbers = [endpoint.extension for endpoint in endpoints]
        if not numbers:
            return []
        messages: list[VoicemailMessage] = []
        for start in range(0, len(numbers), 50):
            response = self._api("vm/query", {"number": ",".join(numbers[start : start + 50])})
            for mailbox in _list(response.get("voicemail_list")):
                mailbox_number = _string(mailbox, "number")
                for item in _list(mailbox.get("data")):
                    messages.append(
                        VoicemailMessage(
                            mailbox=mailbox_number,
                            caller=_string(item, "name", "number") or "A caller",
                            created_at=_parse_datetime(_string(item, "time")),
                        )
                    )
        messages.sort(key=lambda item: item.created_at or datetime.min, reverse=True)
        return messages[:100]

    def _api(self, endpoint: str, params: dict[str, object] | None = None) -> dict[str, Any]:
        values = dict(params or {})
        values["access_token"] = self._token()
        return self._request_json("GET", endpoint, values)

    def _token(self) -> str:
        if self._access_token and time.monotonic() < self._token_expires_at:
            return self._access_token
        if not self._settings.yeastar_base_url:
            raise YeastarError("Yeastar base URL is not configured")
        if not self._settings.yeastar_client_id or not self._settings.yeastar_client_secret:
            raise YeastarError("Yeastar Client ID and Client Secret are not configured")
        response = self._request_json(
            "POST",
            "get_token",
            payload={
                "username": self._settings.yeastar_client_id,
                "password": self._settings.yeastar_client_secret,
            },
        )
        token = _string(response, "access_token")
        if not token:
            raise YeastarError("Yeastar did not return an access token")
        self._access_token = token
        self._token_expires_at = time.monotonic() + max(
            _integer(response.get("access_token_expire_time")) - 30,
            30,
        )
        return token

    def _request_json(
        self,
        method: str,
        endpoint: str,
        params: dict[str, object] | None = None,
        payload: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        query = f"?{urlencode(params)}" if params else ""
        url = f"{self._settings.yeastar_base_url}/openapi/{self._settings.yeastar_api_version}/{endpoint}{query}"
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            url,
            data=body,
            method=method,
            headers={"User-Agent": "PBXSense-Agent", "Content-Type": "application/json"},
        )
        try:
            context = None if self._settings.yeastar_verify_tls else ssl._create_unverified_context()
            with urlopen(request, timeout=self._settings.timeout_seconds, context=context) as response:
                result = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise YeastarError(f"Yeastar API {endpoint} failed: HTTP {exc.code}") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise YeastarError(f"Yeastar API {endpoint} failed: {exc}") from exc
        if not isinstance(result, dict):
            raise YeastarError(f"Yeastar API {endpoint} returned an invalid response")
        if _integer(result.get("errcode")) != 0:
            raise YeastarError(
                f"Yeastar API {endpoint} failed: {_string(result, 'errmsg') or result.get('errcode')}"
            )
        return result


def _channels_from_call_response(response: dict[str, Any]) -> list[AmiChannel]:
    channels: list[AmiChannel] = []
    for call in _rows(response):
        call_id = _string(call, "call_id")
        for member in _list(call.get("members")):
            for kind in ("extension", "inbound", "outbound"):
                details = _object(member.get(kind))
                if not details:
                    continue
                number = _string(details, "number", "to", "from")
                peer = _string(details, "to", "from")
                channels.append(
                    AmiChannel(
                        channel=_string(details, "channel_id") or call_id,
                        extension=number,
                        caller=_string(details, "from", "number"),
                        connected=peer,
                        state=_string(details, "member_status"),
                        endpoint=number,
                        caller_number=_string(details, "from", "number"),
                        connected_number=peer,
                        unique_id=_string(details, "channel_id") or call_id,
                        linked_id=call_id,
                    )
                )
    return channels


def _rows(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _list(response.get("data"))


def _list(value: object) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _integer(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _parse_datetime(value: str) -> datetime | None:
    if value.isdigit():
        try:
            return datetime.fromtimestamp(int(value))
        except (OSError, ValueError):
            return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        for format_string in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(value, format_string)
            except ValueError:
                continue
    return None
