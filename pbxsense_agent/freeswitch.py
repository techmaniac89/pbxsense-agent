from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .history import CdrCall, VoicemailMessage
from .pulse import AmiChannel, AmiEndpoint, AmiQueue, AmiSnapshot
from .settings import AgentSettings
from .version import AGENT_VERSION


class FreeSwitchError(OSError):
    pass


@dataclass(frozen=True)
class FreeSwitchReply:
    headers: dict[str, str]
    body: str


class FreeSwitchClient:
    name = "freeswitch"
    diagnostics_label = "FreeSWITCH ESL"

    def __init__(self, settings: AgentSettings) -> None:
        self._settings = settings

    def snapshot(self) -> AmiSnapshot:
        try:
            channels = self._channels()
            endpoints = self._endpoints(channels)
            return AmiSnapshot(
                reachable=True,
                agent_version=AGENT_VERSION,
                channels=channels,
                endpoints=endpoints,
                queues=self._queues(),
                recent_calls=_read_json_cdr_calls(
                    self._settings.freeswitch_cdr_json_path,
                ),
                voicemails=_read_voicemails(
                    self._settings.freeswitch_voicemail_path,
                ),
            )
        except OSError as exc:
            return AmiSnapshot(
                reachable=False,
                agent_version=AGENT_VERSION,
                error=str(exc),
            )

    def diagnostics(self) -> dict:
        result: dict[str, object] = {
            "pbxType": "freeswitch",
            "host": self._settings.freeswitch_host,
            "port": self._settings.freeswitch_port,
            "timeoutSeconds": self._settings.timeout_seconds,
            "tcpConnected": False,
            "loginAccepted": False,
            "commandAccepted": False,
            "cdrJsonPath": self._settings.freeswitch_cdr_json_path,
            "cdrJsonReadable": _is_dir(self._settings.freeswitch_cdr_json_path),
            "voicemailPath": self._settings.freeswitch_voicemail_path,
            "voicemailPathReadable": _is_dir(self._settings.freeswitch_voicemail_path),
        }

        try:
            with self._connect() as sock:
                result["tcpConnected"] = True
                self._authenticate(sock)
                result["loginAccepted"] = True
                self._api(sock, "status")
                result["commandAccepted"] = True
        except OSError as exc:
            result["error"] = str(exc)

        result["ok"] = result["loginAccepted"] is True
        return result

    def _channels(self) -> list[AmiChannel]:
        with self._connect() as sock:
            self._authenticate(sock)
            raw = self._api(sock, "show channels as json")
        data = _json_object(raw)
        rows = _rows(data)
        return [_channel_from_row(row) for row in rows]

    def _endpoints(self, channels: list[AmiChannel]) -> list[AmiEndpoint]:
        active = {item.extension: item for item in self._endpoints_from_channels(channels)}
        try:
            with self._connect() as sock:
                self._authenticate(sock)
                rows = _rows(_json_object(self._api(sock, "show registrations as json")))
        except OSError:
            return list(active.values())

        endpoints: dict[str, AmiEndpoint] = dict(active)
        for row in rows:
            extension = _string(row, "reg_user", "user", "username")
            if not extension:
                continue
            current = active.get(extension)
            endpoints[extension] = AmiEndpoint(
                extension=extension,
                device_state="Reachable",
                active_channels=current.active_channels if current else 0,
                label=_string(row, "display_name", "name"),
            )
        return list(endpoints.values())

    def _queues(self) -> list[AmiQueue]:
        try:
            with self._connect() as sock:
                self._authenticate(sock)
                names = _pipe_first_column(self._api(sock, "callcenter_config queue list"))
                return [
                    AmiQueue(
                        name=name,
                        waiting_callers=_first_integer(
                            self._api(sock, f"callcenter_config queue count members {name}")
                        ),
                    )
                    for name in names
                ]
        except OSError:
            # mod_callcenter is optional; live calls and presence still work.
            return []

    def _connect(self) -> socket.socket:
        try:
            sock = socket.create_connection(
                (self._settings.freeswitch_host, self._settings.freeswitch_port),
                timeout=self._settings.timeout_seconds,
            )
            sock.settimeout(self._settings.timeout_seconds)
            return sock
        except TimeoutError as exc:
            raise FreeSwitchError(
                "FreeSWITCH ESL TCP connect to "
                f"{self._settings.freeswitch_host}:{self._settings.freeswitch_port} timed out"
            ) from exc
        except OSError as exc:
            raise FreeSwitchError(
                "FreeSWITCH ESL TCP connect to "
                f"{self._settings.freeswitch_host}:{self._settings.freeswitch_port} failed: {exc}"
            ) from exc

    def _authenticate(self, sock: socket.socket) -> None:
        greeting = self._read_reply(sock, phase="FreeSWITCH ESL greeting")
        if greeting.headers.get("content-type", "").lower() != "auth/request":
            raise FreeSwitchError("FreeSWITCH ESL did not request authentication")
        if not self._settings.freeswitch_password:
            raise FreeSwitchError("FreeSWITCH ESL password is not configured")
        self._send(sock, f"auth {self._settings.freeswitch_password}")
        reply = self._read_reply(sock, phase="FreeSWITCH ESL auth")
        if "+OK" not in reply.body:
            raise FreeSwitchError("FreeSWITCH ESL authentication failed")

    def _api(self, sock: socket.socket, command: str) -> str:
        self._send(sock, f"api {command}")
        reply = self._read_reply(sock, phase=f"FreeSWITCH ESL api {command}")
        if reply.body.startswith("-ERR"):
            raise FreeSwitchError(reply.body)
        return reply.body

    def _send(self, sock: socket.socket, command: str) -> None:
        sock.sendall(f"{command}\n\n".encode("utf-8"))

    def _read_reply(self, sock: socket.socket, *, phase: str) -> FreeSwitchReply:
        raw_headers = self._read_until(sock, b"\n\n", phase=phase)
        headers = _parse_headers(raw_headers.decode("utf-8", errors="replace"))
        length = int(headers.get("content-length", "0") or "0")
        body = self._read_exact(sock, length, phase=phase) if length else b""
        return FreeSwitchReply(
            headers=headers,
            body=body.decode("utf-8", errors="replace").strip(),
        )

    def _read_until(self, sock: socket.socket, marker: bytes, *, phase: str) -> bytes:
        chunks: list[bytes] = []
        try:
            while True:
                chunk = sock.recv(1)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"".join(chunks).endswith(marker):
                    break
        except TimeoutError as exc:
            raise FreeSwitchError(f"{phase} timed out") from exc
        return b"".join(chunks)

    def _read_exact(self, sock: socket.socket, length: int, *, phase: str) -> bytes:
        chunks: list[bytes] = []
        remaining = length
        try:
            while remaining > 0:
                chunk = sock.recv(remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        except TimeoutError as exc:
            raise FreeSwitchError(f"{phase} body timed out") from exc
        return b"".join(chunks)

    def _endpoints_from_channels(self, channels: list[AmiChannel]) -> list[AmiEndpoint]:
        endpoints: dict[str, AmiEndpoint] = {}
        for channel in channels:
            endpoint = channel.endpoint or channel.extension
            if not endpoint:
                continue
            existing = endpoints.get(endpoint)
            active_channels = (existing.active_channels if existing else 0) + 1
            endpoints[endpoint] = AmiEndpoint(
                extension=endpoint,
                device_state="Reachable",
                active_channels=active_channels,
                label=channel.caller if channel.caller != endpoint else "",
                role="extension",
            )
        return list(endpoints.values())


def _parse_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def _json_object(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = data.get("rows")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    return []


def _pipe_first_column(raw: str) -> list[str]:
    names: list[str] = []
    for line in raw.splitlines():
        value = line.split("|", 1)[0].strip()
        if not value or value.lower() in {"name", "queue", "+ok"} or value.startswith("-"):
            continue
        names.append(value)
    return names


def _first_integer(raw: str) -> int:
    for value in raw.replace("+OK", "").split():
        try:
            return max(0, int(value))
        except ValueError:
            continue
    return 0


def _channel_from_row(row: dict[str, Any]) -> AmiChannel:
    name = _string(row, "name", "uuid")
    endpoint = _endpoint_from_channel(name)
    caller_number = _string(row, "cid_num", "cid_number", "caller_id_number")
    caller = _string(row, "cid_name", "caller_id_name", "cid_num")
    destination = _string(row, "dest", "callee_num", "presence_id")
    state = _string(row, "state", "callstate")
    return AmiChannel(
        channel=name,
        extension=destination or endpoint,
        caller=caller or caller_number,
        connected=destination,
        state=state,
        endpoint=endpoint,
        caller_number=caller_number,
        connected_number=destination,
        duration=_string(row, "duration", "call_created_epoch"),
        unique_id=_string(row, "uuid"),
        linked_id=_string(row, "bleg_uuid", "call_uuid", "uuid"),
    )


def _read_json_cdr_calls(path: str, *, limit: int = 1000) -> list[CdrCall]:
    root = Path(path) if path else None
    if root is None or not _safe_is_dir(root):
        return []

    files = _recent_files(root, "*.json", limit * 3)
    calls: list[CdrCall] = []
    for file in files:
        try:
            data = json.loads(file.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        row = _flatten_json_cdr(data)
        calls.append(
            CdrCall(
                source=_string(row, "caller_id_number", "cid_num", "caller", "from"),
                destination=_string(row, "destination_number", "dest", "callee", "to"),
                disposition=_cdr_disposition(row),
                started_at=_parse_datetime(
                    _string(row, "start_stamp", "created_time", "start_epoch")
                ),
                duration_seconds=_parse_int(
                    _string(row, "duration", "billsec", "billsec_seconds")
                ),
                context=_string(row, "context", "dialplan", "section"),
                channel=_string(row, "channel_name", "uuid"),
                destination_channel=_string(row, "bridge_uuid", "bleg_uuid"),
                last_app=_string(row, "last_app", "application"),
                last_data=_string(row, "last_arg", "application_data"),
                recording_id=_recording_filename(
                    _string(
                        row,
                        "recording_file",
                        "record_file",
                        "record_path",
                    )
                ),
            )
        )

    calls.sort(key=lambda call: call.started_at or datetime.min, reverse=True)
    return calls[:limit]


def _read_voicemails(path: str, *, limit: int = 100) -> list[VoicemailMessage]:
    root = Path(path) if path else None
    if root is None or not _safe_is_dir(root):
        return []

    messages: list[VoicemailMessage] = []
    for file in _recent_files(root, "*.txt", limit):
        metadata = _key_value_file(file)
        mailbox = _string(metadata, "username", "mailbox", "extension") or file.parent.name
        caller = _string(metadata, "caller_id_name", "caller_id_number", "caller")
        messages.append(
            VoicemailMessage(
                mailbox=mailbox,
                caller=caller or "A caller",
                created_at=_parse_datetime(
                    _string(metadata, "created_epoch", "created", "timestamp")
                ),
            )
        )
    return messages


def _flatten_json_cdr(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    flattened: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            for nested_key, nested_value in value.items():
                flattened.setdefault(str(nested_key), nested_value)
                flattened.setdefault(f"{key}_{nested_key}", nested_value)
        else:
            flattened[str(key)] = value
    variables = data.get("variables")
    if isinstance(variables, dict):
        flattened.update({str(key): value for key, value in variables.items()})
    callflow = data.get("callflow")
    if isinstance(callflow, list) and callflow:
        first = callflow[0]
        if isinstance(first, dict):
            flattened.update(_flatten_json_cdr(first))
    return flattened


def _cdr_disposition(row: dict[str, Any]) -> str:
    raw = _string(row, "hangup_cause", "disposition", "status")
    normalized = raw.lower()
    if any(marker in normalized for marker in ("no_answer", "no answer", "originator_cancel")):
        return "NO ANSWER"
    if "busy" in normalized:
        return "BUSY"
    if any(marker in normalized for marker in ("fail", "error", "unallocated")):
        return "FAILED"
    return "ANSWERED" if raw else "ANSWERED"


def _recent_files(root: Path, pattern: str, limit: int) -> list[Path]:
    try:
        files = [file for file in root.rglob(pattern) if file.is_file()]
    except OSError:
        return []
    files.sort(key=lambda file: _mtime(file), reverse=True)
    return files[:limit]


def _key_value_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return result
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip().strip('"')
    return result


def _parse_datetime(raw: str) -> datetime | None:
    value = raw.strip()
    if not value:
        return None
    if value.isdigit():
        try:
            return datetime.fromtimestamp(int(value))
        except (OSError, ValueError):
            return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).replace(tzinfo=None)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _parse_int(raw: str) -> int:
    try:
        return int(float(raw.strip()))
    except ValueError:
        return 0


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0


def _is_dir(path: str) -> bool:
    return _safe_is_dir(Path(path)) if path else False


def _safe_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _endpoint_from_channel(value: str) -> str:
    if "/" not in value:
        return value
    endpoint = value.rsplit("/", 1)[1]
    return endpoint.split("@", 1)[0].split("-", 1)[0]


def _string(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _recording_filename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1]
