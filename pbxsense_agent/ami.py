from __future__ import annotations

import re
import socket
from dataclasses import dataclass

from .pulse import AmiChannel, AmiEndpoint, AmiQueue, AmiSnapshot
from .settings import AgentSettings
from .version import AGENT_VERSION


@dataclass(frozen=True)
class AmiEvent:
    name: str
    fields: dict[str, str]


class AmiError(OSError):
    pass


class AmiClient:
    name = "asterisk"
    diagnostics_label = "Asterisk AMI"
    pbx_type = "asterisk"

    def __init__(self, settings: AgentSettings) -> None:
        self._settings = settings

    def snapshot(self) -> AmiSnapshot:
        try:
            events = self._read_events()
            return AmiSnapshot(
                reachable=True,
                agent_version=AGENT_VERSION,
                channels=_channels_from_events(events),
                endpoints=_endpoints_from_events(events),
                queues=_queues_from_events(events),
            )
        except OSError as exc:
            return AmiSnapshot(
                reachable=False,
                agent_version=AGENT_VERSION,
                error=str(exc),
            )

    def diagnostics(self) -> dict:
        result: dict[str, object] = {
            "pbxType": self.pbx_type,
            "host": self._ami_host(),
            "port": self._ami_port(),
            "username": self._ami_username(),
            "timeoutSeconds": self._settings.timeout_seconds,
            "tcpConnected": False,
            "bannerReceived": False,
            "loginAccepted": False,
        }

        try:
            with self._connect() as sock:
                result["tcpConnected"] = True
                banner, banner_error = self._read_optional_banner(sock)
                result["bannerReceived"] = bool(banner)
                result["banner"] = banner
                if banner_error:
                    result["bannerWarning"] = banner_error
                response = self._login(sock)
                result["loginAccepted"] = response.get("Response") == "Success"
                result["loginResponse"] = response.get("Response", "")
                result["loginMessage"] = response.get("Message", "")
                self._send_action(sock, {"Action": "Logoff"})
        except OSError as exc:
            result["error"] = str(exc)

        result["ok"] = result["loginAccepted"] is True
        return result

    def _read_events(self) -> list[AmiEvent]:
        with self._connect() as sock:
            sock.settimeout(self._settings.timeout_seconds)
            self._read_optional_banner(sock)
            self._login(sock)

            events: list[AmiEvent] = []
            events.extend(
                self._collect_action_events(
                    sock,
                    action="CoreShowChannels",
                    complete_event="CoreShowChannelsComplete",
                )
            )
            events.extend(
                self._collect_optional_action_events(
                    sock,
                    action="PJSIPShowEndpoints",
                    complete_event="EndpointListComplete",
                )
            )
            events.extend(
                self._collect_optional_action_events(
                    sock,
                    action="PJSIPShowContacts",
                    complete_event="ContactListComplete",
                )
            )
            events.extend(
                self._collect_optional_action_events(
                    sock,
                    action="QueueStatus",
                    complete_event="QueueStatusComplete",
                )
            )
            events.extend(
                self._collect_optional_action_events(
                    sock,
                    action="SIPpeers",
                    complete_event="PeerlistComplete",
                )
            )

            self._send_action(sock, {"Action": "Logoff"})
            return events

    def _connect(self) -> socket.socket:
        host = self._ami_host()
        port = self._ami_port()
        try:
            sock = socket.create_connection(
                (host, port),
                timeout=self._settings.timeout_seconds,
            )
            sock.settimeout(self._settings.timeout_seconds)
            return sock
        except TimeoutError as exc:
            raise AmiError(
                f"AMI TCP connect to {host}:{port} timed out"
            ) from exc
        except OSError as exc:
            raise AmiError(
                f"AMI TCP connect to {host}:{port} failed: {exc}"
            ) from exc

    def _ami_host(self) -> str:
        return self._settings.host

    def _ami_port(self) -> int:
        return self._settings.port

    def _ami_username(self) -> str:
        return self._settings.username

    def _ami_password(self) -> str:
        return self._settings.password

    def _login(self, sock: socket.socket) -> dict[str, str]:
        self._send_action(
            sock,
            {
                "Action": "Login",
                "Username": self._ami_username(),
                "Secret": self._ami_password(),
                "Events": "off",
            },
        )
        response = self._read_until_response(sock, phase="AMI login")
        if response.get("Response") != "Success":
            message = response.get("Message", "unknown AMI login error")
            raise AmiError(f"AMI login failed: {message}")
        return response

    def _collect_action_events(
        self,
        sock: socket.socket,
        *,
        action: str,
        complete_event: str,
    ) -> list[AmiEvent]:
        self._send_action(sock, {"Action": action})
        events: list[AmiEvent] = []

        while True:
            packet = self._read_packet(sock, phase=action)
            if not packet:
                continue
            event_name = packet.get("Event", "")
            if event_name == complete_event:
                return events
            if event_name:
                events.append(AmiEvent(name=event_name, fields=packet))

    def _collect_optional_action_events(
        self,
        sock: socket.socket,
        *,
        action: str,
        complete_event: str,
    ) -> list[AmiEvent]:
        try:
            return self._collect_action_events(
                sock,
                action=action,
                complete_event=complete_event,
            )
        except OSError:
            return []

    def _read_until_response(self, sock: socket.socket, *, phase: str) -> dict[str, str]:
        while True:
            packet = self._read_packet(sock, phase=phase)
            if "Response" in packet:
                return packet

    def _send_action(self, sock: socket.socket, fields: dict[str, str]) -> None:
        payload = "".join(f"{key}: {value}\r\n" for key, value in fields.items())
        sock.sendall(f"{payload}\r\n".encode("utf-8"))

    def _read_banner(self, sock: socket.socket) -> str:
        chunks: list[bytes] = []
        try:
            while True:
                chunk = sock.recv(1)
                if not chunk:
                    break
                chunks.append(chunk)
                raw = b"".join(chunks)
                if raw.endswith(b"\n") or raw.endswith(b"\r\n\r\n"):
                    break
        except TimeoutError as exc:
            raise AmiError("AMI banner timed out") from exc

        return b"".join(chunks).decode("utf-8", errors="replace").strip()

    def _read_optional_banner(self, sock: socket.socket) -> tuple[str, str | None]:
        try:
            return self._read_banner(sock), None
        except AmiError as exc:
            return "", str(exc)

    def _read_packet(self, sock: socket.socket, *, phase: str) -> dict[str, str]:
        chunks: list[bytes] = []
        try:
            while True:
                chunk = sock.recv(1)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"".join(chunks).endswith(b"\r\n\r\n"):
                    break
        except TimeoutError as exc:
            raise AmiError(f"{phase} timed out") from exc

        raw = b"".join(chunks).decode("utf-8", errors="replace")
        fields: dict[str, str] = {}
        for line in raw.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
        return fields


def _channels_from_events(events: list[AmiEvent]) -> list[AmiChannel]:
    channels: list[AmiChannel] = []
    for event in events:
        if event.name != "CoreShowChannel":
            continue
        fields = event.fields
        channels.append(
            AmiChannel(
                channel=fields.get("Channel", ""),
                extension=fields.get("Extension", "") or fields.get("Exten", ""),
                caller=fields.get("CallerIDName", "") or fields.get("CallerIDNum", ""),
                connected=fields.get("ConnectedLineName", "")
                or fields.get("ConnectedLineNum", ""),
                state=fields.get("ChannelStateDesc", ""),
                endpoint=_endpoint_from_channel(fields.get("Channel", "")),
                caller_number=fields.get("CallerIDNum", ""),
                connected_number=fields.get("ConnectedLineNum", ""),
                duration=fields.get("Duration", ""),
                unique_id=fields.get("Uniqueid", ""),
                linked_id=fields.get("Linkedid", ""),
            )
        )
    return channels


def _endpoints_from_events(events: list[AmiEvent]) -> list[AmiEndpoint]:
    endpoints: list[AmiEndpoint] = []
    contact_states = _contact_states_from_events(events)
    for event in events:
        if event.name not in {"EndpointList", "PeerEntry"}:
            continue
        fields = event.fields
        extension = (
            fields.get("ObjectName", "")
            or fields.get("Endpoint", "")
            or fields.get("Peer", "")
            or fields.get("PeerName", "")
        )
        if not extension:
            continue
        device_state = (
            _contact_device_state(contact_states.get(extension, []))
            or fields.get("DeviceState", "")
            or fields.get("Contacts", "")
            or fields.get("Status", "")
        )
        if event.name == "PeerEntry":
            device_state = _sip_peer_device_state(fields.get("Status", ""))
        endpoints.append(
            AmiEndpoint(
                extension=extension,
                device_state=device_state,
                active_channels=_parse_int(fields.get("ActiveChannels", "0")),
                label=_first_value(
                    fields,
                    "CallerIDName",
                    "CalleridName",
                    "CallerID",
                    "Description",
                    "DeviceName",
                    "ObjectName",
                ),
                role=_endpoint_role(extension, fields),
                number=_endpoint_number(fields),
                presence=_first_value(
                    fields,
                    "PresenceState",
                    "Presence",
                    "CustomPresence",
                ),
            )
        )
    return endpoints


def _queues_from_events(events: list[AmiEvent]) -> list[AmiQueue]:
    queue_params: dict[str, dict[str, str]] = {}
    entry_counts: dict[str, int] = {}
    longest_waits: dict[str, int] = {}
    member_counts: dict[str, dict[str, int]] = {}

    for event in events:
        fields = event.fields
        queue = fields.get("Queue", "").strip()
        if not queue:
            continue
        if event.name == "QueueParams":
            queue_params[queue] = fields
        elif event.name == "QueueEntry":
            entry_counts[queue] = entry_counts.get(queue, 0) + 1
            longest_waits[queue] = max(
                longest_waits.get(queue, 0),
                _parse_int(fields.get("Wait", "0")),
            )
        elif event.name == "QueueMember":
            counts = member_counts.setdefault(
                queue,
                {"available": 0, "busy": 0, "paused": 0, "total": 0},
            )
            counts["total"] += 1
            if fields.get("Paused", "").strip().lower() in {"1", "yes", "true"}:
                counts["paused"] += 1
            elif _parse_int(fields.get("Status", "0")) == 1:
                counts["available"] += 1
            elif _parse_int(fields.get("Status", "0")) in {2, 3, 6, 7, 8}:
                counts["busy"] += 1

    queue_names = set(queue_params) | set(entry_counts) | set(member_counts)
    queues: list[AmiQueue] = []
    for queue in sorted(queue_names):
        members = member_counts.get(queue, {})
        queues.append(
            AmiQueue(
                name=queue,
                waiting_callers=(
                    entry_counts[queue]
                    if queue in entry_counts
                    else _parse_int(queue_params.get(queue, {}).get("Calls", "0"))
                ),
                longest_wait_seconds=longest_waits.get(queue, 0),
                available_members=members.get("available", 0),
                busy_members=members.get("busy", 0),
                paused_members=members.get("paused", 0),
                total_members=members.get("total", 0),
            )
        )
    return queues


def _sip_peer_device_state(status: str) -> str:
    normalized = status.strip().lower()
    if normalized.startswith("ok") or normalized.startswith("lagged"):
        return "Reachable"
    if any(marker in normalized for marker in ("unreachable", "unknown", "rejected")):
        return "Unreachable"
    return status


def _contact_states_from_events(events: list[AmiEvent]) -> dict[str, list[str]]:
    contacts: dict[str, list[str]] = {}
    for event in events:
        if event.name != "ContactList":
            continue
        fields = event.fields
        endpoint = (
            fields.get("EndpointName", "")
            or fields.get("Endpoint", "")
            or fields.get("AOR", "")
            or fields.get("ObjectName", "")
        ).strip()
        if not endpoint:
            continue
        state = (
            fields.get("Status", "")
            or fields.get("ContactStatus", "")
            or fields.get("UserAgent", "")
        ).strip()
        if state:
            contacts.setdefault(endpoint, []).append(state)
    return contacts


def _contact_device_state(states: list[str]) -> str:
    if not states:
        return ""
    normalized_states = [state.lower() for state in states]
    if any(_contact_state_is_reachable(state) for state in normalized_states):
        return "Reachable"
    if any(_contact_state_is_unreachable(state) for state in normalized_states):
        return "Unreachable"
    return states[0]


def _contact_state_is_reachable(state: str) -> bool:
    return (
        ("reachable" in state and "unreachable" not in state)
        or ("available" in state and "unavailable" not in state)
        or "nonqualified" in state
        or "created" in state
    )


def _contact_state_is_unreachable(state: str) -> bool:
    return "unreachable" in state or "unavailable" in state or "removed" in state


def _parse_int(raw: str) -> int:
    try:
        return int(raw)
    except ValueError:
        return 0


def _first_value(fields: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = fields.get(key, "").strip()
        if value:
            return _clean_label(value)
    return ""


def _endpoint_number(fields: dict[str, str]) -> str:
    for key in (
        "FromUser",
        "CallerIDNum",
        "CallerID",
        "OutboundCallerID",
        "Contact",
        "Contacts",
        "ServerUri",
        "ClientUri",
        "Aor",
        "AOR",
    ):
        number = _number_from_pjsip_value(fields.get(key, ""))
        if number:
            return number
    return ""


def _number_from_pjsip_value(value: str) -> str:
    cleaned = value.strip().strip('"')
    if not cleaned:
        return ""

    uri_match = re.search(r"sips?:([^@>;]+)", cleaned, flags=re.IGNORECASE)
    if uri_match:
        cleaned = uri_match.group(1)
    elif "<" in cleaned:
        cleaned = cleaned.split("<", 1)[0].strip().strip('"')

    caller_id_match = re.search(r"<([^>]+)>", value)
    if caller_id_match:
        nested = _number_from_pjsip_value(caller_id_match.group(1))
        if nested:
            return nested

    cleaned = cleaned.split("@", 1)[0].strip()
    cleaned = re.sub(r"^(tel:|sip:|sips:)", "", cleaned, flags=re.IGNORECASE)
    candidate = re.sub(r"[^0-9+]", "", cleaned)
    digits = re.sub(r"\D", "", candidate)
    if len(digits) >= 3:
        return candidate
    return ""


def _clean_label(value: str) -> str:
    if "<" in value:
        return value.split("<", 1)[0].strip().strip('"')
    return value.strip().strip('"')


def _endpoint_from_channel(channel: str) -> str:
    if "/" not in channel:
        return ""
    endpoint = channel.split("/", 1)[1]
    return endpoint.split("-", 1)[0]


def _endpoint_role(name: str, fields: dict[str, str]) -> str:
    if _looks_like_trunk(name, fields):
        return "trunk"
    return "extension"


def _looks_like_trunk(name: str, fields: dict[str, str]) -> bool:
    normalized = name.strip().lower()
    searchable = " ".join(
        [
            normalized,
            fields.get("Description", ""),
            fields.get("Aor", ""),
            fields.get("Auths", ""),
            fields.get("OutboundAuths", ""),
            fields.get("Transport", ""),
        ]
    ).lower()

    trunk_markers = (
        "trunk",
        "provider",
        "carrier",
        "sipgate",
        "voip",
        "pstn",
        "itsp",
        "cosmote",
        "ote",
        "vodafone",
        "nova",
        "wind",
        "telekom",
        "twilio",
        "flowroute",
        "voipms",
        "voip.ms",
        "didww",
        "telnyx",
        "bandwidth",
        "siptrunk",
    )
    return any(marker in searchable for marker in trunk_markers)
