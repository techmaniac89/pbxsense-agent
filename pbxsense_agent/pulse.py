from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import quote
from zoneinfo import ZoneInfo

from .engine import build_engine_signals
from .history import CdrCall, VoicemailMessage, interpreted_call_kind


@dataclass(frozen=True)
class AmiChannel:
    channel: str
    extension: str
    caller: str
    connected: str
    state: str
    endpoint: str = ""
    caller_number: str = ""
    connected_number: str = ""
    duration: str = ""
    unique_id: str = ""
    linked_id: str = ""


@dataclass(frozen=True)
class AmiEndpoint:
    extension: str
    device_state: str
    active_channels: int = 0
    label: str = ""
    role: str = "extension"
    number: str = ""
    # A PBX-provided presence state, such as DND or Away. This is kept apart
    # from device_state: a phone can be registered while its owner is away.
    presence: str = ""


@dataclass(frozen=True)
class AmiSnapshot:
    reachable: bool
    agent_version: str
    channels: list[AmiChannel] = field(default_factory=list)
    endpoints: list[AmiEndpoint] = field(default_factory=list)
    recent_calls: list[CdrCall] = field(default_factory=list)
    voicemails: list[VoicemailMessage] = field(default_factory=list)
    error: str | None = None


def build_home_payload(
    snapshot: AmiSnapshot,
    *,
    display_name: str,
    extension_names: dict[str, str],
    now: datetime | None = None,
    timezone_name: str = "",
    pbx_type: str = "asterisk",
    pbx_host: str = "",
    pbx_port: int | str = "",
    moment_hours: int = 24,
) -> dict:
    now = now or _now(timezone_name)
    moment_hours = _valid_moment_hours(moment_hours)
    active_channels = [
        channel for channel in snapshot.channels if _is_active_channel(channel)
    ]
    call_channels = _dedupe_call_channels(active_channels)
    endpoint_labels = {
        endpoint.extension: endpoint.label
        for endpoint in snapshot.endpoints
        if endpoint.label
    }
    endpoint_roles = {endpoint.extension: endpoint.role for endpoint in snapshot.endpoints}
    endpoint_numbers = {
        endpoint.extension: endpoint.number
        for endpoint in snapshot.endpoints
        if endpoint.number
    }
    people = _build_people(snapshot.endpoints, active_channels, extension_names)
    trunks = _build_trunks(snapshot.endpoints, extension_names)
    active_calls = [
        _call_from_channel(
            channel,
            extension_names,
            endpoint_labels,
            endpoint_roles,
            endpoint_numbers,
        )
        for channel in call_channels
    ]
    calls = [*active_calls]
    calls.extend(
        _calls_from_history(
            snapshot.recent_calls,
            extension_names,
            endpoint_roles,
            endpoint_numbers,
            now,
        )
    )
    calls.extend(_calls_from_voicemail(snapshot.voicemails, extension_names, now))
    signals = _build_signals(
        snapshot,
        call_channels,
        extension_names,
        endpoint_labels,
        endpoint_roles,
        endpoint_numbers,
        now,
        moment_hours,
    )
    signals.extend(
        build_engine_signals(
            endpoints=snapshot.endpoints,
            recent_calls=snapshot.recent_calls,
            voicemails=snapshot.voicemails,
            extension_names=extension_names,
            now=now,
        )
    )

    current = active_calls[0] if active_calls else _quiet_now(snapshot)
    mood = _mood(snapshot, active_channels, signals)

    return {
        "greeting": _greeting(now),
        "mood": mood,
        "connection": {
            "kind": "local" if snapshot.reachable else "reconnecting",
            "label": "Connected locally" if snapshot.reachable else "Reconnecting",
            "detail": _connection_detail(snapshot, display_name),
            "agentVersion": snapshot.agent_version,
            "lastContact": "Just now" if snapshot.reachable else "Not yet",
            "pbxType": pbx_type,
            "pbxHost": pbx_host,
            "pbxPort": pbx_port,
        },
        "now": current,
        "signals": signals,
        "calls": calls,
        "people": people,
        "trunks": trunks,
    }


def _build_people(
    endpoints: list[AmiEndpoint],
    active_channels: list[AmiChannel],
    extension_names: dict[str, str],
) -> list[dict]:
    talking_extensions = {_person_endpoint(channel) for channel in active_channels}
    talking_extensions.discard("")

    people: list[dict] = []
    for endpoint in sorted(endpoints, key=lambda item: item.extension):
        if endpoint.role == "trunk":
            continue

        name = _extension_name(endpoint.extension, extension_names, endpoint.label)
        presence, presence_label = _person_presence(
            endpoint,
            is_talking=(
                endpoint.extension in talking_extensions
                or endpoint.active_channels > 0
            ),
        )
        if presence == "on_call":
            status = "talking"
            status_text = "On a call"
            detail = "Active now"
        elif presence == "offline":
            status = "unavailable"
            status_text = "Unavailable"
            detail = endpoint.device_state or "Not reachable"
        else:
            status = "online"
            status_text = presence_label
            detail = endpoint.device_state or "Reachable"

        people.append(
            {
                "name": name,
                "extension": endpoint.extension,
                "status": status,
                "statusText": status_text,
                "detail": detail,
                "presence": {
                    "state": presence,
                    "label": presence_label,
                },
            }
        )

    return people


def _person_presence(
    endpoint: AmiEndpoint,
    *,
    is_talking: bool,
) -> tuple[str, str]:
    """Return a stable person-presence state from PBX presence and device data.

    Calls take priority over a stale user-set presence state.  The returned
    state is deliberately connector-neutral so clients do not need to know
    whether the source was AMI, ESL, or a vendor API.
    """
    if is_talking:
        return "on_call", "On a call"
    device_presence = _normalized_presence(endpoint.device_state)
    # Do not let a stale user-set state conceal a phone that is unreachable,
    # ringing, or otherwise actively busy at the PBX right now.
    if device_presence and device_presence[0] in {"offline", "ringing", "busy"}:
        return device_presence
    return _normalized_presence(endpoint.presence) or device_presence or ("unknown", "Unknown")


def _normalized_presence(raw: str) -> tuple[str, str] | None:
    value = raw.strip()
    if not value:
        return None
    normalized = value.lower().replace("_", " ").replace("-", " ")
    if any(marker in normalized for marker in ("unavailable", "unreachable", "offline", "removed")):
        return "offline", "Offline"
    if "do not disturb" in normalized or normalized == "dnd":
        return "do_not_disturb", "Do not disturb"
    if "away" in normalized:
        return "away", "Away"
    if "ringing" in normalized:
        return "ringing", "Ringing"
    if any(marker in normalized for marker in ("busy", "in use", "on hold")):
        return "busy", "Busy"
    if any(
        marker in normalized
        for marker in ("available", "reachable", "registered", "not in use", "idle")
    ):
        return "available", "Available"
    if "unknown" in normalized:
        return "unknown", "Unknown"
    return None


def _build_trunks(
    endpoints: list[AmiEndpoint],
    extension_names: dict[str, str],
) -> list[dict]:
    trunks: list[dict] = []
    for endpoint in sorted(endpoints, key=lambda item: item.extension):
        if endpoint.role != "trunk":
            continue

        name = _trunk_display_name(
            _extension_name(endpoint.extension, extension_names, endpoint.label)
        )
        unavailable = _endpoint_unavailable(endpoint)
        if unavailable:
            status_text = "Needs attention"
            detail = endpoint.device_state or "Not reachable"
        elif endpoint.active_channels > 0:
            status_text = "Working"
            detail = f"Carrying {endpoint.active_channels} active channel(s)"
        else:
            status_text = "Working"
            detail = _registered_trunk_detail(endpoint.device_state)

        trunks.append(
            {
                "name": name,
                "endpoint": endpoint.extension,
                "statusText": status_text,
                "detail": detail,
                "activeChannels": endpoint.active_channels,
                "available": not unavailable,
            }
        )

    return trunks


def _build_signals(
    snapshot: AmiSnapshot,
    active_channels: list[AmiChannel],
    extension_names: dict[str, str],
    endpoint_labels: dict[str, str],
    endpoint_roles: dict[str, str],
    endpoint_numbers: dict[str, str],
    now: datetime,
    moment_hours: int,
) -> list[dict]:
    signals: list[dict] = []

    if not snapshot.reachable:
        return [
            {
                "id": "sig_agent_reconnecting",
                "kind": "agent_reconnecting",
                "category": "health",
                "importance": "important",
                "state": "active",
                "title": "PBXSense Agent is trying to reach the PBX.",
                "body": snapshot.error or "The Agent could not read the PBX yet.",
                "timeLabel": "Just now",
                "actionLabel": None,
                "why": [
                    "The Agent attempted to read the configured PBX connector.",
                    "A successful PBX snapshot has not arrived yet.",
                ],
                "technical": {"error": snapshot.error or "unknown"},
            }
        ]

    active_trunk_endpoints: set[str] = set()
    for channel in active_channels[:5]:
        channel_endpoint = channel.endpoint or channel.extension
        if endpoint_roles.get(channel_endpoint) == "trunk":
            active_trunk_endpoints.add(channel_endpoint)
            trunk_name = _extension_name(
                channel_endpoint,
                extension_names,
                endpoint_labels.get(channel_endpoint, ""),
            )
            trunk_number = endpoint_numbers.get(channel_endpoint, "")
            title = _trunk_call_title(channel, trunk_number)
            signals.append(
                {
                    "id": f"sig_trunk_call_{_safe_id(channel.channel)}",
                    "kind": "trunk_call_active",
                    "category": "activity",
                    "importance": "feed",
                    "state": "active",
                    "title": title,
                    "body": f"Live call through {_trunk_display_name(trunk_name)}.",
                    "timeLabel": "Now",
                    "actionLabel": None,
                    "why": [
                        "The PBX reported an active channel on a trunk endpoint.",
                        "PBXSense classified this endpoint as a trunk, not a phone.",
                    ],
                    "technical": {
                        "channel": channel.channel,
                        "endpoint": channel_endpoint,
                        "caller": _caller_name(channel),
                        "destination": _trunk_call_destination(channel, trunk_number),
                        "trunk_number": trunk_number,
                        "state": channel.state,
                        "role": "trunk",
                    },
                }
            )
            continue

        person_endpoint = _person_endpoint(channel)
        extension_name = _party_name(
            person_endpoint,
            fallback=channel.caller,
            extension_names=extension_names,
            endpoint_labels=endpoint_labels,
        )
        caller = _peer_name(
            channel,
            person_endpoint=person_endpoint,
            extension_names=extension_names,
            endpoint_labels=endpoint_labels,
        )
        signals.append(
            {
                "id": f"sig_active_{_safe_id(channel.channel)}",
                "kind": "call_active",
                "category": "activity",
                "importance": "feed",
                "state": "active",
                "title": f"{extension_name} is talking to {caller}.",
                "body": "A live call is moving through the PBX.",
                "timeLabel": "Now",
                "actionLabel": None,
                "why": [
                    "The PBX reported an active channel.",
                    "PBXSense mapped the channel to an extension.",
                ],
                "technical": {
                    "channel": channel.channel,
                    "extension": person_endpoint or channel.extension,
                    "dialed_extension": channel.extension,
                    "caller_number": channel.caller_number,
                    "connected_number": channel.connected_number,
                    "caller": caller,
                    "state": channel.state,
                },
            }
        )

    for endpoint in snapshot.endpoints:
        if endpoint.role == "trunk":
            if endpoint.extension in active_trunk_endpoints:
                continue
            signals.extend(_trunk_signals(endpoint, extension_names))
            continue

        if _endpoint_unavailable(endpoint):
            name = _extension_name(endpoint.extension, extension_names, endpoint.label)
            signals.append(
                {
                    "id": f"sig_endpoint_{endpoint.extension}_unavailable",
                    "kind": "endpoint_unavailable",
                    "category": "health",
                    "importance": "attention",
                    "state": "active",
                    "title": f"{name} looks unavailable.",
                    "body": "The phone is not currently reachable through the PBX.",
                    "timeLabel": "Just now",
                    "actionLabel": "Open person",
                    "why": [
                        "The PBX reported the endpoint as unavailable.",
                        "PBXSense treats device availability as an office health signal.",
                    ],
                    "technical": {
                        "extension": endpoint.extension,
                        "device_state": endpoint.device_state,
                    },
                }
            )

    signals.extend(_moment_signals(snapshot, active_channels, now, moment_hours))

    return signals


def _moment_signals(
    snapshot: AmiSnapshot,
    active_channels: list[AmiChannel],
    now: datetime,
    moment_hours: int,
) -> list[dict]:
    recent_calls = _calls_in_window(snapshot.recent_calls, now, moment_hours)
    signal_id = f"sig_moment_{now.date().isoformat()}_{moment_hours}h"
    window_label = _moment_window_label(moment_hours)

    if active_channels:
        active_count = len(_dedupe_call_channels(active_channels))
        return [
            {
                "id": signal_id,
                "kind": "pbx_active_moment",
                "category": "moment",
                "importance": "feed",
                "state": "active",
                "title": "Calls are moving right now.",
                "body": "PBXSense sees live call activity and is keeping the moment visible.",
                "timeLabel": "Now",
                "actionLabel": None,
                "why": [
                    "The PBX connector reported at least one active channel.",
                    "Moments summarize what the PBX feels like without asking for action.",
                ],
                "technical": {
                    "active_calls": str(active_count),
                    "visible_window": window_label,
                },
            }
        ]

    moment = _daily_behavior_moment(
        snapshot.recent_calls,
        recent_calls,
        now,
        moment_hours,
    )
    return [
        {
            "id": signal_id,
            "kind": moment["kind"],
            "category": "moment",
            "importance": "feed",
            "state": "active",
            "title": moment["title"],
            "body": moment["body"],
            "timeLabel": _moment_time_label(moment_hours),
            "actionLabel": None,
            "why": [
                "The PBX connector responded successfully.",
                moment["why"],
                "PBXSense chooses one useful daily Moment so the feed feels alive without becoming noisy.",
            ],
            "technical": {
                **moment["technical"],
                "visible_window": window_label,
                "moment_pool": moment["pool"],
            },
        }
    ]


def _daily_behavior_moment(
    all_calls: list[CdrCall],
    recent_calls: list[CdrCall],
    now: datetime,
    moment_hours: int,
) -> dict:
    recent_answered = _history_kind_count(recent_calls, "answered")
    recent_missed = _history_kind_count(recent_calls, "missed")
    recent_ivr_reached = _history_kind_count(recent_calls, "ivr_reached")
    previous_window_calls = _calls_between(
        all_calls,
        now.replace(tzinfo=None) - timedelta(hours=moment_hours * 2),
        now.replace(tzinfo=None) - timedelta(hours=moment_hours),
    )
    window_label = _moment_window_label(moment_hours)
    busiest_hour = _busiest_hour_label(recent_calls)
    pool: list[dict] = []

    if recent_calls:
        call_word = "call" if len(recent_calls) == 1 else "calls"
        pool.append(
            {
                "kind": "pbx_daily_flow_moment",
                "title": f"{len(recent_calls)} {call_word} passed through in the {window_label}.",
                "body": "PBXSense sees the day's call flow and is keeping a calm eye on it.",
                "why": f"PBXSense counted recent call history inside the {window_label}.",
            }
        )

    if recent_answered > 0 and recent_missed == 0:
        pool.append(
            {
                "kind": "pbx_answered_cleanly_moment",
                "title": "Recent calls are being answered cleanly.",
                "body": f"PBXSense found answered calls without missed-call pressure in the {window_label}.",
                "why": "Recent call history has answered calls and no missed calls.",
            }
        )

    if recent_missed > recent_answered and recent_missed > 0:
        pool.append(
            {
                "kind": "pbx_missed_weight_moment",
                "title": "Missed calls shaped the day more than answered calls.",
                "body": f"PBXSense noticed the {window_label} leaned toward calls that did not connect.",
                "why": "Missed calls outnumbered answered calls in recent history.",
            }
        )

    if busiest_hour is not None:
        hour, count = busiest_hour
        pool.append(
            {
                "kind": "pbx_busy_hour_moment",
                "title": f"Calls clustered around {hour}.",
                "body": f"{count} call(s) landed in that hour during the {window_label}.",
                "why": "PBXSense grouped recent calls by hour and found the busiest one.",
            }
        )

    if previous_window_calls:
        if len(recent_calls) >= max(3, len(previous_window_calls) * 1.5):
            pool.append(
                {
                    "kind": "pbx_busier_than_previous_window_moment",
                    "title": "The PBX is busier than the previous window.",
                    "body": f"The {window_label} has more visible call flow than the window before it.",
                    "why": f"PBXSense compared the {window_label} with the same period before it.",
                }
            )
        elif len(recent_calls) <= max(1, len(previous_window_calls) * 0.45):
            pool.append(
                {
                    "kind": "pbx_quieter_than_previous_window_moment",
                    "title": "The PBX is quieter than the previous window.",
                    "body": f"The {window_label} has less visible call flow than the window before it.",
                    "why": f"PBXSense compared the {window_label} with the same period before it.",
                }
            )

    if not pool:
        calm_pool = [
            {
                "kind": "pbx_reachable_moment",
                "title": "The PBX is reachable right now.",
                "body": "PBXSense is connected and waiting for something meaningful to happen.",
                "why": "No live call or recent call history needed attention.",
            },
            {
                "kind": "pbx_calm_day_moment",
                "title": "The PBX has had a quiet day so far.",
                "body": "PBXSense can reach the PBX, but recent call history is calm.",
                "why": "The PBX is reachable and no recent call history was visible.",
            },
            {
                "kind": "pbx_ready_moment",
                "title": "The PBX is ready and waiting.",
                "body": "PBXSense is connected and will surface activity when the day starts moving.",
                "why": "The PBX connector responded and no active calls were present.",
            },
        ]
        pool = calm_pool

    selected = pool[now.toordinal() % len(pool)]
    selected["technical"] = {
        "recent_calls": str(len(recent_calls)),
        "previous_window_calls": str(len(previous_window_calls)),
        "answered_calls": str(recent_answered),
        "missed_calls": str(recent_missed),
        "ivr_reached_calls": str(recent_ivr_reached),
        "moment_hours": str(moment_hours),
    }
    selected["pool"] = ",".join(item["kind"] for item in pool)
    return selected


def _calls_in_window(
    calls: list[CdrCall],
    now: datetime,
    hours: int,
) -> list[CdrCall]:
    window_start = now.replace(tzinfo=None) - timedelta(hours=hours)
    window_end = now.replace(tzinfo=None)
    return _calls_between(calls, window_start, window_end)


def _valid_moment_hours(hours: int) -> int:
    return hours if hours in {1, 3, 6, 12, 24} else 24


def _moment_window_label(hours: int) -> str:
    return f"last {hours} hours"


def _moment_time_label(hours: int) -> str:
    return f"Last {hours} hours"


def _calls_between(
    calls: list[CdrCall],
    window_start: datetime,
    window_end: datetime,
) -> list[CdrCall]:
    return [
        call
        for call in calls
        if call.started_at is not None
        and window_start <= call.started_at.replace(tzinfo=None) < window_end
    ]


def _history_kind_count(calls: list[CdrCall], kind: str) -> int:
    return sum(1 for call in calls if interpreted_call_kind(call) == kind)


def _busiest_hour_label(calls: list[CdrCall]) -> tuple[str, int] | None:
    counts: dict[int, int] = {}
    for call in calls:
        if call.started_at is None:
            continue
        hour = call.started_at.hour
        counts[hour] = counts.get(hour, 0) + 1

    if not counts:
        return None

    hour, count = max(counts.items(), key=lambda item: (item[1], -item[0]))
    if count < 2:
        return None

    return f"{hour:02d}:00", count


def _trunk_signals(
    endpoint: AmiEndpoint,
    extension_names: dict[str, str],
) -> list[dict]:
    name = _extension_name(endpoint.extension, extension_names, endpoint.label)
    if _endpoint_unavailable(endpoint):
        return [
            {
                "id": f"sig_trunk_{endpoint.extension}_unavailable",
                "kind": "trunk_unavailable",
                "category": "health",
                "importance": "important",
                "state": "active",
                "title": f"{_trunk_display_name(name)} looks unavailable.",
                "body": "Incoming or outgoing calls through this trunk may be affected.",
                "timeLabel": "Just now",
                "actionLabel": None,
                "why": [
                    "The PBX reported a trunk-like endpoint as unavailable.",
                    "PBXSense monitors trunks separately from phones and extensions.",
                ],
                "technical": {
                    "endpoint": endpoint.extension,
                    "device_state": endpoint.device_state,
                    "active_channels": str(endpoint.active_channels),
                    "role": "trunk",
                },
            }
        ]

    if endpoint.active_channels > 0:
        return [
            {
                "id": f"sig_trunk_{endpoint.extension}_active",
                "kind": "trunk_active",
                "category": "activity",
                "importance": "feed",
                "state": "active",
                "title": f"{_trunk_display_name(name)} is carrying calls.",
                "body": f"{endpoint.active_channels} active channel(s) are using this trunk.",
                "timeLabel": "Now",
                "actionLabel": None,
                "why": [
                    "The PBX reported active channels on a trunk-like endpoint.",
                    "PBXSense treats trunk traffic as PBX activity, not a person status.",
                ],
                "technical": {
                    "endpoint": endpoint.extension,
                    "device_state": endpoint.device_state,
                    "active_channels": str(endpoint.active_channels),
                    "role": "trunk",
                },
            }
        ]

    return []


def _call_from_channel(
    channel: AmiChannel,
    extension_names: dict[str, str],
    endpoint_labels: dict[str, str],
    endpoint_roles: dict[str, str],
    endpoint_numbers: dict[str, str],
) -> dict:
    channel_endpoint = channel.endpoint or channel.extension
    if endpoint_roles.get(channel_endpoint) == "trunk":
        trunk_name = _extension_name(
            channel_endpoint,
            extension_names,
            endpoint_labels.get(channel_endpoint, ""),
        )
        trunk_number = endpoint_numbers.get(channel_endpoint, "")
        return {
            "title": _trunk_call_title(channel, trunk_number),
            "body": f"Live call through {_trunk_display_name(trunk_name)}.",
            "timeLabel": "Active now",
            "isActive": True,
            "kind": "active",
        }

    person_endpoint = _person_endpoint(channel)
    extension_name = _party_name(
        person_endpoint,
        fallback=channel.caller,
        extension_names=extension_names,
        endpoint_labels=endpoint_labels,
    )
    caller = _peer_name(
        channel,
        person_endpoint=person_endpoint,
        extension_names=extension_names,
        endpoint_labels=endpoint_labels,
    )
    return {
        "title": f"{extension_name} is talking to {caller}.",
        "body": "Live call from the PBX.",
        "timeLabel": "Active now",
        "isActive": True,
        "kind": "active",
    }


def _calls_from_history(
    recent_calls: list[CdrCall],
    extension_names: dict[str, str],
    endpoint_roles: dict[str, str],
    endpoint_numbers: dict[str, str],
    now: datetime,
) -> list[dict]:
    calls: list[dict] = []
    for record in recent_calls:
        source = _extension_name(record.source, extension_names)
        destination = _history_destination_name(
            record,
            extension_names,
            endpoint_roles,
            endpoint_numbers,
        )
        interpreted_kind = interpreted_call_kind(record)
        if interpreted_kind == "answered":
            kind = "answered"
            title = f"{source} called {destination}."
            body = _duration_body(record.duration_seconds)
        elif interpreted_kind == "ivr_reached":
            kind = "ivr_reached"
            title = f"{source} reached the IVR."
            body = "The call reached the PBX menu."
        elif interpreted_kind == "missed":
            kind = "missed"
            title = f"{source} missed {destination}."
            body = "The call did not connect."
        else:
            continue

        call = {
                "title": title,
                "body": body,
                "timeLabel": _time_label(record.started_at, now),
                "isActive": False,
                "kind": kind,
        }
        if record.recording_id:
            call["recording"] = {
                "available": True,
                "id": record.recording_id,
                "url": f"/recordings/{quote(record.recording_id, safe='')}",
            }
        calls.append(call)
    return calls


def _history_destination_name(
    record: CdrCall,
    extension_names: dict[str, str],
    endpoint_roles: dict[str, str],
    endpoint_numbers: dict[str, str],
) -> str:
    raw_destination = record.destination.strip()
    if _looks_like_callable_number(raw_destination):
        return _extension_name(raw_destination, extension_names)

    trunk_endpoint = _history_trunk_endpoint(record, endpoint_roles)
    trunk_number = endpoint_numbers.get(trunk_endpoint, "")
    if trunk_number:
        return trunk_number

    return _extension_name(raw_destination, extension_names)


def _history_trunk_endpoint(
    record: CdrCall,
    endpoint_roles: dict[str, str],
) -> str:
    for channel in (record.channel, record.destination_channel):
        endpoint = _endpoint_from_channel(channel)
        if endpoint_roles.get(endpoint) == "trunk":
            return endpoint
    return ""


def _calls_from_voicemail(
    voicemails: list[VoicemailMessage],
    extension_names: dict[str, str],
    now: datetime,
) -> list[dict]:
    calls: list[dict] = []
    for message in voicemails:
        mailbox = _extension_name(message.mailbox, extension_names)
        calls.append(
            {
                "title": f"{message.caller} left {mailbox} a voicemail.",
                "body": "A voicemail is available.",
                "timeLabel": _time_label(message.created_at, now),
                "isActive": False,
                "kind": "voicemail",
            }
        )
    return calls


def _duration_body(duration_seconds: int) -> str:
    if duration_seconds <= 0:
        return "The call connected."
    minutes, seconds = divmod(duration_seconds, 60)
    if minutes <= 0:
        return f"The call lasted {seconds} seconds."
    if seconds == 0:
        return f"The call lasted {minutes} minute{'s' if minutes != 1 else ''}."
    return f"The call lasted {minutes} minute{'s' if minutes != 1 else ''} {seconds} seconds."


def _time_label(value: datetime | None, now: datetime) -> str:
    if value is None:
        return "Earlier"
    now = now.replace(tzinfo=None)
    if value.date() == now.date():
        return value.strftime("Today, %H:%M")
    return value.strftime("%d %b, %H:%M")


def _now(timezone_name: str) -> datetime:
    if timezone_name:
        try:
            return datetime.now(ZoneInfo(timezone_name))
        except Exception:
            pass
    return datetime.now()


def _extension_name(
    extension: str,
    extension_names: dict[str, str],
    observed_label: str = "",
) -> str:
    if observed_label and not _looks_like_extension(observed_label, extension):
        return observed_label
    return extension_names.get(extension, extension)


def _trunk_display_name(name: str) -> str:
    return name if "trunk" in name.lower() else f"SIP trunk {name}"


def _looks_like_extension(value: str, extension: str) -> bool:
    normalized = value.strip().lower()
    if not extension.strip().isdigit() and normalized == extension.strip().lower():
        return False

    return normalized in {
        "",
        extension.strip().lower(),
        f"pjsip/{extension}".lower(),
        f"sip/{extension}".lower(),
    }


def _quiet_now(snapshot: AmiSnapshot) -> dict:
    if snapshot.reachable:
        return {
            "title": "The office is quiet.",
            "body": "The PBX is reachable.",
            "timeLabel": "Now",
            "isActive": False,
            "kind": "answered",
        }

    return {
        "title": "Waiting for the PBX.",
        "body": snapshot.error or "The Agent is reconnecting.",
        "timeLabel": "Now",
        "isActive": False,
        "kind": "missed",
    }


def _mood(
    snapshot: AmiSnapshot,
    active_channels: list[AmiChannel],
    signals: list[dict],
) -> str:
    if not snapshot.reachable:
        return "PBXSense is trying to reach the PBX."
    if any(signal["importance"] in {"attention", "important"} for signal in signals):
        return "There is something worth watching."
    if active_channels:
        return "Calls are moving."
    return "Everything looks healthy."


def _dedupe_call_channels(channels: list[AmiChannel]) -> list[AmiChannel]:
    groups: dict[str, list[AmiChannel]] = {}
    order: list[str] = []
    for channel in channels:
        key = _call_group_key(channel)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(channel)

    return [_preferred_call_channel(groups[key]) for key in order]


def _call_group_key(channel: AmiChannel) -> str:
    if channel.linked_id:
        return f"linked:{channel.linked_id}"
    parties = _call_party_key(channel)
    if len(parties) > 1:
        return "parties:" + "|".join(sorted(parties))
    return f"channel:{channel.channel}"


def _preferred_call_channel(channels: list[AmiChannel]) -> AmiChannel:
    for channel in channels:
        if channel.caller_number and _person_endpoint(channel) == channel.caller_number:
            return channel
    for channel in channels:
        if channel.caller and _clean_unknown(channel.caller):
            return channel
    return channels[0]


def _call_party_key(channel: AmiChannel) -> frozenset[str]:
    person = _person_endpoint(channel)
    peer = _peer_endpoint(channel, person)
    return frozenset(party for party in (person, peer) if party)


def _peer_endpoint(channel: AmiChannel, person_endpoint: str) -> str:
    for candidate in (
        channel.connected_number,
        channel.extension,
        channel.caller_number,
    ):
        if candidate and candidate != person_endpoint:
            return candidate
    return ""


def _connection_detail(snapshot: AmiSnapshot, display_name: str) -> str:
    if snapshot.reachable:
        return f"{display_name} answered the Agent snapshot request."
    return snapshot.error or "The Agent has not connected to the PBX yet."


def _greeting(now: datetime) -> str:
    if 5 <= now.hour < 12:
        return "Good morning"
    if 12 <= now.hour < 18:
        return "Good afternoon"
    return "Good evening"


def _is_active_channel(channel: AmiChannel) -> bool:
    state = channel.state.lower()
    return state in {"up", "ring", "ringing"} or bool(channel.connected)


def _endpoint_unavailable(endpoint: AmiEndpoint) -> bool:
    state = endpoint.device_state.lower()
    return "unavailable" in state or "unreachable" in state


def _registered_trunk_detail(device_state: str) -> str:
    state = device_state.strip()
    if not state:
        return "Registered and ready"
    if any(marker in state.lower() for marker in ("registered", "reachable", "available", "ok")):
        return "Registered and ready"
    return state


def _caller_name(channel: AmiChannel) -> str:
    return channel.caller or channel.connected or "a caller"


def _trunk_call_title(channel: AmiChannel, trunk_number: str = "") -> str:
    caller = _trunk_call_caller(channel)
    destination = _trunk_call_destination(channel, trunk_number)
    if destination:
        return f"{caller} is calling {destination}."
    return f"{caller} is using the SIP trunk."


def _trunk_call_caller(channel: AmiChannel) -> str:
    return (
        _clean_unknown(channel.caller_number)
        or _clean_unknown(channel.caller)
        or _clean_unknown(channel.connected)
        or "A caller"
    )


def _trunk_call_destination(channel: AmiChannel, trunk_number: str = "") -> str:
    trunk_endpoint = channel.endpoint or _endpoint_from_channel(channel.channel)
    for candidate in (
        channel.connected_number,
        channel.extension,
        channel.connected,
    ):
        cleaned = _clean_unknown(candidate)
        if (
            cleaned
            and cleaned != trunk_endpoint
            and _looks_like_callable_number(cleaned)
        ):
            return cleaned
    cleaned_trunk_number = _clean_unknown(trunk_number)
    if cleaned_trunk_number:
        return cleaned_trunk_number
    return ""


def _looks_like_callable_number(value: str) -> bool:
    stripped = value.strip()
    digits = "".join(character for character in stripped if character.isdigit())
    if not digits:
        return False
    if stripped.lower() in {"s", "i", "t", "h", "e", "fax"}:
        return False
    return len(digits) >= 3 or stripped.startswith("+")


def _person_endpoint(channel: AmiChannel) -> str:
    return channel.endpoint or _endpoint_from_channel(channel.channel) or channel.extension


def _endpoint_from_channel(channel: str) -> str:
    if "/" not in channel:
        return ""
    endpoint = channel.split("/", 1)[1]
    return endpoint.split("-", 1)[0]


def _peer_name(
    channel: AmiChannel,
    *,
    person_endpoint: str,
    extension_names: dict[str, str],
    endpoint_labels: dict[str, str],
) -> str:
    candidates = [
        channel.connected_number,
        channel.extension,
        channel.caller_number,
    ]
    for candidate in candidates:
        if candidate and candidate != person_endpoint:
            return _party_name(
                candidate,
                fallback=channel.connected or channel.caller,
                extension_names=extension_names,
                endpoint_labels=endpoint_labels,
            )

    person_name = _party_name(
        person_endpoint,
        fallback="",
        extension_names=extension_names,
        endpoint_labels=endpoint_labels,
    )
    for fallback in [channel.connected, channel.caller]:
        cleaned = _clean_unknown(fallback)
        if cleaned and cleaned != person_name:
            return cleaned

    return "a caller"


def _party_name(
    extension: str,
    *,
    fallback: str,
    extension_names: dict[str, str],
    endpoint_labels: dict[str, str],
) -> str:
    if extension:
        observed_label = endpoint_labels.get(extension, "")
        manual_name = extension_names.get(extension, "")
        if observed_label or manual_name:
            return _extension_name(extension, extension_names, observed_label)
        return extension
    return _clean_unknown(fallback) or "a caller"


def _clean_unknown(value: str) -> str:
    cleaned = value.strip()
    if cleaned.lower() in {"", "<unknown>", "unknown"}:
        return ""
    return cleaned


def _safe_id(raw: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in raw).strip("_").lower()
