from __future__ import annotations

from collections import Counter
from datetime import datetime
import re
from typing import Any

from .history import CdrCall, SecurityEvent, VoicemailMessage, interpreted_call_kind


def build_engine_signals(
    *,
    endpoints: list[Any],
    recent_calls: list[CdrCall],
    voicemails: list[VoicemailMessage],
    security_events: list[SecurityEvent],
    extension_names: dict[str, str],
    now: datetime,
) -> list[dict]:
    signals: list[dict] = []
    signals.extend(
        _missed_call_recommendations(endpoints, recent_calls, extension_names, now)
    )
    signals.extend(_call_mix_insights(recent_calls, voicemails, now))
    signals.extend(_rhythm_insights(recent_calls, now))
    signals.extend(_missed_rate_recommendations(recent_calls, now))
    signals.extend(_endpoint_recommendations(endpoints, extension_names))
    signals.extend(_security_signals(recent_calls, security_events, now))
    return signals


def _missed_call_recommendations(
    endpoints: list[Any],
    recent_calls: list[CdrCall],
    extension_names: dict[str, str],
    now: datetime,
) -> list[dict]:
    endpoint_labels = _person_endpoint_labels(endpoints)
    by_destination: dict[str, set[tuple[str, str]]] = {}
    for call in recent_calls:
        if interpreted_call_kind(call) != "missed":
            continue
        attempt_key = _call_attempt_key(call)
        for destination in _missed_call_targets(call, endpoint_labels):
            by_destination.setdefault(destination, set()).add(attempt_key)
    signals: list[dict] = []

    ranked_destinations = sorted(
        by_destination.items(),
        key=lambda item: len(item[1]),
        reverse=True,
    )
    for destination, attempts in ranked_destinations[:3]:
        count = len(attempts)
        if count < 2:
            continue
        name = _extension_name(
            destination,
            extension_names,
            endpoint_labels.get(destination, ""),
        )
        signals.append(
            {
                "id": f"sig_tip_missed_{_safe_id(destination)}",
                "kind": "missed_call_pattern",
                "category": "recommendation",
                "importance": "attention",
                "state": "active",
                "title": f"{name} missed {count} recent calls.",
                "body": "It may be worth checking coverage for this phone.",
                "timeLabel": "Today",
                "actionLabel": None,
                "why": [
                    f"PBXSense found {count} recent calls that did not connect.",
                    "The calls point to the same destination.",
                ],
                "technical": {
                    "extension": destination,
                    "missed_calls": str(count),
                    "window": _history_window(recent_calls, now),
                },
            }
        )

    return signals


def _call_mix_insights(
    recent_calls: list[CdrCall],
    voicemails: list[VoicemailMessage],
    now: datetime,
) -> list[dict]:
    if not recent_calls and not voicemails:
        return []

    answered = sum(
        1 for call in recent_calls if interpreted_call_kind(call) == "answered"
    )
    missed = _missed_count(recent_calls)
    ivr_reached = sum(
        1 for call in recent_calls if interpreted_call_kind(call) == "ivr_reached"
    )
    voicemail_count = len(voicemails)
    total = answered + missed + ivr_reached + voicemail_count
    if total == 0:
        return []

    if answered == 0 and missed == 0 and ivr_reached > 0 and voicemail_count == 0:
        title = "Recent callers reached the IVR."
        body = "PBXSense saw callers reach the PBX menu without human missed-call pressure."
    elif missed == 0 and voicemail_count == 0:
        title = "Recent calls are being handled cleanly."
        body = "PBXSense did not find missed calls or voicemail pressure in the latest history."
    elif missed > answered:
        title = "Missed calls are higher than answered calls."
        body = "Recent call history may deserve a quick look."
    elif voicemail_count > 0:
        title = "Voicemail is part of today's call flow."
        body = "PBXSense found recent voicemail activity alongside call history."
    else:
        title = "Recent call flow looks balanced."
        body = "Answered and missed calls are both visible, without a strong pattern yet."

    return [
        {
            "id": "sig_insight_call_mix",
            "kind": "call_mix_insight",
            "category": "insight",
            "importance": "feed",
            "state": "active",
            "title": title,
            "body": body,
            "timeLabel": "Today",
            "actionLabel": None,
            "why": [
                "PBXSense compared answered calls, missed calls, and voicemail activity.",
                "This is derived from recent call history visible to the Agent.",
            ],
            "technical": {
                "answered_calls": str(answered),
                "missed_calls": str(missed),
                "ivr_reached_calls": str(ivr_reached),
                "voicemails": str(voicemail_count),
                "comparison_window": _history_window(recent_calls, now),
            },
        }
    ]


def _rhythm_insights(recent_calls: list[CdrCall], now: datetime) -> list[dict]:
    dated_calls = _dated_calls(recent_calls)
    if len(dated_calls) < 20 or _history_days(dated_calls) < 7:
        return []

    today = now.date()
    today_calls = [call for call in dated_calls if call.started_at.date() == today]
    if not today_calls:
        return []

    same_weekday_counts = _same_weekday_counts(dated_calls, now)
    if len(same_weekday_counts) < 2:
        return []

    baseline = sum(same_weekday_counts) / len(same_weekday_counts)
    today_count = len(today_calls)
    signals: list[dict] = []

    if today_count >= max(6, baseline * 1.5):
        signals.append(
            {
                "id": "sig_insight_weekday_busier",
                "kind": "weekday_volume_pattern",
                "category": "insight",
                "importance": "feed",
                "state": "active",
                "title": "Today is busier than this weekday usually is.",
                "body": "PBXSense compared today with recent matching weekdays.",
                "timeLabel": "Today",
                "actionLabel": None,
                "why": [
                    f"Today has {today_count} visible call(s).",
                    f"Recent matching weekdays average about {baseline:.1f} call(s).",
                ],
                "technical": {
                    "today_calls": str(today_count),
                    "weekday_average": f"{baseline:.1f}",
                    "comparison_window": f"{len(same_weekday_counts)} matching weekdays",
                },
            }
        )
    elif today_count <= max(1, baseline * 0.45) and baseline >= 5:
        signals.append(
            {
                "id": "sig_insight_weekday_quieter",
                "kind": "weekday_volume_pattern",
                "category": "insight",
                "importance": "feed",
                "state": "active",
                "title": "Today is quieter than this weekday usually is.",
                "body": "PBXSense compared today with recent matching weekdays.",
                "timeLabel": "Today",
                "actionLabel": None,
                "why": [
                    f"Today has {today_count} visible call(s).",
                    f"Recent matching weekdays average about {baseline:.1f} call(s).",
                ],
                "technical": {
                    "today_calls": str(today_count),
                    "weekday_average": f"{baseline:.1f}",
                    "comparison_window": f"{len(same_weekday_counts)} matching weekdays",
                },
            }
        )

    busiest_hour = _busiest_hour(dated_calls)
    if busiest_hour is not None:
        hour, count = busiest_hour
        signals.append(
            {
                "id": "sig_insight_busiest_hour",
                "kind": "busy_hour_pattern",
                "category": "insight",
                "importance": "feed",
                "state": "active",
                "title": f"Calls tend to cluster around {hour:02d}:00.",
                "body": "This is the busiest hour in the visible call history.",
                "timeLabel": "This month",
                "actionLabel": None,
                "why": [
                    f"PBXSense found {count} call(s) around {hour:02d}:00.",
                    "This came from the local call history visible to the Agent.",
                ],
                "technical": {
                    "hour": f"{hour:02d}:00",
                    "calls_in_hour": str(count),
                    "comparison_window": f"{_history_days(dated_calls)} days",
                },
            }
        )

    return signals[:2]


def _missed_rate_recommendations(recent_calls: list[CdrCall], now: datetime) -> list[dict]:
    dated_calls = _dated_calls(recent_calls)
    if len(dated_calls) < 20 or _history_days(dated_calls) < 7:
        return []

    today = now.date()
    today_calls = [call for call in dated_calls if call.started_at.date() == today]
    previous_calls = [call for call in dated_calls if call.started_at.date() != today]
    if len(today_calls) < 5 or len(previous_calls) < 10:
        return []

    today_missed = _missed_count(today_calls)
    previous_missed = _missed_count(previous_calls)
    today_rate = today_missed / len(today_calls)
    baseline_rate = previous_missed / len(previous_calls)

    if today_missed < 3 or today_rate < baseline_rate + 0.2:
        return []

    return [
        {
            "id": "sig_tip_missed_rate_higher_today",
            "kind": "missed_rate_pattern",
            "category": "recommendation",
            "importance": "attention",
            "state": "active",
            "title": "Missed calls are higher than usual today.",
            "body": "It may be worth checking coverage before the day gets busier.",
            "timeLabel": "Today",
            "actionLabel": None,
            "why": [
                f"Today missed-call rate is {_percent(today_rate)}.",
                f"The recent baseline is about {_percent(baseline_rate)}.",
            ],
            "technical": {
                "today_calls": str(len(today_calls)),
                "today_missed_calls": str(today_missed),
                "today_missed_rate": _percent(today_rate),
                "baseline_missed_rate": _percent(baseline_rate),
                "comparison_window": f"{_history_days(previous_calls)} prior days",
            },
        }
    ]


def _endpoint_recommendations(
    endpoints: list[Any],
    extension_names: dict[str, str],
) -> list[dict]:
    unavailable = [
        endpoint
        for endpoint in endpoints
        if endpoint.role != "trunk" and _endpoint_unavailable(endpoint)
    ]
    if len(unavailable) < 2:
        return []

    names = [_extension_name(endpoint.extension, extension_names, endpoint.label) for endpoint in unavailable]
    return [
        {
            "id": "sig_tip_multiple_endpoints_unavailable",
            "kind": "endpoint_unavailable_pattern",
            "category": "recommendation",
            "importance": "attention",
            "state": "active",
            "title": f"{len(unavailable)} phones look unavailable.",
            "body": "This may be a network, power, or registration issue rather than one phone.",
            "timeLabel": "Just now",
            "actionLabel": None,
            "why": [
                "AMI reported more than one extension as unavailable.",
                "PBXSense groups related endpoint trouble before suggesting action.",
            ],
            "technical": {
                "extensions": ", ".join(endpoint.extension for endpoint in unavailable),
                "phones": ", ".join(names),
                "unavailable_count": str(len(unavailable)),
            },
        }
    ]


def _person_endpoint_labels(endpoints: list[Any]) -> dict[str, str]:
    return {
        endpoint.extension: endpoint.label
        for endpoint in endpoints
        if endpoint.role != "trunk" and endpoint.extension
    }


def _missed_call_targets(call: CdrCall, endpoint_labels: dict[str, str]) -> list[str]:
    targets: list[str] = []

    if call.destination in endpoint_labels:
        targets.append(call.destination)

    targets.extend(_channel_targets(call.destination_channel, endpoint_labels))
    targets.extend(_dial_targets(call.last_data, endpoint_labels))

    seen: set[str] = set()
    unique: list[str] = []
    for target in targets:
        if target in seen:
            continue
        seen.add(target)
        unique.append(target)
    return unique


def _channel_targets(value: str, endpoint_labels: dict[str, str]) -> list[str]:
    endpoint = _endpoint_from_channel(value)
    if endpoint and endpoint in endpoint_labels:
        return [endpoint]
    return []


def _dial_targets(value: str, endpoint_labels: dict[str, str]) -> list[str]:
    targets: list[str] = []
    for match in re.finditer(r"(?:PJSIP|SIP|IAX2|DAHDI)/([^,&|/)-]+)", value):
        endpoint = match.group(1).strip()
        if endpoint in endpoint_labels:
            targets.append(endpoint)
    return targets


def _endpoint_from_channel(value: str) -> str:
    if "/" not in value:
        return ""
    endpoint = value.split("/", 1)[1]
    return endpoint.split("-", 1)[0]


def _security_signals(
    recent_calls: list[CdrCall],
    security_events: list[SecurityEvent],
    now: datetime,
) -> list[dict]:
    signals: list[dict] = []
    failed_calls = [
        call
        for call in recent_calls
        if call.disposition.upper() in {"FAILED", "CONGESTION"}
    ]
    if len(failed_calls) >= 3:
        signals.append(
            {
                "id": "sig_security_failed_call_cluster",
                "kind": "failed_call_cluster",
                "category": "security",
                "importance": "attention",
                "state": "active",
                "title": "Several calls failed close together.",
                "body": "PBXSense grouped repeated failed call attempts for review.",
                "timeLabel": "Today",
                "actionLabel": None,
                "why": [
                    f"PBXSense found {len(failed_calls)} failed or congested recent calls.",
                    "Repeated failures can point to routing, trunk, or unwanted call attempts.",
                ],
                "technical": {
                    "attempts": str(len(failed_calls)),
                    "window": _history_window(recent_calls, now),
                    "sources": ", ".join(sorted({call.source for call in failed_calls if call.source})[:5]),
                },
            }
        )

    authentication_events = [
        event
        for event in security_events
        if event.kind in {"InvalidAccountID", "InvalidPassword", "ChallengeResponseFailed"}
    ]
    if len(authentication_events) >= 3:
        services = ", ".join(sorted({event.service for event in authentication_events})[:3])
        signals.append(
            {
                "id": "sig_security_authentication_failures",
                "kind": "authentication_failure_cluster",
                "category": "security",
                "importance": "attention",
                "state": "active",
                "title": "Several PBX login attempts were rejected.",
                "body": "PBXSense grouped recent failed authentication events for review.",
                "timeLabel": "Recent",
                "actionLabel": None,
                "why": [
                    f"PBXSense found {len(authentication_events)} recent rejected authentication events.",
                    "The Agent keeps only aggregate security evidence, not account names or addresses.",
                ],
                "technical": {
                    "attempts": str(len(authentication_events)),
                    "services": services or "PBX",
                    "window": "15 minutes",
                },
            }
        )

    acl_events = [event for event in security_events if event.kind == "FailedACL"]
    if len(acl_events) >= 2:
        services = ", ".join(sorted({event.service for event in acl_events})[:3])
        signals.append(
            {
                "id": "sig_security_acl_failures",
                "kind": "acl_failure_cluster",
                "category": "security",
                "importance": "attention",
                "state": "active",
                "title": "Repeated PBX access attempts were blocked.",
                "body": "PBXSense grouped recent access-control failures for review.",
                "timeLabel": "Recent",
                "actionLabel": None,
                "why": [
                    f"PBXSense found {len(acl_events)} recent ACL failures.",
                    "The Agent keeps only aggregate security evidence, not account names or addresses.",
                ],
                "technical": {
                    "attempts": str(len(acl_events)),
                    "services": services or "PBX",
                    "window": "15 minutes",
                },
            }
        )

    malformed_events = [
        event for event in security_events if event.kind == "RequestBadFormat"
    ]
    if len(malformed_events) >= 3:
        services = ", ".join(sorted({event.service for event in malformed_events})[:3])
        signals.append(
            {
                "id": "sig_security_malformed_requests",
                "kind": "malformed_request_cluster",
                "category": "security",
                "importance": "attention",
                "state": "active",
                "title": "Several malformed PBX requests were rejected.",
                "body": "PBXSense grouped recent invalid request-format events for review.",
                "timeLabel": "Recent",
                "actionLabel": None,
                "why": [
                    f"PBXSense found {len(malformed_events)} recent malformed requests.",
                    "The Agent keeps only aggregate security evidence, not account names or addresses.",
                ],
                "technical": {
                    "attempts": str(len(malformed_events)),
                    "services": services or "PBX",
                    "window": "15 minutes",
                },
            }
        )

    return signals


def _history_window(recent_calls: list[CdrCall], now: datetime) -> str:
    times = [call.started_at for call in recent_calls if call.started_at is not None]
    if not times:
        return "recent history"
    oldest = min(times)
    elapsed = now.replace(tzinfo=None) - oldest
    if elapsed.days > 0:
        return f"{elapsed.days + 1} days"
    hours = max(1, elapsed.seconds // 3600)
    return f"about {hours} hour{'s' if hours != 1 else ''}"


def _dated_calls(recent_calls: list[CdrCall]) -> list[CdrCall]:
    return [call for call in recent_calls if call.started_at is not None]


def _history_days(calls: list[CdrCall]) -> int:
    dates = {call.started_at.date() for call in calls if call.started_at is not None}
    return len(dates)


def _same_weekday_counts(calls: list[CdrCall], now: datetime) -> list[int]:
    today = now.date()
    weekday = today.weekday()
    counts: Counter[object] = Counter(
        call.started_at.date()
        for call in calls
        if call.started_at is not None
        and call.started_at.date() != today
        and call.started_at.weekday() == weekday
    )
    return list(counts.values())


def _busiest_hour(calls: list[CdrCall]) -> tuple[int, int] | None:
    counts: Counter[int] = Counter(
        call.started_at.hour for call in calls if call.started_at is not None
    )
    if not counts:
        return None
    hour, count = counts.most_common(1)[0]
    if count < 4:
        return None
    return hour, count


def _missed_count(calls: list[CdrCall]) -> int:
    attempts = {
        _call_attempt_key(call)
        for call in calls
        if interpreted_call_kind(call) == "missed"
    }
    return len(attempts)


def _call_attempt_key(call: CdrCall) -> tuple[str, str]:
    source = call.source.strip().lower()
    if call.started_at is None:
        fallback = "|".join(
            [
                call.destination.strip().lower(),
                call.channel.strip().lower(),
                call.destination_channel.strip().lower(),
                call.last_data.strip().lower(),
                str(call.duration_seconds),
            ]
        )
        return source, fallback

    bucket = int(call.started_at.timestamp()) // 10
    return source, str(bucket)


def _percent(value: float) -> str:
    return f"{round(value * 100)}%"


def _extension_name(extension: str, extension_names: dict[str, str], observed_label: str = "") -> str:
    if observed_label and observed_label.strip().lower() != extension.strip().lower():
        return observed_label
    return extension_names.get(extension, extension)


def _endpoint_unavailable(endpoint: Any) -> bool:
    state = endpoint.device_state.lower()
    return "unavailable" in state or "unreachable" in state


def _safe_id(raw: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in raw).strip("_").lower()
