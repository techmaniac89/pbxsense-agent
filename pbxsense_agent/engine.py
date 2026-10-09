from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from math import ceil
import re
from typing import Any

from .history import CdrCall, SecurityEvent, VoicemailMessage, interpreted_call_kind


def build_engine_signals(
    *,
    endpoints: list[Any],
    queues: list[Any],
    recent_calls: list[CdrCall],
    voicemails: list[VoicemailMessage],
    security_events: list[SecurityEvent],
    extension_names: dict[str, str],
    now: datetime,
    data_sources: dict[str, dict] | None = None,
) -> list[dict]:
    sources = data_sources or {}
    if sources.get("queues", {}).get("state", "ready") != "ready":
        queues = []
    if sources.get("cdr", {}).get("state", "ready") != "ready":
        recent_calls = []
    signals: list[dict] = []
    signals.extend(
        _missed_call_recommendations(endpoints, recent_calls, extension_names, now)
    )
    signals.extend(_call_mix_insights(recent_calls, voicemails, now))
    signals.extend(_rhythm_insights(recent_calls, now))
    signals.extend(_call_quality_insights(recent_calls))
    signals.extend(_operational_insights(endpoints, queues, recent_calls, extension_names, now))
    signals.extend(_operational_moments(queues, recent_calls, voicemails, now))
    signals.extend(_missed_rate_recommendations(recent_calls, now))
    signals.extend(_endpoint_recommendations(endpoints, extension_names))
    signals.extend(_security_signals(recent_calls, security_events, now))
    if sources.get("queueMembers", {}).get("state", "ready") != "ready":
        signals = [signal for signal in signals if signal.get("kind") != "queue_demand_vs_agents"]
    if sources.get("voicemail", {}).get("state", "ready") != "ready":
        signals = [signal for signal in signals if signal.get("kind") != "voicemail_free_service_streak"]
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
    cutoff = now.replace(tzinfo=None) - timedelta(minutes=15)
    failed_calls = [
        call
        for call in recent_calls
        if call.disposition.upper() in {"FAILED", "CONGESTION"}
        and call.started_at is not None
        and call.started_at >= cutoff
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
                    "window": "15 minutes",
                    "sources": ", ".join(sorted({call.source for call in failed_calls if call.source})[:5]),
                },
            }
        )

    recent_security_events = [
        event
        for event in security_events
        if event.occurred_at is not None and event.occurred_at >= cutoff
    ]
    authentication_events = [
        event
        for event in recent_security_events
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

    acl_events = [event for event in recent_security_events if event.kind == "FailedACL"]
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
        event for event in recent_security_events if event.kind == "RequestBadFormat"
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


def _call_quality_insights(recent_calls: list[CdrCall]) -> list[dict]:
    measured = [
        call for call in recent_calls
        if call.packet_loss_percent is not None
        or call.jitter_ms is not None
        or call.latency_ms is not None
    ]
    degraded = [
        call for call in measured
        if (call.packet_loss_percent or 0) >= 2
        or (call.jitter_ms or 0) >= 30
        or (call.latency_ms or 0) >= 150
    ]
    if not degraded:
        return []
    worst_loss = max((call.packet_loss_percent or 0) for call in degraded)
    worst_jitter = max((call.jitter_ms or 0) for call in degraded)
    worst_latency = max((call.latency_ms or 0) for call in degraded)
    return [{
        "id": "sig_insight_cucm_call_quality",
        "kind": "call_quality_degradation",
        "category": "insight",
        "importance": "attention",
        "state": "active",
        "title": "Recent calls show quality degradation.",
        "body": "CUCM diagnostic records found packet loss, jitter, or latency worth reviewing.",
        "timeLabel": "Recent history",
        "actionLabel": None,
        "why": [
            f"{len(degraded)} of {len(measured)} calls with CMR evidence crossed a quality threshold.",
            "PBXSense checks for at least 2% packet loss, 30 ms jitter, or 150 ms latency.",
        ],
        "technical": {
            "degraded_calls": str(len(degraded)),
            "measured_calls": str(len(measured)),
            "worst_packet_loss_percent": f"{worst_loss:.2f}",
            "worst_jitter_ms": f"{worst_jitter:.1f}",
            "worst_latency_ms": f"{worst_latency:.1f}",
        },
    }]


def _signal(category: str, identifier: str, kind: str, title: str, body: str,
            why: list[str], technical: dict, time_label: str = "Today") -> dict:
    return {"id": f"sig_{category}_{identifier}", "kind": kind, "category": category,
            "importance": "feed", "state": "active", "title": title, "body": body,
            "timeLabel": time_label, "actionLabel": None, "why": why,
            "technical": {key: str(value) for key, value in technical.items()}}


def _operational_insights(endpoints: list[Any], queues: list[Any], calls: list[CdrCall],
                          extension_names: dict[str, str], now: datetime) -> list[dict]:
    signals: list[dict] = []
    waiting = sum(max(0, queue.waiting_callers) for queue in queues)
    available = sum(max(0, queue.available_members) for queue in queues)
    if waiting > available:
        signals.append(_signal("insight", "queue_demand_agents", "queue_demand_vs_agents",
            f"{waiting} callers are waiting for {available} available queue agents.",
            "Queue demand is currently higher than available coverage.",
            [f"The PBX reports {waiting} waiting caller(s) and {available} available agent(s)."],
            {"waiting_callers": waiting, "available_agents": available}, "Now"))

    dated = _dated_calls(calls)
    queue_misses = [call for call in dated if interpreted_call_kind(call) == "missed" and _is_queue_call(call)]
    periods: Counter[tuple[object, int]] = Counter((call.started_at.date(), call.started_at.hour) for call in queue_misses)
    hours: Counter[int] = Counter(hour for (_, hour), count in periods.items() if count >= 2)
    if hours:
        hour, days = hours.most_common(1)[0]
        if days >= 2:
            signals.append(_signal("insight", "repeated_abandonment", "repeated_abandonment_period",
                f"Queue abandonments repeatedly cluster around {hour:02d}:00.",
                "The same pressure period appears on multiple days.",
                [f"At least two abandoned queue calls appeared in that hour on {days} days."],
                {"hour": f"{hour:02d}:00", "matching_days": days}, "Recent history"))

    after_hours = [call for call in dated if call.started_at.hour < 8 or call.started_at.hour >= 18]
    if len(dated) >= 20 and len(after_hours) >= 5 and len(after_hours) / len(dated) >= .2:
        signals.append(_signal("insight", "after_hours_calls", "after_hours_call_pattern",
            "A meaningful share of calls arrives after hours.",
            "Coverage or routing outside the working day may deserve review.",
            [f"{len(after_hours)} of {len(dated)} visible calls were before 08:00 or after 18:00."],
            {"after_hours_calls": len(after_hours), "visible_calls": len(dated)}, "Recent history"))

    endpoint_ids = {endpoint.extension for endpoint in endpoints if endpoint.role != "trunk"}
    failed = Counter(call.destination for call in dated if call.destination in endpoint_ids and interpreted_call_kind(call) == "missed")
    if failed:
        extension, count = failed.most_common(1)[0]
        days = {call.started_at.date() for call in dated if call.destination == extension and interpreted_call_kind(call) == "missed"}
        if count >= 4 and len(days) >= 2:
            name = _extension_name(extension, extension_names, "")
            signals.append(_signal("insight", f"extension_availability_{_safe_id(extension)}", "recurring_extension_availability",
                f"{name} has recurring availability pressure.",
                "Missed attempts to this extension recur across multiple days.",
                [f"PBXSense found {count} missed attempts across {len(days)} days."],
                {"extension": extension, "missed_attempts": count, "days": len(days)}, "Recent history"))

    configured_trunks = [endpoint for endpoint in endpoints if endpoint.role == "trunk"]
    if len(configured_trunks) >= 2:
        missed_by_trunk: Counter[str] = Counter()
        for call in dated:
            if interpreted_call_kind(call) != "missed":
                continue
            trunk_name = _trunk_name_for_context(call.context, endpoints, extension_names)
            if trunk_name:
                missed_by_trunk[_short_trunk_name(trunk_name)] += 1
        total_trunk_missed = sum(missed_by_trunk.values())
        if total_trunk_missed >= 5 and missed_by_trunk:
            trunk_name, count = missed_by_trunk.most_common(1)[0]
            if count / total_trunk_missed >= .6:
                signals.append(_signal("insight", f"trunk_missed_{_safe_id(trunk_name)}", "trunk_missed_call_load",
                    f"{trunk_name} carries most of the visible missed-call load.",
                    "One of the configured SIP trunks accounts for a disproportionate share.",
                    [f"{count} of {total_trunk_missed} missed inbound calls were associated with this trunk."],
                    {"trunk": trunk_name, "missed_calls": count, "total_trunk_missed_calls": total_trunk_missed}, "Recent history"))

    today_durations = [c.duration_seconds for c in dated if c.started_at.date() == now.date() and interpreted_call_kind(c) == "answered"]
    prior_durations = [c.duration_seconds for c in dated if c.started_at.date() != now.date() and c.started_at.weekday() == now.weekday() and interpreted_call_kind(c) == "answered"]
    if len(today_durations) >= 5 and len(prior_durations) >= 10:
        today_avg, prior_avg = sum(today_durations) / len(today_durations), sum(prior_durations) / len(prior_durations)
        if prior_avg >= 10 and (today_avg >= prior_avg * 1.4 or today_avg <= prior_avg * .6):
            direction = "longer" if today_avg > prior_avg else "shorter"
            signals.append(_signal("insight", "weekday_duration_change", "weekday_call_duration_change",
                f"Answered calls are {direction} than on matching weekdays.",
                "PBXSense compared average answered-call duration.",
                [f"Today averages {round(today_avg)}s versus {round(prior_avg)}s on matching weekdays."],
                {"today_average_seconds": round(today_avg), "weekday_average_seconds": round(prior_avg)}))

    trunks = Counter(filter(None, (_trunk_display_for_call(call, endpoints, extension_names) for call in dated)))
    if sum(trunks.values()) >= 10 and len(trunks) >= 2:
        trunk, count = trunks.most_common(1)[0]
        share = count / sum(trunks.values())
        if share >= .8:
            signals.append(_signal("insight", "trunk_distribution", "trunk_usage_distribution",
                f"Most visible calls rely on trunk {trunk}.",
                "Traffic is concentrated enough that failover readiness matters.",
                [f"This trunk carried {round(share * 100)}% of calls with identifiable trunks."],
                {"primary_trunk": trunk, "share": f"{round(share * 100)}%", "identified_calls": sum(trunks.values())}, "Recent history"))
    return signals


def _operational_moments(queues: list[Any], calls: list[CdrCall], voicemails: list[VoicemailMessage], now: datetime) -> list[dict]:
    signals: list[dict] = []
    answered = sorted((c for c in _dated_calls(calls) if c.started_at.date() == now.date() and interpreted_call_kind(c) == "answered"), key=lambda c: c.started_at)
    if answered:
        first = answered[0]
        signals.append(_signal("moment", "first_answered_call", "first_answered_call_of_day",
            "The first call of the day was answered.", "The day is under way with a connected caller.",
            [f"The first visible answered call began at {first.started_at:%H:%M}."], {"answered_at": f"{first.started_at:%H:%M}"}))
    signals.extend(_adaptive_volume_moments(calls, now))
    if queues and now.hour >= 17 and all(q.waiting_callers == 0 and q.longest_wait_seconds <= 60 for q in queues):
        signals.append(_signal("moment", "queues_met_target", "queues_finished_within_target",
            "All monitored queues finished within target.", "No callers remain waiting and observed waits stayed within 60 seconds.",
            [f"PBXSense checked {len(queues)} monitored queue(s) near the end of the day."],
            {"queues": len(queues), "target_seconds": 60}))
    today_calls = [c for c in _dated_calls(calls) if c.started_at.date() == now.date()]
    today_missed = _missed_count(today_calls)
    if now.hour >= 17 and today_calls and today_missed == 0:
        signals.append(_signal("moment", "day_without_missed_calls", "full_day_without_missed_calls",
            "The working day finished without a missed call.",
            "Every visible call avoided a missed-call outcome.",
            [f"PBXSense checked {len(today_calls)} call(s); a no-call day never qualifies."],
            {"visible_calls": len(today_calls), "missed_calls": 0}))

    calls_by_date: dict[object, list[CdrCall]] = {}
    for call in _dated_calls(calls):
        calls_by_date.setdefault(call.started_at.date(), []).append(call)
    clean_streak, clean_day = 0, now.date()
    # Today counts only after the working day; earlier in the day start with yesterday.
    if now.hour < 17:
        clean_day -= timedelta(days=1)
    while calls_by_date.get(clean_day) and _missed_count(calls_by_date[clean_day]) == 0:
        clean_streak, clean_day = clean_streak + 1, clean_day - timedelta(days=1)
    if clean_streak >= 2:
        signals.append(_signal("moment", "clean_operating_streak", "clean_operating_day_streak",
            f"A {clean_streak}-day clean operating streak is growing.",
            "Each counted day had real call activity and no missed calls.",
            ["No-call days and incomplete working days are excluded."], {"streak_days": clean_streak}))
    activity_dates = {c.started_at.date() for c in _dated_calls(calls)}
    voicemail_dates = {v.created_at.date() for v in voicemails if v.created_at is not None}
    streak, day = 0, now.date()
    while day in activity_dates and day not in voicemail_dates:
        streak, day = streak + 1, day - timedelta(days=1)
    if streak >= 2:
        signals.append(_signal("moment", "voicemail_free_streak", "voicemail_free_service_streak",
            f"A {streak}-day voicemail-free service streak is growing.",
            "Calls were visible without a new voicemail on each counted day.",
            ["The streak counts consecutive days represented in local call history."], {"streak_days": streak}))
    return signals


def _adaptive_volume_moments(calls: list[CdrCall], now: datetime) -> list[dict]:
    """Recognize volume relative to this PBX, never a universal call count."""
    answered = [call for call in _dated_calls(calls) if interpreted_call_kind(call) == "answered"]
    today = now.date()
    signals: list[dict] = []

    daily_counts = Counter(call.started_at.date() for call in answered if call.started_at.date() != today)
    current_daily = sum(call.started_at.date() == today for call in answered)
    if len(daily_counts) >= 3:
        signals.extend(_average_volume_moment("daily", current_daily, list(daily_counts.values()), len(daily_counts)))

    current_week = today.isocalendar()[:2]
    weekly_calls: Counter[tuple[int, int]] = Counter()
    weekly_days: dict[tuple[int, int], set[object]] = {}
    current_week_count = 0
    for call in answered:
        week = call.started_at.date().isocalendar()[:2]
        if week == current_week:
            current_week_count += 1
        else:
            weekly_calls[week] += 1
            weekly_days.setdefault(week, set()).add(call.started_at.date())
    complete_weeks = [count for week, count in weekly_calls.items() if len(weekly_days.get(week, set())) >= 4]
    if len(complete_weeks) >= 2:
        signals.extend(_average_volume_moment("weekly", current_week_count, complete_weeks, len(complete_weeks)))

    current_month = (today.year, today.month)
    monthly_calls: Counter[tuple[int, int]] = Counter()
    monthly_days: dict[tuple[int, int], set[object]] = {}
    current_month_count = 0
    for call in answered:
        month = (call.started_at.year, call.started_at.month)
        if month == current_month:
            current_month_count += 1
        else:
            monthly_calls[month] += 1
            monthly_days.setdefault(month, set()).add(call.started_at.date())
    complete_months = [count for month, count in monthly_calls.items() if len(monthly_days.get(month, set())) >= 15]
    if len(complete_months) >= 2:
        signals.extend(_average_volume_moment("monthly", current_month_count, complete_months, len(complete_months)))
    return signals


def _average_volume_moment(period: str, current: int, baselines: list[int], samples: int) -> list[dict]:
    average = sum(baselines) / len(baselines)
    target = max(1, ceil(average))
    if current < target:
        return []
    label = {"daily": "day", "weekly": "week", "monthly": "month"}[period]
    return [_signal("moment", f"adaptive_{period}_volume", "adaptive_call_volume_milestone",
        f"This {label} reached the PBX's usual call volume.",
        f"The team answered {current} calls against a learned {period} average of about {average:.1f}.",
        [f"The target adapts to this PBX using {samples} completed {label}(s)."],
        {"period": period, "answered_calls": current, "average_answered_calls": f"{average:.1f}",
         "adaptive_target": target, "baseline_periods": samples},
        {"daily": "Today", "weekly": "This week", "monthly": "This month"}[period])]


def _is_queue_call(call: CdrCall) -> bool:
    return "queue" in " ".join((call.context, call.last_app, call.last_data)).lower()


def _trunk_from_call(call: CdrCall) -> str:
    for value in (call.channel, call.destination_channel):
        match = re.search(r"(?:PJSIP|SIP|IAX2)/([^/-]+)", value, re.IGNORECASE)
        if match and not match.group(1).isdigit():
            return match.group(1)
    return ""


def _trunk_display_for_call(call: CdrCall, endpoints: list[Any], extension_names: dict[str, str]) -> str:
    trunk = _trunk_from_call(call)
    if not trunk:
        context_name = _trunk_name_for_context(call.context, endpoints, extension_names)
        return context_name or ""
    for endpoint in endpoints:
        if endpoint.role == "trunk" and endpoint.extension.lower() == trunk.lower():
            return _extension_name(endpoint.extension, extension_names, endpoint.label)
    return trunk


def _trunk_name_for_context(context: str, endpoints: list[Any], extension_names: dict[str, str]) -> str | None:
    """Resolve dialplan contexts like from-Cosmote without calling them departments."""
    normalized = re.sub(r"[^a-z0-9]", "", context.lower())
    if not normalized.startswith("from"):
        return None
    suffix = normalized[4:]
    if not suffix or suffix == "internal":
        return None
    for endpoint in endpoints:
        if endpoint.role != "trunk":
            continue
        candidates = (endpoint.extension, endpoint.label, extension_names.get(endpoint.extension, ""))
        if any(
            suffix == candidate or (len(suffix) >= 3 and suffix in candidate)
            for candidate in (re.sub(r"[^a-z0-9]", "", value.lower()) for value in candidates if value)
        ):
            return _extension_name(endpoint.extension, extension_names, endpoint.label)
    return None


def _short_trunk_name(name: str) -> str:
    concise = re.sub(r"\s+(?:sip\s+)?trunk$", "", name, flags=re.IGNORECASE).strip()
    return concise or name


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
