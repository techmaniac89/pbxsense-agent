"""Pure operations-dashboard rendering; no database or Firebase initialization."""
from __future__ import annotations

import html
from typing import Callable


def _human_age(seconds: object) -> str:
    if not isinstance(seconds, int):
        return "Never"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _human_bytes(value: object) -> str:
    amount = float(max(0, int(value or 0)))
    for unit in ("B", "KiB", "MiB", "GiB"):
        if amount < 1024 or unit == "GiB":
            return f"{int(amount)} B" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return "0 B"


def _daily_workload(row: dict[str, object]) -> int:
    totals = row["totals"]
    return sum(
        int(totals.get(key, 0))
        for key in (
            "heartbeats",
            "controlExchanges",
            "remoteSnapshotReads",
            "encryptedSnapshotsPublished",
            "notificationAttempts",
        )
    )


def _money(value: object, currency: str) -> str:
    amount = max(0.0, float(value or 0))
    if amount < 0.01:
        return f"{currency} {amount:.4f}"
    return f"{currency} {amount:.2f}"


def _usage_dashboard_page(
    report: dict[str, object], *, relay_version: str,
    cost_estimator: Callable[[dict[str, int]], dict[str, float | int]],
) -> str:
    policy = report["policy"]
    totals = report["totals"]
    scheduler = report["scheduler"]
    currency = html.escape(str(report["costModel"]["currency"]))
    delivery_percent = report["notificationDeliveryPercent"]
    delivery_text = (
        f"{delivery_percent:.1f}%"
        if isinstance(delivery_percent, (int, float))
        else "No sends"
    )
    latency = report["averageNotificationLatencyMs"]
    latency_text = f"{latency:,} ms" if isinstance(latency, int) else "No samples"
    remote_reads = int(totals.get("remoteSnapshotReads", 0))
    remote_unavailable = int(totals.get("remoteSnapshotUnavailable", 0))
    unavailable_percent = (
        min(100, round(100 * remote_unavailable / remote_reads, 1))
        if remote_reads
        else 0
    )

    alerts: list[str] = []
    if not scheduler["healthy"]:
        alerts.append("Heartbeat sweep has not completed in the expected three-minute window.")
    if report["expiredApps"]:
        alerts.append(f"{report['expiredApps']} app registration(s) have expired and should be cleaned up.")
    if report["appsExpiringSoon"]:
        alerts.append(f"{report['appsExpiringSoon']} app registration(s) expire within seven days unless refreshed.")
    if report["quotaWarningAgents"]:
        alerts.append(f"{report['quotaWarningAgents']} Agent(s) are at or above 80% of the hourly notification quota.")
    if isinstance(delivery_percent, (int, float)) and delivery_percent < 95:
        alerts.append(f"Push acceptance is {delivery_percent:.1f}% today, below the 95% operator threshold.")
    if unavailable_percent >= 10 and remote_reads >= 10:
        alerts.append(f"{unavailable_percent:.1f}% of remote snapshot reads were unavailable today.")
    alert_html = "".join(f"<li>{html.escape(item)}</li>" for item in alerts)
    if not alert_html:
        alert_html = '<li class="ok">No operational threshold needs attention.</li>'

    daily_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(row['date']))}{'' if row['complete'] else ' (today)'}</td>"
        f"<td>{row['agents']}</td><td>{row['apps']}</td>"
        f"<td>{row['totals'].get('heartbeats', 0):,}</td>"
        f"<td>{row['totals'].get('controlExchanges', 0):,}</td>"
        f"<td>{row['totals'].get('remoteSnapshotReads', 0):,}</td>"
        f"<td>{row['totals'].get('remoteSnapshotUnavailable', 0):,}</td>"
        f"<td>{row['totals'].get('encryptedSnapshotsPublished', 0):,}</td>"
        f"<td>{_human_bytes(row['totals'].get('encryptedSnapshotBytes', 0))}</td>"
        f"<td>{row['totals'].get('notificationAccepted', 0):,}</td>"
        f"<td>{row['totals'].get('notificationFailed', 0):,}</td>"
        f"<td>{_money(cost_estimator(row['totals'])['total'], currency)}</td>"
        "</tr>"
        for row in report["daily"]
    )
    max_daily_workload = max(1, *(_daily_workload(row) for row in report["daily"]))
    trend_rows = "".join(
        '<div class="trend-row">'
        f"<span>{html.escape(str(row['date'])[5:])}</span>"
        f'<div class="bar-track"><i style="width:{max(2, round(100 * _daily_workload(row) / max_daily_workload))}%"></i></div>'
        f"<b>{_daily_workload(row):,}</b></div>"
        for row in reversed(report["daily"])
    )
    agent_rows = "".join(
        "<tr>"
        f"<td><code>{html.escape(str(row['agent']))}</code></td>"
        f"<td>{'Active' if row['active'] else 'Inactive'}</td>"
        f"<td>{_human_age(row['lastSeenSeconds'])}</td>"
        f"<td>{row['registeredApps']}</td><td>{row['connectedApps']}</td>"
        f"<td>{_percent_text(row['deliveryPercent'])}</td>"
        f"<td><span class=\"meter {'warn' if row['quotaPercent'] >= 80 else ''}\">{row['quotaCount']}/{policy['maxEventsPerAgentHour']} ({row['quotaPercent']}%)</span></td>"
        f"<td>{_latency_text(row['lastFcmLatencyMs'])}</td>"
        f"<td>{_money(row['estimatedCostToday']['total'], currency)}</td>"
        f"<td>{_money(row['estimatedCost30Days'], currency)}</td>"
        f"<td>{sum(int(value) for value in row['usage'].values()):,}</td>"
        "</tr>"
        for row in report["agents"]
        if row["active"]
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="300"><title>PBXSense Relay operations</title>
<style>{_usage_css()}</style></head><body><main><header><div><p class="eyebrow">PBXSense Relay {html.escape(relay_version)}</p>
<h1>Operations dashboard</h1><p>Updated {html.escape(str(report['generatedAt']))}; refreshes every five minutes.</p></div>
<span class="status {'attention' if alerts else ''}">{'Attention' if alerts else 'Operational'} · privacy-safe</span></header>
<section class="cards"><article><span>Active Agents</span><strong>{report['activeAgents']}</strong><small>{report['registeredAgents']} registered</small></article>
<article><span>Connected apps</span><strong>{report['connectedApps']}</strong><small>{report['registeredApps']} registered</small></article>
<article><span>Push acceptance</span><strong>{delivery_text}</strong><small>{totals.get('notificationAccepted', 0):,} accepted · {totals.get('notificationFailed', 0):,} failed</small></article>
<article><span>FCM latency</span><strong>{latency_text}</strong><small>Average across today’s attempts</small></article>
<article><span>Heartbeat scheduler</span><strong>{'Healthy' if scheduler['healthy'] else 'Stale'}</strong><small>{_human_age(scheduler['ageSeconds'])} · last sweep lost {scheduler['lastLost']}</small></article>
<article><span>Quota pressure</span><strong>{report['highestQuotaPercent']}%</strong><small>{report['quotaWarningAgents']} Agents at ≥80%</small></article>
<article><span>Remote availability</span><strong>{100 - unavailable_percent:.1f}%</strong><small>{remote_unavailable:,} unavailable of {remote_reads:,} reads</small></article>
<article><span>Estimated Relay cost</span><strong>{_money(report['estimatedCostToday']['total'], currency)}</strong><small>{_money(report['estimatedCost30Days'], currency)} projected from {report['costModel']['projectionBasisHours']:.1f}h observed</small></article></section>
<section class="alerts"><h2>Operational attention</h2><ul>{alert_html}</ul></section>
<section><h2>Remotely delivered policy</h2><div class="policy">
<span>Presence <b>{policy['agentPresenceSeconds']} sec</b></span><span>Lost after <b>{policy['agentLossSeconds']} sec</b></span>
<span>App poll <b>{policy['remotePollSeconds']} sec</b></span><span>Control exchange <b>{policy['controlExchangeSeconds']} sec</b></span>
<span>Apps per Agent <b>{policy['maxAppsPerAgent']}</b></span><span>Events per hour <b>{policy['maxEventsPerAgentHour']}</b></span></div></section>
<section class="split"><div><h2>Seven-day workload movement</h2><p class="section-summary"><strong>{report['workloadOperations']:,}</strong> protocol operations today</p><div class="trends">{trend_rows}</div></div>
<div><h2>Capacity and retention</h2><dl class="facts"><div><dt>Encrypted snapshot coverage</dt><dd>{report['snapshotCapableApps']} / {report['registeredApps']} apps</dd></div>
<div><dt>Encrypted bytes today</dt><dd>{_human_bytes(totals.get('encryptedSnapshotBytes', 0))}</dd></div>
<div><dt>Registrations expiring in 7 days</dt><dd>{report['appsExpiringSoon']}</dd></div><div><dt>Expired registrations</dt><dd>{report['expiredApps']}</dd></div>
<div><dt>Usage rollup retention</dt><dd>90 days (TTL required)</dd></div><div><dt>Event retention</dt><dd>2 days</dd></div></dl></div></section>
<section><h2>Daily rollups</h2><div class="table"><table><thead><tr><th>UTC date</th><th>Agents</th><th>Apps</th><th>Heartbeats</th><th>Control</th><th>Remote reads</th><th>Unavailable</th><th>Snapshots</th><th>Encrypted bytes</th><th>Push accepted</th><th>Push failed</th><th>Estimated cost</th></tr></thead><tbody>{daily_rows}</tbody></table></div></section>
<section><h2>Active Agent activity today</h2><div class="table"><table><thead><tr><th>Hashed Agent</th><th>Status</th><th>Last contact</th><th>Apps</th><th>Connected</th><th>Push acceptance</th><th>Hourly quota</th><th>Last FCM latency</th><th>Est. today</th><th>Est. 30 days</th><th>Operations</th></tr></thead><tbody>{agent_rows}</tbody></table></div><p class="note">Inactive Agents are excluded from this activity list. {html.escape(str(report['privacy']))}</p></section>
<section><h2>Cost model</h2><p class="note">{html.escape(str(report['costModel']['basis']))} The model attributes measured requests, estimated Firestore reads/writes/deletes, Cloud Run request-based CPU and memory, and estimated encrypted-snapshot egress to each hashed Agent. The 30-day projection annualizes today’s workload after at least one observed UTC hour; it is volatile early in the day. Average request duration is {report['costModel']['averageRequestSeconds']:.3f} seconds. Every unit rate is configurable with <code>PBXSENSE_RELAY_COST_*</code> environment variables. Reconcile these estimates against a Cloud Billing export before using them for pricing or customer billing.</p></section>
<section><h2>Metric notes</h2><p class="note">Push acceptance is Firebase acceptance, not proof that Android displayed a notification. FCM itself is a no-cost Firebase product; the estimate covers Relay infrastructure around it. Workload proxy combines heartbeats, control exchanges, remote reads, snapshot publications, and notification attempts. Cloud Run, Firestore, Firebase, and Billing remain authoritative for cost and platform latency. Expired-record counts verify application state, while TTL enablement must still be checked in Google Cloud.</p></section>
</main></body></html>"""


def _percent_text(value: object) -> str:
    return f"{value:.1f}%" if isinstance(value, (int, float)) else "—"


def _latency_text(value: object) -> str:
    return f"{value:,} ms" if isinstance(value, int) else "—"


def _usage_css() -> str:
    return """
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#07110f;color:#edf7f2}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#17362e 0,#07110f 42%);min-height:100vh}
main{width:min(1180px,calc(100% - 32px));margin:0 auto;padding:42px 0 80px}header{display:flex;justify-content:space-between;gap:24px;align-items:flex-start}
h1{font-size:clamp(32px,5vw,54px);margin:4px 0 8px}h2{margin:0 0 18px;font-size:22px}.eyebrow{color:#f1bd70;text-transform:uppercase;letter-spacing:.14em;font-size:12px;font-weight:800}
p{color:#a9bdb5}.status{background:#193f35;color:#8ce0c2;border:1px solid #285b4e;border-radius:999px;padding:8px 13px;white-space:nowrap}.status.attention{background:#3c241c;color:#ffb4a4;border-color:#704032}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:34px 0}article,section{background:#0e1d19;border:1px solid #203c34;border-radius:18px;padding:22px}
.section-summary{margin:-8px 0 18px;color:#9ebbb1}.section-summary strong{color:#f5fff9;font-size:1.15rem}
section{margin:16px 0}article span,article small{display:block;color:#99afa6}article strong{display:block;font-size:34px;margin:10px 0 5px}
.policy{display:flex;flex-wrap:wrap;gap:10px}.policy span{background:#152a24;border-radius:10px;padding:10px 13px;color:#a9bdb5}.policy b{color:#edf7f2}
.alerts ul{margin:0;padding-left:22px;color:#ffb4a4;display:grid;gap:9px}.alerts .ok{color:#8ce0c2}.split{display:grid;grid-template-columns:1.15fr 1fr;gap:28px}.trends{display:grid;gap:10px}.trend-row{display:grid;grid-template-columns:48px 1fr 72px;gap:10px;align-items:center;color:#99afa6;font-variant-numeric:tabular-nums}.trend-row b{text-align:right;color:#edf7f2}.bar-track{height:10px;background:#152a24;border-radius:99px;overflow:hidden}.bar-track i{display:block;height:100%;background:linear-gradient(90deg,#2e8f73,#8ce0c2);border-radius:inherit}.facts{margin:0;display:grid;gap:0}.facts div{display:flex;justify-content:space-between;gap:20px;padding:10px 0;border-bottom:1px solid #203c34}.facts dt{color:#99afa6}.facts dd{margin:0;text-align:right;font-weight:700}.meter{display:inline-block;background:#193f35;color:#8ce0c2;border-radius:99px;padding:5px 8px}.meter.warn{background:#3c241c;color:#ffb4a4}
.table{overflow:auto}table{width:100%;border-collapse:collapse;min-width:980px}th,td{text-align:left;padding:12px;border-bottom:1px solid #203c34;font-variant-numeric:tabular-nums;white-space:nowrap}th{color:#8ce0c2;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
code{color:#f1bd70}.note{font-size:13px;line-height:1.55}.login{display:grid;place-items:center;min-height:100vh;padding:20px}.login section{width:min(460px,100%)}label{display:grid;gap:8px;color:#a9bdb5}
input{width:100%;padding:13px;border-radius:10px;border:1px solid #36554c;background:#07110f;color:#fff}button{margin-top:14px;border:0;border-radius:10px;padding:12px 16px;background:#e9ad5c;color:#191107;font-weight:800;cursor:pointer}.error{color:#ffaaa0}
@media(max-width:800px){.cards{grid-template-columns:repeat(2,1fr)}header{display:block}.status{display:inline-block;margin-top:12px}.split{grid-template-columns:1fr}}
@media(max-width:480px){.cards{grid-template-columns:1fr}}
"""



