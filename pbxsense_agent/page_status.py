"""Small, evidence-based status summaries for the administrator page."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def page_timezone(name):
    if name:
        try:
            return ZoneInfo(name), f'{name} (configured PBX timezone)'
        except (ZoneInfoNotFoundError, ValueError):
            return timezone.utc, 'UTC fallback — configured PBX timezone is invalid'
    return datetime.now().astimezone().tzinfo, 'Agent local timezone — PBX timezone not configured'


def readable_timestamp(value, timezone_name):
    if not value:
        return 'Not yet observed'
    tz, _ = page_timezone(timezone_name)
    local = datetime.fromtimestamp(value, tz=tz)
    offset = local.strftime('%z')
    offset = offset[:3] + ':' + offset[3:]
    return f'{local.day} {local.strftime("%B %Y")} at {local:%H:%M} · GMT{offset}'


def readable_iso_timestamp(value, timezone_name):
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            return 'Timezone not reported'
        return readable_timestamp(parsed.timestamp(), timezone_name)
    except (ValueError, TypeError, OverflowError, OSError):
        return 'Not reported'


def capability_statuses(snapshot, *, stale=False, pbx_type=''):
    sources = snapshot.sources
    result = []
    for key, label in (('liveCalls', 'Live calls'), ('phones', 'Phones'),
                       ('trunks', 'Trunks'), ('queues', 'Queues'), ('cdr', 'Call history')):
        state = sources.get(key, {}).get('state', '')
        if key == 'trunks' and not state and pbx_type in {'asterisk', 'grandstream'}:
            inventory = [sources.get(name, {}).get('state') for name in ('PJSIPShowEndpoints', 'SIPpeers')]
            if 'ready' in inventory:
                state = 'partial' if any(e.role == 'unknown' for e in snapshot.endpoints) else 'ready'
        if pbx_type == 'mock' and not state:
            state = 'ready'
        if state == 'not_configured':
            text, style = 'Not configured', 'neutral'
        elif state == 'unsupported':
            text, style = 'Not supported', 'neutral'
        elif stale or not snapshot.reachable:
            text, style = 'Needs attention', 'attention'
        elif state == 'ready':
            text, style = 'Available', 'ok'
        elif state:
            text, style = 'Needs attention', 'attention'
        else:
            text, style = 'Not yet verified', 'neutral'
        result.append((label, text, style))
    return result


def push_pairing_status(status, *, qr_has_activation=None):
    if not status.get('configured'):
        return 'Not configured', 'Local pairing still works. Closed-app notifications require the push relay.', 'neutral'
    if status.get('lastActivationError') or status.get('lastOutboxError'):
        return 'Needs attention', 'Local pairing still works. Open Paired apps to check push registration.', 'attention'
    if qr_has_activation:
        return 'Available for pairing', 'This QR includes secure push setup. Delivery also requires app registration and notification permission.', 'ok'
    if qr_has_activation is False:
        return 'Not included in this QR', 'This QR supports local pairing only. Refresh pairing before scanning to include closed-app push setup.', 'attention'
    if status.get('enrolled'):
        return 'Check app registration', 'The relay is enrolled. Open Paired apps to verify each app; enrollment alone does not confirm delivery.', 'neutral'
    return 'Not ready', 'Local pairing still works. Push relay setup has not completed.', 'attention'
