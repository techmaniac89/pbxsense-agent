"""Readable diagnostic sections; the raw API remains unchanged."""
from html import escape
import re
from .page_status import readable_timestamp, readable_iso_timestamp

LABELS = {
    'pbxType': 'Phone system', 'tcpConnected': 'Server connection',
    'bannerReceived': 'Protocol greeting received', 'loginAccepted': 'Credentials accepted',
    'commandAccepted': 'PBX commands permitted', 'ok': 'Connection check passed',
    'dataSources': 'Data availability', 'runtime': 'Agent operation', 'loops': 'Background tasks',
    'internetRelay': 'Internet relay', 'history': 'Call history and voicemail',
    'security': 'Security monitoring', 'cdr': 'Call history', 'lastSuccessAgeSeconds': 'Last successful check',
    'endpointClassification': 'Endpoint classification', 'ready': 'Ready',
    'cdrJsonReadable': 'Call-history files readable', 'cdrJsonEnabled': 'Call-history source configured',
    'voicemailPathReadable': 'Voicemail files readable', 'timeoutSeconds': 'Connection timeout',
    'PJSIPShowEndpoints': 'PJSIP endpoint inventory', 'SIPpeers': 'Legacy SIP peer inventory',
    'QueueStatus': 'Queue inventory', 'PJSIPShowRegistrationsOutbound': 'Outbound trunk registrations',
    'pushRelayHeartbeat': 'Cloud presence check', 'pushRelayPublisher': 'Notification publishing',
    'snapshot': 'PBX updates', 'liveCalls': 'Live calls',
}
STATES = {'ready': 'Available', 'not_configured': 'Not configured', 'unsupported': 'Not supported',
          'permission_denied': 'Permission required', 'temporarily_unavailable': 'Temporarily unavailable',
          'partial': 'Some information is missing', 'unknown': 'Not yet verified'}


def label(key):
    return LABELS.get(key, re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', key).replace('_', ' ').capitalize())


def value_text(key, value, timezone_name):
    if isinstance(value, bool):
        return 'Yes' if value else 'No'
    if value is None or value == '':
        return 'Not reported'
    if key.endswith('At') and isinstance(value, (int, float)):
        return readable_timestamp(value, timezone_name)
    if key.endswith('At') and isinstance(value, str) and re.match(r'^\d{4}-\d\d-\d\dT', value):
        return readable_iso_timestamp(value, timezone_name)
    if key == 'lastSuccessAgeSeconds' and isinstance(value, (int, float)):
        return 'Just now' if value < 2 else f'{value:g} seconds ago'
    if key.endswith('Seconds') and isinstance(value, (int, float)):
        return f'{value:g} seconds'
    return STATES.get(str(value), str(value))


def diagnostics_sections(payload, timezone_name, title='PBX connection', depth=0):
    if depth > 6:
        return ''
    rows, groups = [], []
    for key, value in payload.items():
        if isinstance(value, dict):
            groups.append(diagnostics_sections(value, timezone_name, label(str(key)), depth+1))
        elif isinstance(value, (list, tuple)):
            items = ''.join(f'<li>{escape(value_text(str(key), item, timezone_name))}</li>'
                            for item in value if not isinstance(item, (dict, list)))
            rows.append(f'<div><dt>{escape(label(str(key)))}</dt><dd><ul>{items}</ul></dd></div>' if items
                        else f'<div><dt>{escape(label(str(key)))}</dt><dd>{"See Raw JSON for item details" if value else "None reported"}</dd></div>')
        else:
            rows.append(f'<div><dt>{escape(label(str(key)))}</dt><dd>{escape(value_text(str(key), value, timezone_name))}</dd></div>')
    body = f'<dl class="diagnostics">{"".join(rows)}</dl>{"".join(groups)}'
    # Root connection checks and direct diagnostic groups share one accordion
    # level; nested source/task details remain visible inside their parent.
    if depth <= 1:
        if depth == 0:
            return (f'<details class="panel diagnostic-section"><summary>{escape(title)}</summary>'
                    f'<dl class="diagnostics">{"".join(rows)}</dl></details>' + ''.join(groups))
        return (f'<details class="panel diagnostic-section"><summary>{escape(title)}</summary>'
                f'{body}</details>')
    return f'<section class="panel"><h2>{escape(title)}</h2>{body}</section>'
