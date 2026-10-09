# PBXSense Agent Connectors

PBXSense Agent is open source so PBX support should be easy to extend without
changing the PBXSense app.

A connector observes one PBX family and translates it into PBXSense concepts.
The app should not know whether the source is Asterisk, FreeSWITCH, CUCM, or
something else.

Connectors live inside this agent repository under `pbxsense_agent/`. They are
responsible for PBX-specific access, authentication, parsing, and diagnostics.
Everything they return should already be shaped for the Agent engine, not for a
specific vendor UI or raw protocol feed.

The internal contract is `PbxSnapshot`, containing `PbxChannel`, `PbxEndpoint`
and `PbxQueue` observations from `pbxsense_agent.observations`. These neutral
types are shared by all connectors; they are not the app's JSON schema.
Legacy `pulse.AmiSnapshot`, `AmiChannel`, `AmiEndpoint` and `AmiQueue` imports
remain exact aliases for compatibility. New connectors should import the
neutral types directly. Preserve health confidence, unknown states and optional
history evidence rather than inventing capabilities a PBX cannot report.

`HistoryCollector` merges configured local history for Asterisk/Grandstream and
CUCM at `history_poll_seconds`, without changing the live snapshot interval.
FreeSWITCH and Yeastar keep their connector-owned history collection. Failed
local reads do not advance cache fingerprints, allowing the next collection to
retry. `SignalCollector` observes the enriched snapshot under the runtime's
collection lock; connector code must not call trackers independently.

```text
PBX connector
  -> channels, endpoints, trunks, extension presence, history evidence
  -> Pulse snapshot
  -> Signals
  -> App
```

## Source availability and freshness

Agent `0.6.39-beta` consumes source availability/freshness in a persistent daily
ledger. Connectors keep their existing bounded history windows; the shared
collector accumulates newly observed outcomes across successive overlapping
windows. A full first window or a lost overlap is not complete-day evidence.
Failed queues/history and collection gaps invalidate affected coverage rather
than certifying success from retained data. Queue/day/streak/volume Moments now
require this evidence; see `CONFIGURATION.md` for warm-up and sampling limits.

Agent `0.6.38-beta` adds optional `dataSources` to `/home` (and therefore
`/live`) and `/diagnostics`. Each source reports `state` and
`lastSuccessAgeSeconds`. States are `ready`, `partial`, `unsupported`,
`not_configured`, `permission_denied`, or `temporarily_unavailable`.
An age of `null` means no successful observation yet; zero is a fresh read,
not an assertion that the last call or history file was created recently.
Missing keys are unspecified, not proof of support. This is additive:
existing apps can ignore it, and no app version change is needed. A future app
UI can label retained history values as stale using these fields.

Agent `0.6.38-beta` and app `0.6.7-beta+284` coordinate source-aware queue and
current-call display. Queue rows add optional `sourceState` and `membersKnown`;
`status: unknown` means the retained values are not a current observation.
Unsupported member coverage does not imply zero available agents. The app shows
unavailable queues neutrally, and unconfigured/unavailable live-call monitoring
does not claim that there are no calls. Update the app alongside this Agent for
the new queue display; older apps ignore the metadata and may still label an
unknown queue as ready. Missing metadata retains legacy parsing behavior.

Production history collection uses strict read-error reporting. Real filesystem
read/scan failures retain the last successful source records and fingerprints,
mark that source unavailable, and retry at the next history interval without
taking the PBX core offline. Best-effort diagnostic readers remain compatible.
Malformed individual JSON/CSV records and oversized files are still skipped
within the existing bounded-reader safeguards. Yeastar queue inventory and
status structures are validated before replacing the complete queue cache;
only a valid empty list or explicit zero count can confirm emptiness.

- A successful empty read means zero. Failed optional queue reads retain the
  last complete queue generation and report unavailable instead of silently
  implying no callers. Queue-cleared activity and queue-target moments require
  successful queue evidence. Queue-demand insights are suppressed when agent
  coverage is unsupported; history-driven insights/moments do not use failed
  CDR reads, and voicemail-free streaks require available voicemail evidence.
- Asterisk and Grandstream additionally expose the individual AMI actions
  (`PJSIPShowEndpoints`, `PJSIPShowContacts`,
  `PJSIPShowRegistrationsOutbound`, `QueueStatus`, `SIPpeers`). Unsupported
  optional actions are normal on some PBXs; denied permissions are distinct.
  Actions are retried on subsequent polls, allowing permissions to recover.
  Raw rejection messages are not published.
- FreeSWITCH keeps up to 10,000 previously observed extension identities in
  memory. A complete successful registration list confirms deregistration;
  failed/incomplete lists make remembered phones unknown, not offline or
  recovered. This inventory resets on Agent restart and cannot discover phones
  that have never registered or appeared on an internal call leg.
  `mod_callcenter` provides waiting/trying caller counts, longest wait from
  `joined_epoch`, and deduplicated available/busy/on-break/total agents.
  Logged-out agents and agents still within `ready_time` are not available.
  Missing `mod_callcenter` does not take the core connector offline.
- CUCM reports registration coverage separately from JTAPI live-call
  availability; queues are unsupported. Yeastar reports live and history sources
  independently; queue member coverage is currently unsupported.
- Configured local history paths that disappear retain their last records and
  report unavailable. Unconfigured paths do not count as confirmed empty
  history. Local history readiness means the source path is accessible and the
  bounded reader completed, not that every record is valid or the PBX has
  emitted CDRs. Existing malformed-record and scan-limit safeguards still apply.

FreeSWITCH parsing follows the upstream
[callcenter implementation](https://github.com/signalwire/freeswitch/blob/master/src/mod/applications/mod_callcenter/mod_callcenter.c)
and [JSON show implementation](https://github.com/signalwire/freeswitch/blob/master/src/mod/applications/mod_commands/mod_commands.c).

## Existing Connectors

| PBX | Connector | Status |
| --- | --- | --- |
| Asterisk | `ami.py` | Active calls, endpoints, trunks, queue wait/member state, CDR history, voicemail |
| FreePBX, Issabel, VitalPBX | `ami.py` | Supported as Asterisk-based systems |
| Grandstream UCM / SoftwareUCM | `grandstream.py` | Restricted AMI with UCM port/TLS defaults, live calls, endpoints, trunks, queues; optional local history paths |
| FreeSWITCH | `freeswitch.py` | Event Socket connection, retained observed extension inventory, active channels, optional mod_callcenter queue wait/agent state and JSON CDR/voicemail paths |
| FusionPBX | `freeswitch.py` | Supported as a FreeSWITCH-based system |
| Yeastar P-Series | `yeastar.py` | OAuth API, extension status, live calls, queue waiting status, CDR, voicemail, recordings |
| Cisco Unified Communications Manager | `cucm.py`, `jtapi.py` | Read-only AXL inventory, RisPort70 registration presence, completed CDR/CMR history, and optional JTAPI live calls |
| Mock | `mock.py` | Development/test fixture |

GUI PBX distributions are handled through the PBX engine underneath them.
FreePBX, Issabel, and VitalPBX still expose Asterisk AMI. FusionPBX still uses
FreeSWITCH Event Socket. Their web interfaces do not need separate connectors
unless PBXSense later wants distribution-specific settings, provisioning, or
dashboard metadata.

The Asterisk connector reads PJSIP endpoints and also asks for classic
`chan_sip` peers when that AMI action is available.

Normalized trunk entries include an optional `connectionType`. The Asterisk
connector reports `PJSIP` or `SIP` for the endpoint source it can identify.
Connectors that observe BRI, PRI, analog, or another PSTN technology should use
the same field and keep those external connections separate from People.

It also uses AMI's read-only `QueueStatus` action when the AMI user has the
`agent` read permission. The Agent reports queue counts and wait times only;
it does not return caller names or numbers, nor does it add/remove/pause queue
members.

When `ASTERISK_SECURITY_LOG_PATH` is visible, the Agent also turns recent
failed authentication, ACL-block, and malformed-request security events into
aggregate Security Signals. An unavailable trunk remains a Health Signal, not
a Security Signal.

### Grandstream UCM Notes

Grandstream UCM and SoftwareUCM use the dedicated `grandstream.py` connector.
Set `PBXSENSE_PBX_TYPE=grandstream-ucm` (or `grandstream`, `ucm`, or a
UCM-series alias) and configure `GRANDSTREAM_UCM_AMI_*` with a dedicated,
IP-restricted AMI user. The connector defaults to UCM plain AMI port `7777`;
set `GRANDSTREAM_UCM_AMI_TLS=true` to use UCM TLS AMI (default port `5039`).
The UCM web UI exposes AMI under **Value-added Features > AMI**. Grant only the
read privileges required by the Agent:
`system`, `call`, `reporting`, `command`, and `agent`.

Queue visibility uses AMI `QueueStatus`; it is read-only and reports aggregate
wait/member counts, not caller identities. CDR, voicemail, and recording paths
are optional because their UCM locations vary by model and firmware.

The connector tries both modern PJSIP endpoint actions and classic SIP peer
actions. This preserves endpoint visibility on older UCM firmware that does not
offer the PJSIP AMI action.

## Connector Contract

Every runtime connector implements the `PBXConnector` protocol from
`pbxsense_agent/connectors.py`:

```python
class PBXConnector(Protocol):
    name: str
    diagnostics_label: str

    def snapshot(self) -> PbxSnapshot:
        ...

    def diagnostics(self) -> dict:
        ...
```

`snapshot()` is the normal data path. It should return a `PbxSnapshot` with
normalized channels, endpoints, trunks, history evidence, and reachability
state. If the PBX cannot be reached or authentication fails, return a snapshot
with `reachable=False` and a useful error instead of raising into the app layer.

`diagnostics()` is the setup and troubleshooting path. It should return a plain
JSON-compatible dictionary with enough detail to explain which step failed, such
as TCP connection, authentication, command support, or missing configuration.

The historical `AmiSnapshot`, `AmiChannel` and `AmiEndpoint` names remain exact
compatibility aliases; new code should use the neutral observation names.

### Extension Presence

The `people` entries in `GET /home` include an additive `presence` object:

```json
{
  "presence": {
    "state": "do_not_disturb",
    "label": "Do not disturb"
  }
}
```

The supported neutral states are `available`, `on_call`, `busy`, `ringing`,
`away`, `do_not_disturb`, `offline`, and `unknown`. `on_call` takes priority
over a PBX-provided presence state while a live channel exists. Connectors may
provide a raw presence value through `PbxEndpoint.presence`; otherwise the
Agent derives presence from the endpoint device state. Existing `status`,
`statusText`, and `detail` fields remain available for older app versions.
When a non-trunk endpoint transitions from reachable to offline, the Agent may
also include `lastActiveAt` as an ISO 8601 timestamp. It represents the final
healthy Agent observation, not a PBX registration-expiry timestamp. The field
is omitted for online devices and until the Agent has observed a healthy state.

## Add A Connector

1. Create `pbxsense_agent/<pbx_name>.py`.
2. Implement a class with:

```python
class ExampleClient:
    name = "example"
    diagnostics_label = "Example PBX"

    def snapshot(self) -> PbxSnapshot:
        ...

    def diagnostics(self) -> dict:
        ...
```

3. Return `PbxSnapshot` from `snapshot()`.
4. Map active calls to `PbxChannel`.
5. Map people/devices/trunks to `PbxEndpoint`.
6. Keep raw PBX details in diagnostics or `technical` evidence, not the first
   app layer.
7. Register the connector in `connector_for_settings()` in
   `pbxsense_agent/connectors.py`.
8. Add environment variables to `.env.example`.
9. Add installer detection only if the PBX can be detected safely.
10. Add tests for connector selection and at least one mapping example.

## Connector Rules

- Never expose raw PBX events as app feed items.
- Prefer stable IDs and grouped Signals.
- Make diagnostics specific and one tap deeper.
- Fail calmly: unreachable PBX should produce an Agent health Signal, not a
  crash.
- Avoid dependencies when the PBX has a simple TCP or HTTP protocol.
- Keep authentication local, tokenized, and private to LAN/VPN by default.
- Keep connector-specific protocol fields under diagnostics or `technical`
  evidence so the primary app model stays stable.

## Configuration Rules

Add connector settings to `pbxsense_agent/settings.py` and `.env.example`.
Prefer explicit environment variable prefixes for each PBX family:

```text
EXAMPLE_PBX_HOST=127.0.0.1
EXAMPLE_PBX_PORT=1234
EXAMPLE_PBX_USERNAME=pbxsense
EXAMPLE_PBX_PASSWORD=
```

Register the new connector in `connector_for_settings()` and add a
`PBXSENSE_PBX_TYPE` value or alias only when it maps cleanly to one connector.
GUI distribution aliases should resolve to the engine connector unless the GUI
itself becomes a required integration surface.

## FreeSWITCH Notes

The first FreeSWITCH connector uses Event Socket Library over TCP:

```text
FREESWITCH_ESL_HOST=127.0.0.1
FREESWITCH_ESL_PORT=8021
FREESWITCH_ESL_PASSWORD=<event_socket password>
```

The installer tries to read the password from:

```text
/etc/freeswitch/autoload_configs/event_socket.conf.xml
```

If the connector can authenticate, it reads `show channels as json` for live
calls and `show registrations as json` for registered Sofia users. This keeps
idle registered extensions visible in People. Live-channel discovery accepts
only internal Sofia and `user/` legs, so external caller IDs are not presented
as temporary extensions in People. When `mod_callcenter` is loaded,
the connector uses `callcenter_config queue list` and `queue count members` for
read-only waiting counts. These supplemental commands are optional and do not
make the core connector unreachable when unavailable.

Optional history inputs:

```text
FREESWITCH_CDR_JSON_PATH=/var/log/freeswitch
FREESWITCH_VOICEMAIL_PATH=/var/lib/freeswitch/storage/voicemail
```

Those paths are disabled by default because FreeSWITCH CDR and voicemail storage
layout depends on enabled modules and distribution packaging.
Completed CDR is file-backed and is not obtained through ESL. The standard
native Agent installation reads the `mod_json_cdr` output directory directly,
as it does with filesystem history on Asterisk. A remote or containerized Agent
instead needs a read-only mount or synchronized copy. The sample module configuration describes
`log-dir` as a base directory, but builds can write `*.cdr.json` directly into
that directory. Point `FREESWITCH_CDR_JSON_PATH` at whichever directory actually
contains the files; do not assume that a `json_cdr/` child exists.

## Yeastar P-Series Notes

Live snapshots retain their two-second API refresh, while CDR and voicemail
refresh independently at `PBXSENSE_HISTORY_POLL_SECONDS` (30 seconds by default).
An optional history failure retains the last successful records and does not
hide live calls or make Core unavailable. Raw diagnostics expose each history
source's readiness/error and last-success age; cached data is not a fresh read.
Core extension/live-call failures still mark the connector unavailable.
CDR parsing accepts v1 `disposition`/`duration` and v2 `last_status`/`call_duration`.
V2 abandoned calls map to missed calls, with queue evidence when supplied.
`YEASTAR_API_VERSION` still controls the requested API version; firmware support
must be checked before selecting `v2.0`. No automatic firmware/version switch is
performed, and history remains bounded to the latest 1,000 records.

## CUCM Registration Completeness

Schema reference: [Cisco RisPort70 API](https://developer.cisco.com/docs/sxml/risport70-api/).

Phone registration is queried by explicit AXL device names using
`selectCmDeviceExt`, in batches of 200 with a 10,000-device per-collection safety
cap. The method consolidates cross-node registration state. The parser accepts
the documented `CmDevices/item` response as well as legacy `CmDevice` elements.
Missing devices, failed batches and devices beyond the cap remain unknown;
they do not imply offline or recovery. A shared line is reachable if any device
is registered, and confirmed offline only if every device explicitly reports
unregistered/rejected. Total query failure still marks Core unavailable.
Raw diagnostics include registration coverage, missing devices, failed batches
and whether the safety cap was reached. These are bounded observations, not an
unlimited cluster inventory. Unknown evidence does not update last-active time
or confirm phone recovery; an existing confirmed incident stays visible.

## Yeastar Setup

CDR v2 reference: [Yeastar CDR API](https://help.yeastar.com/en/p-series-software-edition/developer-guide/query-cdr-list-v2.html).

The Yeastar connector supports both local P-Series PBXs and P-Series Cloud
Edition through the P-Series OpenAPI. Enable API access under `Integrations >
API`, create a Client ID and Client Secret, and allow the Agent host when IP
restriction is enabled.

```text
PBXSENSE_PBX_TYPE=yeastar
YEASTAR_BASE_URL=https://pbx.example.com
YEASTAR_CLIENT_ID=<client-id>
YEASTAR_CLIENT_SECRET=<client-secret>
```

The connector uses the documented `extension/search`, `call/query`, `cdr/list`,
`vm/query`, `queue/search`, `queue/call_status`, and recording endpoints. It
caches its cloud snapshot briefly while the Agent's central polling pipeline
serves all app and relay consumers. Queue endpoints are optional: permission or
firmware failures omit queue data without hiding extensions and live calls.

## Snapshot Ownership

Connectors are polled only by the Agent's central snapshot task. HTTP `/home`,
WebSocket `/live`, and push processing render or diff that cached observation;
they must never call a connector independently. This preserves transition order
inside the Activity and availability trackers and prevents PBX load from growing
with the number of connected apps.
