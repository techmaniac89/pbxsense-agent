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

```text
PBX connector
  -> channels, endpoints, trunks, extension presence, history evidence
  -> Pulse snapshot
  -> Signals
  -> App
```

## Existing Connectors

| PBX | Connector | Status |
| --- | --- | --- |
| Asterisk | `ami.py` | Active calls, endpoints, trunks, queue wait/member state, CDR history, voicemail |
| FreePBX, Issabel, VitalPBX | `ami.py` | Supported as Asterisk-based systems |
| Grandstream UCM / SoftwareUCM | `grandstream.py` | Restricted AMI with UCM port/TLS defaults, live calls, endpoints, trunks, queues; optional local history paths |
| FreeSWITCH | `freeswitch.py` | Event Socket connection, registered extensions, active channels, optional mod_callcenter queue counts and JSON CDR/voicemail paths |
| FusionPBX | `freeswitch.py` | Supported as a FreeSWITCH-based system |
| Yeastar P-Series | `yeastar.py` | OAuth API, extension status, live calls, queue waiting status, CDR, voicemail, recordings |
| Mock | `mock.py` | Development/test fixture |

GUI PBX distributions are handled through the PBX engine underneath them.
FreePBX, Issabel, and VitalPBX still expose Asterisk AMI. FusionPBX still uses
FreeSWITCH Event Socket. Their web interfaces do not need separate connectors
unless PBXSense later wants distribution-specific settings, provisioning, or
dashboard metadata.

The Asterisk connector reads PJSIP endpoints and also asks for classic
`chan_sip` peers when that AMI action is available.

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

    def snapshot(self) -> AmiSnapshot:
        ...

    def diagnostics(self) -> dict:
        ...
```

`snapshot()` is the normal data path. It should return an `AmiSnapshot` with
normalized channels, endpoints, trunks, history evidence, and reachability
state. If the PBX cannot be reached or authentication fails, return a snapshot
with `reachable=False` and a useful error instead of raising into the app layer.

`diagnostics()` is the setup and troubleshooting path. It should return a plain
JSON-compatible dictionary with enough detail to explain which step failed, such
as TCP connection, authentication, command support, or missing configuration.

The names `AmiSnapshot`, `AmiChannel`, and `AmiEndpoint` are historical from the
first Asterisk connector. Treat them as the Agent's current neutral snapshot
shape until the internal model is renamed.

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
provide a raw presence value through `AmiEndpoint.presence`; otherwise the
Agent derives presence from the endpoint device state. Existing `status`,
`statusText`, and `detail` fields remain available for older app versions.

## Add A Connector

1. Create `pbxsense_agent/<pbx_name>.py`.
2. Implement a class with:

```python
class ExampleClient:
    name = "example"
    diagnostics_label = "Example PBX"

    def snapshot(self) -> AmiSnapshot:
        ...

    def diagnostics(self) -> dict:
        ...
```

3. Return `AmiSnapshot` from `snapshot()`.
4. Map active calls to `AmiChannel`.
5. Map people/devices/trunks to `AmiEndpoint`.
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
idle registered extensions visible in People. When `mod_callcenter` is loaded,
the connector uses `callcenter_config queue list` and `queue count members` for
read-only waiting counts. These supplemental commands are optional and do not
make the core connector unreachable when unavailable.

Optional history inputs:

```text
FREESWITCH_CDR_JSON_PATH=/var/log/freeswitch/json_cdr
FREESWITCH_VOICEMAIL_PATH=/var/lib/freeswitch/storage/voicemail
```

Those paths are disabled by default because FreeSWITCH CDR and voicemail storage
layout depends on enabled modules and distribution packaging.

## Yeastar P-Series Notes

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
