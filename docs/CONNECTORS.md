# PBXPulse Agent Connectors

PBXPulse Agent is open source so PBX support should be easy to extend without
changing the PBXPulse app.

A connector observes one PBX family and translates it into PBXPulse concepts.
The app should not know whether the source is Asterisk, FreeSWITCH, 3CX, CUCM,
or something else.

Connectors live inside this agent repository under `pbxpulse_agent/`. They are
responsible for PBX-specific access, authentication, parsing, and diagnostics.
Everything they return should already be shaped for the Agent engine, not for a
specific vendor UI or raw protocol feed.

```text
PBX connector
  -> channels, endpoints, trunks, history evidence
  -> Pulse snapshot
  -> Signals
  -> App
```

## Existing Connectors

| PBX | Connector | Status |
| --- | --- | --- |
| Asterisk | `ami.py` | Active calls, endpoints, trunks, CDR history, voicemail |
| FreePBX, Issabel, VitalPBX | `ami.py` | Supported as Asterisk-based systems |
| FreeSWITCH | `freeswitch.py` | Event Socket connection and active channels |
| FusionPBX | `freeswitch.py` | Supported as a FreeSWITCH-based system |
| Mock | `mock.py` | Development/test fixture |

GUI PBX distributions are handled through the PBX engine underneath them.
FreePBX, Issabel, and VitalPBX still expose Asterisk AMI. FusionPBX still uses
FreeSWITCH Event Socket. Their web interfaces do not need separate connectors
unless PBXPulse later wants distribution-specific settings, provisioning, or
dashboard metadata.

The Asterisk connector reads PJSIP endpoints and also asks for classic
`chan_sip` peers when that AMI action is available.

## Connector Contract

Every runtime connector implements the `PBXConnector` protocol from
`pbxpulse_agent/connectors.py`:

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

## Add A Connector

1. Create `pbxpulse_agent/<pbx_name>.py`.
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
   `pbxpulse_agent/connectors.py`.
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

Add connector settings to `pbxpulse_agent/settings.py` and `.env.example`.
Prefer explicit environment variable prefixes for each PBX family:

```text
EXAMPLE_PBX_HOST=127.0.0.1
EXAMPLE_PBX_PORT=1234
EXAMPLE_PBX_USERNAME=pbxpulse
EXAMPLE_PBX_PASSWORD=
```

Register the new connector in `connector_for_settings()` and add a
`PBXPULSE_PBX_TYPE` value or alias only when it maps cleanly to one connector.
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

If the connector can authenticate, it reads `show channels as json` and maps
live calls into the same app model used by Asterisk.
