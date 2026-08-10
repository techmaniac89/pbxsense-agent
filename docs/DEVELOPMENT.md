# PBXSense Agent Development

This repository contains the PBXSense Agent service. It is a FastAPI app that
normalizes PBX data for the PBXSense app.

## Local Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Run in mock mode:

```bash
PBXSENSE_AGENT_MODE=mock uvicorn pbxsense_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

Open:

```text
http://127.0.0.1:8765/home
```

## Running Against Asterisk

```bash
. .venv/bin/activate
PBXSENSE_AGENT_MODE=ami \
ASTERISK_AMI_HOST=127.0.0.1 \
ASTERISK_AMI_PORT=5038 \
ASTERISK_AMI_USERNAME=pbxsense \
ASTERISK_AMI_PASSWORD=your-secret \
  uvicorn pbxsense_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

## Running Tests

The current test suite uses Python `unittest`:

```bash
python -m unittest discover -s tests
```

Run a single test module:

```bash
python -m unittest tests.test_pulse
```

## Project Layout

```text
pbxsense_agent/
  main.py          FastAPI routes, pairing, diagnostics, live WebSocket
  settings.py      Environment parsing and PBX type normalization
  connectors.py    Connector protocol and connector selection
  ami.py           Asterisk AMI connector
  freeswitch.py    FreeSWITCH Event Socket connector
  mock.py          Development fixture connector
  pulse.py         PBXSense Home payload and signal generation
  history.py       CDR and voicemail evidence readers
  live.py          Live event diffing
  version.py       Agent version
scripts/
  setup_docker.sh  Interactive Docker connector setup and startup
  install_common.sh Shared Linux service setup
  install_debian.sh Debian/Ubuntu/Raspberry Pi OS installer entry point
  install_fedora.sh Fedora/RHEL-family installer entry point
  ensure_token.py  Token generator
tests/
  test_pulse.py    Mapping and signal tests
```

## App Contract

The PBXSense app should consume the Agent, not PBX internals:

```text
GET /home
WS  /live
GET /pair
GET /diagnostics
GET /recordings/{recording-id}
POST /push/devices
GET /push/devices/status
POST /push/devices/revoke
```

The app should not talk directly to AMI, ESL, ARI, SIP, SSH, or raw PBX logs.

## Runtime Data Flow

`main.py` owns one central snapshot task. It polls the selected connector once,
enriches Asterisk-family snapshots with local history, advances signal/activity
trackers once, and stores an immutable observation. `/home`, every `/live`
client, and the relay publisher consume that cached state. Do not introduce PBX
polling inside request or WebSocket handlers; doing so can reorder transitions
and makes connector load proportional to connected clients.

`/live` emits a small `heartbeat` event every ten seconds when no PBX data has
changed. The app uses it only as transport liveness; without it, a quiet PBX can
look stale even while WebSocket ping/pong remains healthy.

Feed Signal IDs stay stable for UI updates. Interruptive outage Signals also
carry an occurrence-scoped `notificationId`. Relay idempotency and Android
notification tags use that occurrence so local and FCM copies collapse while a
genuine later outage can notify again.

### Phone-availability notification contract

Per-device Health Signals remain visible and diagnosable in the feed. Push
delivery applies a separate correlation policy so a temporary shared outage on
a large PBX does not generate dozens of notifications:

- hold newly confirmed phone outages for a 15-second correlation window;
- notify one or two affected phones individually;
- correlate three or more recently affected phones into one incident;
- update the same Android notification no more than once every 30 seconds;
- suppress per-phone outage and recovery pushes while the PBX or Agent
  connection itself is unavailable;
- require 15 continuous healthy seconds before sending one grouped recovery;
- keep the completed incident in a two-minute cooldown before starting a new
  episode.

Message wording follows the current affected count. Shared network/PBX wording
is valid only while at least three phones remain unavailable. When the incident
drops to two or one phone, use remaining-phone wording such as **1 phone still
looks unavailable** and explain that the other affected phones recovered. Never
show **A shared network or PBX interruption may be affecting 1 phone**.

Grouped updates use unique event IDs for relay idempotency and one stable
notification tag for Android replacement. The grouped recovery uses that same
tag so it replaces the outage notification instead of stacking beside it.

The relay presence heartbeat is a separate task. It must remain independent of
PBX snapshot, history, and signal failures so a slow connector cannot create a
false Agent-lost notification.

The optional Secure Internet Relay runs as another independent outbound task.
Keep its command allowlist explicit and bounded. Home data uses a separate
per-device encrypted envelope; the app-held X25519 private key must never be
sent to the Agent or relay. Any new relayed field must remain inside that
envelope and pass the projection/privacy tests. Diagnostics, recordings, and
PBX control remain outside the Internet Relay contract.

## Adding Connectors

Read `docs/CONNECTORS.md` before adding a connector. The short version:

- Implement the `PBXConnector` protocol.
- Return the current neutral snapshot types from `pbxsense_agent/pulse.py`.
- Keep raw PBX details inside diagnostics or `technical` evidence.
- Register the connector in `connector_for_settings()`.
- Add settings to `pbxsense_agent/settings.py` and `.env.example`.
- Add focused tests for connector selection and mapping.

## Release Artifacts

Generated release files belong in `dist/` locally and should be attached to
GitHub Releases instead of committed.

Expected release asset names look like:

```text
dist/
  PBXSenseAgent-<version>-linux-source-installer.tar.gz
```

Release notes should include supported connectors, upgrade notes, and installer
changes.
