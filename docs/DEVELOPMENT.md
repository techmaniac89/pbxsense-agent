# PBXPulse Agent Development

This repository contains the PBXPulse Agent service. It is a FastAPI app that
normalizes PBX data for the PBXPulse app.

## Local Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Run in mock mode:

```bash
PBXPULSE_AGENT_MODE=mock uvicorn pbxpulse_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

Open:

```text
http://127.0.0.1:8765/home
```

## Running Against Asterisk

```bash
. .venv/bin/activate
PBXPULSE_AGENT_MODE=ami \
ASTERISK_AMI_HOST=127.0.0.1 \
ASTERISK_AMI_PORT=5038 \
ASTERISK_AMI_USERNAME=pbxpulse \
ASTERISK_AMI_PASSWORD=your-secret \
  uvicorn pbxpulse_agent.main:app --host 0.0.0.0 --port 8765 --reload
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
pbxpulse_agent/
  main.py          FastAPI routes, pairing, diagnostics, live WebSocket
  settings.py      Environment parsing and PBX type normalization
  connectors.py    Connector protocol and connector selection
  ami.py           Asterisk AMI connector
  freeswitch.py    FreeSWITCH Event Socket connector
  mock.py          Development fixture connector
  pulse.py         PBXPulse Home payload and signal generation
  history.py       CDR and voicemail evidence readers
  live.py          Live event diffing
  version.py       Agent version
scripts/
  install_linux.sh Linux service installer
  ensure_token.py  Token generator
tests/
  test_pulse.py    Mapping and signal tests
```

## App Contract

The PBXPulse app should consume the Agent, not PBX internals:

```text
GET /home
WS  /live
GET /pair
GET /diagnostics
```

The app should not talk directly to AMI, ESL, ARI, SIP, SSH, or raw PBX logs.

## Adding Connectors

Read `docs/CONNECTORS.md` before adding a connector. The short version:

- Implement the `PBXConnector` protocol.
- Return the current neutral snapshot types from `pbxpulse_agent/pulse.py`.
- Keep raw PBX details inside diagnostics or `technical` evidence.
- Register the connector in `connector_for_settings()`.
- Add settings to `pbxpulse_agent/settings.py` and `.env.example`.
- Add focused tests for connector selection and mapping.

## Release Artifacts

Generated release files belong in `dist/` locally and should be attached to
GitHub Releases instead of committed.

Expected release asset names look like:

```text
dist/
  PBXPulseAgent-<version>-linux-source-installer.tar.gz
```

Release notes should include supported connectors, upgrade notes, and installer
changes.
