# PBXSense Agent

PBXSense Agent is the local bridge between a phone system and the PBXSense app.
It runs near the PBX, observes PBX state through the safest available connector,
and exposes a small PBXSense-shaped API that the app can consume without knowing
PBX-specific protocols.

The Agent keeps PBX integration concerns in one place. The app talks to the
Agent; the Agent talks to Asterisk, FreeSWITCH, Yeastar P-Series, or a development mock connector.
This keeps AMI, ESL, SIP details, filesystem paths, and distro-specific quirks
out of the user-facing PBXSense experience.

## What It Does

- Reads current PBX state from a supported connector.
- Converts raw PBX observations into PBXSense Home data, Signals, Tips, and
  technical details.
- Reports extension presence in People, including available, on-call, busy,
  ringing, away, DND, and offline states when the connector can observe them.
- Shows Asterisk queue pressure, including callers waiting, longest wait, and
  available, busy, or paused queue members.
- Groups recent PBX authentication failures and blocked ACL attempts into
  privacy-preserving Security Signals when the local security log is visible.
- Streams live Home snapshots so the app can refresh without polling the PBX
  directly.
- Serves pairing pages and QR payloads for connecting PBXSense to the local
  Agent.
- Provides diagnostics for connector setup, especially Asterisk AMI.
- Supports production service installs, Docker Compose installs, and local
  development mode.

The app should only talk to these Agent surfaces:

- `GET /home`
- `WS /live`
- `GET /pair`
- `GET /diagnostics` and connector-specific diagnostics when troubleshooting
- `GET /recordings/{recording-id}` for a recording attached to a returned call

The app should not talk directly to AMI, ESL, ARI, SIP, SSH, or raw PBX logs.

## Supported Connectors

- Asterisk through AMI.
- FreeSWITCH through Event Socket.
- Yeastar P-Series through its OAuth-protected OpenAPI.
- Grandstream UCM through its restricted Asterisk Manager Interface (AMI).
- Mock connector for local development and UI testing.

GUI PBX distributions are mapped to their underlying PBX engine:

- FreePBX, Issabel, and VitalPBX use the Asterisk connector.
- FusionPBX uses the FreeSWITCH connector.
- Grandstream UCM and SoftwareUCM use the dedicated UCM AMI connector.

## Usage Overview

Most deployments should use the Linux service installer. It installs the Agent
under `/opt/pbxsense-agent`, creates a systemd service, prepares
`/etc/pbxsense-agent.env`, auto-detects the likely PBX connector, prompts for
connector settings, and generates a local pairing token when one is not already
configured.

```bash
sudo sh ./scripts/install_linux.sh
```

Docker Compose is available when the PBX is already containerized or when the
Agent should be managed as a container:

```bash
cp .env.example .env
docker compose up --build
```

For local development, use mock mode:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
PBXSENSE_AGENT_MODE=mock uvicorn pbxsense_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

After the Agent is running, open:

```text
http://127.0.0.1:8765/home
```

For pairing, open:

```text
http://127.0.0.1:8765/pair
```

If `PBXSENSE_AGENT_TOKEN` is configured, LAN browser visits can open the Agent
page directly. The pairing page still embeds the token in the `pbxsense://`
payload for the app:

```text
http://<agent-host>:8765/pair?token=<PBXSENSE_AGENT_TOKEN>
```

## Configuration

The Agent is configured through environment variables. The most important ones
are:

- `PBXSENSE_PBX_TYPE`: `asterisk`, `grandstream`, `freeswitch`, `yeastar`, or `mock`.
- `PBXSENSE_AGENT_MODE`: connector mode; normally `ami`, `freeswitch`, `yeastar`, or `mock`.
- `PBXSENSE_DISPLAY_NAME`: friendly name shown by the Agent.
- `PBXSENSE_TIMEZONE`: IANA timezone used for timestamps and history.
- `PBXSENSE_AGENT_TOKEN`: optional shared token for pairing and remote access.
- `ASTERISK_AMI_*`: Asterisk AMI host, port, username, password, and timeout.
- `FREESWITCH_ESL_*`: FreeSWITCH Event Socket host, port, and password.
- `ASTERISK_CDR_CSV_PATH`: Asterisk CDR CSV path for call history.
- `ASTERISK_VOICEMAIL_PATH`: Asterisk voicemail spool path.
- `ASTERISK_RECORDINGS_PATH`: Asterisk MixMonitor recording root.
- `ASTERISK_SECURITY_LOG_PATH`: Asterisk security log for aggregate security Signals.
- `FREESWITCH_RECORDINGS_PATH`: optional FreeSWITCH recording root.
- `YEASTAR_*`: P-Series API base URL and client credentials.

Use `.env.example` as the starting point for Docker and development installs.
Linux service installs write the final environment file to:

```text
/etc/pbxsense-agent.env
```

## Repository Layout

- `pbxsense_agent/`: FastAPI app, connector adapters, live stream, settings, and
  PBXSense signal generation.
- `scripts/`: installer and helper scripts.
- `packaging/`: package metadata and release packaging support.
- `tests/`: automated tests for Agent behavior.
- `dist/`: generated release artifacts; keep built packages attached to GitHub
  Releases instead of committing new generated assets.

## Documentation

- `docs/INSTALL.md`: production service, Docker, and local run instructions.
- `docs/CONFIGURATION.md`: environment variables, defaults, aliases, and tokens.
- `docs/CONNECTORS.md`: connector contract and extension guidance.
- `docs/TROUBLESHOOTING.md`: diagnostics, AMI/ESL failures, pairing, and history.
- `docs/DEVELOPMENT.md`: local setup, tests, project layout, and release notes.
- `SECURITY.md`: network boundaries, credentials, tokens, and service hardening.

## Recommended Install

The main installation path is a small Linux service installed near the PBX.
This is the simplest production shape: no Docker knowledge required, the Agent
starts with the machine, and the installer helps fill the root-owned
environment file.

On the PBX host, or on a small Linux machine that can reach the PBX connector:

```bash
cd pbxsense-agent
sudo sh ./scripts/install_linux.sh
```

If the folder was copied from Windows to Linux, the scripts may arrive as
`664`. Running them with `sh` works without needing the executable bit. Release
archives preserve executable modes.

The installer:

- Installs Python runtime packages when `apt-get` is available.
- Auto-detects local Asterisk or FreeSWITCH files and commands when possible.
- Lets you confirm `asterisk`, `freeswitch`, `yeastar`, or `mock` mode interactively.
- Prompts for timezone, Agent port, and connector timeout.
- Prompts for AMI, ESL, or Yeastar API credentials and preserves existing values on reinstall.
- Suggests Asterisk CDR CSV, voicemail, and recording paths from common local locations.
- Reuses a readable Asterisk `manager.conf` user secret or FreeSWITCH Event
  Socket password as a default when it can find one.
- Creates `/opt/pbxsense-agent`.
- Creates a private `pbxsense` service user.
- Creates `/etc/pbxsense-agent.env`.
- Generates a local pairing token when one is not provided.
- Creates a Python virtual environment and installs `requirements.txt`.
- Copies the Agent code, scripts, docs, compose examples, and support files.
- Creates and starts `pbxsense-agent.service`.

The installer writes Agent settings only. It does not edit PBX server
configuration, so AMI, ESL, or Yeastar API access must still be enabled and permitted on the
PBX side.

After install, review `/etc/pbxsense-agent.env`. If you change connector
credentials, timezone, or file paths, restart the service.

After install, useful commands are:

```bash
systemctl status pbxsense-agent
journalctl -u pbxsense-agent -f
```

To uninstall the Linux service and installed app files:

```bash
sudo sh ./scripts/uninstall_linux.sh
```

This also removes `/etc/pbxsense-agent.env`, so the installer does not reuse
saved choices on the next install. Use `--purge` to also remove local data,
logs, and the `pbxsense` service user.

Open the Agent page:

```text
http://<agent-host>:8765/
```

To pair the app, open:

```text
http://<agent-host>:8765/pair?token=<PBXSENSE_AGENT_TOKEN>
```

The token lives in `/etc/pbxsense-agent.env`.

### Installer Defaults

Set the PBX type before install if you want to skip auto-detection and force a
connector mode:

```bash
sudo PBXSENSE_PBX_TYPE=freeswitch sh ./scripts/install_linux.sh
```

Supported values today:

```text
asterisk
freeswitch
mock
```

### Asterisk Defaults

Official Asterisk installs are conservative. The sample `manager.conf` ships
with AMI disabled:

```ini
[general]
enabled = no
;webenabled = yes
port = 5038
bindaddr = 0.0.0.0
```

In practice this means a fresh Asterisk system usually needs AMI enabled and a
manager user created before PBXSense can read live PBX state. The official
sample also shows `deny`/`permit` on the manager user, not only under
`[general]`. `permit` must match the host running the PBXSense Agent. If the
Agent runs on the PBX itself, localhost is enough:

```ini
deny = 0.0.0.0/0.0.0.0
permit = 127.0.0.1/255.255.255.255
```

If the Agent runs elsewhere on the LAN, permit that Agent host or a trusted LAN
range. For example, this allows any host on `192.168.0.x` to try AMI login:

```ini
deny = 0.0.0.0/0.0.0.0
permit = 192.168.0.0/255.255.255.0
```

Prefer a single Agent host permit when the Agent has a stable IP. Use a subnet
permit only when the Agent IP can move or the deployment is managed inside a
trusted private LAN/VPN. Never expose AMI to the internet.

The installer does not edit Asterisk configuration. Prepare AMI in Asterisk,
then put the connection values in `/etc/pbxsense-agent.env`.

Do not expose AMI to the internet. A typical Agent environment looks like:

```text
PBXSENSE_AGENT_MODE=ami
PBXSENSE_DISPLAY_NAME=Asterisk
ASTERISK_AMI_HOST=127.0.0.1
ASTERISK_AMI_PORT=5038
ASTERISK_AMI_USERNAME=pbxsense
ASTERISK_AMI_PASSWORD=<secret>
ASTERISK_CDR_CSV_PATH=/var/log/asterisk/cdr-csv/Master.csv
ASTERISK_VOICEMAIL_PATH=/var/spool/asterisk/voicemail
ASTERISK_SECURITY_LOG_PATH=/var/log/asterisk/security
```

Create or verify an AMI section like this in Asterisk:

```ini
[general]
enabled = yes

[pbxsense]
secret = <secret>
read = system,call,reporting,command,agent
write =
permit = 127.0.0.1/255.255.255.255
```

If the Agent runs from another LAN host, set the AMI host in
`/etc/pbxsense-agent.env`:

```text
ASTERISK_AMI_HOST=192.168.x.x
```

Then configure Asterisk `permit` for that Agent host or trusted LAN/VPN range.

### FreeSWITCH Defaults

For FreeSWITCH, configure the Agent to use Event Socket:

```text
PBXSENSE_PBX_TYPE=freeswitch
FREESWITCH_ESL_HOST=127.0.0.1
FREESWITCH_ESL_PORT=8021
FREESWITCH_ESL_PASSWORD=<event_socket password>
FREESWITCH_CDR_JSON_PATH=
FREESWITCH_VOICEMAIL_PATH=
```

Read the password from your FreeSWITCH configuration and place it in
`/etc/pbxsense-agent.env`. The standard location is:

```text
/etc/freeswitch/autoload_configs/event_socket.conf.xml
```

The FreeSWITCH connector reads active channels through ESL. Optional local JSON
CDR and voicemail metadata paths can add history and voicemail evidence when
those FreeSWITCH modules/files are available.

### GUI PBX Distributions

PBXSense connects to the PBX engine, not to the web GUI. FreePBX, Issabel, and
VitalPBX are treated as Asterisk systems and use the AMI connector. FusionPBX is
treated as a FreeSWITCH system and uses Event Socket. Set
`PBXSENSE_PBX_TYPE=asterisk`, `grandstream`, or `freeswitch`; the aliases
`freepbx`, `issabel`, `vitalpbx`, `grandstream-ucm`, `ucm6300`, and `fusionpbx`
are accepted too.

The main thing that can differ between GUI distributions is filesystem layout:
CDR CSV location, voicemail spool location, and whether the GUI has already
created an AMI/ESL user. The Asterisk connector reads PJSIP endpoints and also
asks AMI for classic `chan_sip` peers when available, which helps older
FreePBX-style systems. If history or voicemail is missing, check `/diagnostics`
and adjust `ASTERISK_CDR_CSV_PATH` or `ASTERISK_VOICEMAIL_PATH`.

`PBXSENSE_EXTENSION_NAMES` is optional. PBXSense first tries to use endpoint
labels from AMI. Keep the mapping only if your PBX exposes numbers without
friendly names, or if you want to rename them for the app.

If your Asterisk writes CDR to another location, change
`ASTERISK_CDR_CSV_PATH` in `/etc/pbxsense-agent.env`.

### Grandstream UCM

Grandstream UCM and SoftwareUCM run Asterisk and expose a restricted AMI
integration. Use the dedicated UCM connector, which defaults to UCM's AMI port
`7777` instead of generic Asterisk's `5038`:

```text
PBXSENSE_PBX_TYPE=grandstream-ucm
GRANDSTREAM_UCM_AMI_HOST=<ucm-lan-address>
GRANDSTREAM_UCM_AMI_PORT=7777
GRANDSTREAM_UCM_AMI_USERNAME=<ucm-ami-user>
GRANDSTREAM_UCM_AMI_PASSWORD=<ucm-ami-password>
```

In the UCM web UI, create a dedicated AMI user under **Value-added Features >
AMI**, restrict its permitted IPs to the Agent host (or a trusted private
subnet), and grant only the read privileges needed by PBXSense:

```text
system,call,reporting,command,agent
```

The `agent` privilege allows read-only queue visibility, including how many
callers are waiting. For UCM TLS, set `GRANDSTREAM_UCM_AMI_TLS=true`; its
documented default TLS port is `5039`. Keep certificate verification on unless
the local UCM certificate is known to be self-signed. UCM recording and CDR
paths vary by model and firmware, so configure history/recordings only after
confirming the files are locally visible to the Agent.

## Docker Compose Option

Docker is the secondary deployment option. Use it when the PBX already runs in
Compose, when you prefer container lifecycle management, or when the Agent
should stay separate from the host Python environment.

Create `.env` from the example:

```bash
cp .env.example .env
```

Edit `.env` and set:

```text
ASTERISK_AMI_PASSWORD=your-secret
```

Keep the Agent timezone aligned with the PBX:

```text
TZ=Your/Timezone
PBXSENSE_TIMEZONE=Your/Timezone
```

`PBXSENSE_TIMEZONE` is optional. If it is empty, PBXSense uses `TZ` or the
container's local time. Use an IANA name such as `Europe/Athens`,
`Europe/London`, or `America/New_York`.

Live app refresh uses a one-second cadence by default so endpoint recovery,
active calls, and Home Signals feel current without the app talking to the PBX
directly.

Optionally protect the Agent with a shared local token:

```text
PBXSENSE_AGENT_TOKEN=choose-a-long-random-value
```

When this is set, PBXSense must be connected with the same token. Leave it empty
only for quick local testing on a trusted network.

To generate a random token into `.env` before creating the container:

```bash
python3 scripts/ensure_token.py .env
```

If your main compose file lives one folder above `pbxsense-agent`, run it from
that parent folder like this:

```bash
python3 ./pbxsense-agent/scripts/ensure_token.py ./pbxsense-agent/.env
```

The script only fills `PBXSENSE_AGENT_TOKEN` when it is empty. It will not rotate
an existing token.

PBXSense defaults to the official Asterisk filesystem layout:

```text
ASTERISK_CDR_CSV_PATH=/var/log/asterisk/cdr-csv/Master.csv
ASTERISK_VOICEMAIL_PATH=/var/spool/asterisk/voicemail
```

For the Asterisk Docker layout below:

```yaml
volumes:
  - ./asterisk/logs:/var/log/asterisk
  - ./asterisk/spool:/var/spool/asterisk
```

use:

```text
ASTERISK_CDR_CSV_PATH=/var/log/asterisk/cdr-csv/Master.csv
ASTERISK_VOICEMAIL_PATH=/var/spool/asterisk/voicemail
```

Some distributions write to `/var/log/asterisk/cdr-custom/Master.csv` instead.
Use that path only if your mounted `./asterisk/logs` folder actually contains
`cdr-custom/Master.csv`.

### Asterisk Docker Notes

The `andrius/asterisk` image can be intentionally empty until you provide
configuration files under the mounted config folder. PBXSense expects standard
Asterisk behavior, so make sure your Asterisk container has these basics:

```text
/etc/asterisk/manager.conf      AMI enabled and a PBXSense read user
/etc/asterisk/cdr.conf          CDR enabled
/etc/asterisk/cdr_csv.conf      CSV CDR backend enabled
/etc/asterisk/pjsip.conf        PJSIP endpoints/trunks, or chan_sip if used
/etc/asterisk/extensions.conf   Dialplan/IVR/ring groups
/etc/asterisk/voicemail.conf    Only if voicemail is used
```

Official-style CDR CSV normally appears at:

```text
./asterisk/logs/cdr-csv/Master.csv
```

If that file does not appear after calls, enable/load the Asterisk CDR CSV
backend in the Asterisk container before expecting Insights and Tips from call
history.

If this `pbxsense-agent` repository lives beside the `asterisk` folder, keep:

```text
ASTERISK_LOGS_HOST_PATH=../asterisk/logs
ASTERISK_SPOOL_HOST_PATH=../asterisk/spool
```

If the PBXSense Agent compose file is in the same folder as the `asterisk`
folder, change those two host paths to:

```text
ASTERISK_LOGS_HOST_PATH=./asterisk/logs
ASTERISK_SPOOL_HOST_PATH=./asterisk/spool
```

If your main compose file is one folder above `pbxsense-agent` and also contains
the `asterisk` folder, use `docker-compose.parent-example.yml` as the shape for
the PBXSense service. In that layout the important paths are:

```yaml
build:
  context: ./pbxsense-agent
env_file:
  - ./pbxsense-agent/.env
volumes:
  - ./asterisk/logs:/var/log/asterisk:ro
  - ./asterisk/spool:/var/spool/asterisk:ro
```

`PBXSENSE_EXTENSION_NAMES` is optional. PBXSense first tries to use endpoint
labels from AMI. Keep the mapping only if your PBX exposes numbers without
friendly names, or if you want to rename them for the app.

Keep all PBXSense/Asterisk values in `.env`. The Dockerfile only sets Python
runtime defaults such as unbuffered logging.

Then start the Agent:

```bash
docker compose up --build
```

Open:

```text
http://127.0.0.1:8765/home
```

To pair the app, open the Agent pairing page:

```text
http://127.0.0.1:8765/pair
```

If `PBXSENSE_AGENT_TOKEN` is set, requests from localhost, private LAN, or VPN
client IPs are treated as trusted for Agent HTTP pages, JSON endpoints, and
`/live`. Browser HTML pages also receive an HTTP-only cookie, and the real Agent
token is not added to normal page links.

The pairing page still embeds the token in the QR payload so the app can store
it for non-LAN or stricter future access:

```text
http://<agent-host>:8765/pair?token=your-token
```

The QR contains a `pbxsense://pair?...` payload with the Agent URL and token.
PBXSense setup can scan this QR and fill the Agent URL and token automatically.

## GitHub Release Assets

Keep build scripts in the repository, but attach built installers to GitHub
Releases instead of committing them.

Recommended release asset layout:

```text
dist/
  PBXSenseAgent-0.2.9-beta-linux-source-installer.tar.gz
```

Create the Linux release packages from a Linux release host and attach the
generated files from `dist/`.

The source-installer archive includes the Agent code, docs, install script, and
uninstall script. It installs under `/opt/pbxsense-agent`, creates the systemd
service, writes `/etc/pbxsense-agent.env`, and creates the Python virtual
environment on the target machine.

For a release tag such as `agent-v0.2.9-beta`, attach the matching files from
`dist/`. The GitHub Release notes should include the Agent version, the
supported PBX connectors, upgrade notes, and any installer changes.

## Development Mode

Use mock mode only for local app or Agent development:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
PBXSENSE_AGENT_MODE=mock \
  uvicorn pbxsense_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

Open:

```text
http://127.0.0.1:8765/home
```

To run against AMI without installing a service:

```bash
. .venv/bin/activate
PBXSENSE_AGENT_MODE=ami \
ASTERISK_AMI_HOST=127.0.0.1 \
ASTERISK_AMI_PORT=5038 \
ASTERISK_AMI_USERNAME=pbxsense \
ASTERISK_AMI_PASSWORD=your-secret \
  uvicorn pbxsense_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

## Troubleshooting AMI

If `/home` says PBXSense is trying to reach Asterisk, open:

```text
http://127.0.0.1:8765/diagnostics/ami
```

Read the result like this:

- `tcpConnected: false`: the Agent cannot reach `ASTERISK_AMI_HOST:ASTERISK_AMI_PORT`.
- `bannerReceived: false`: TCP connected, but AMI did not send its greeting.
- `loginAccepted: false`: AMI answered, but username/password or AMI permissions are wrong.

On the host running the Agent, also check:

```bash
docker compose logs -f
docker compose exec pbxsense-agent sh -lc 'python - <<PY
import os, socket
host=os.environ["ASTERISK_AMI_HOST"]
port=int(os.environ["ASTERISK_AMI_PORT"])
print("checking", host, port)
socket.create_connection((host, port), timeout=3).close()
print("tcp ok")
PY'
```

If diagnostics say `AMI banner timed out`, TCP is open but the Agent did not
receive AMI's greeting. The Agent will still try to log in, because some
deployments may not send a useful banner. Check what the port sends:

```bash
docker compose exec pbxsense-agent sh -lc 'python - <<PY
import os, socket
host=os.environ["ASTERISK_AMI_HOST"]
port=int(os.environ["ASTERISK_AMI_PORT"])
with socket.create_connection((host, port), timeout=3) as sock:
    sock.settimeout(3)
    print(sock.recv(200).decode("utf-8", errors="replace"))
PY'
```

A real AMI socket should start with something like `Asterisk Call Manager`.

### Volumes

The compose file defines two named PBXSense volumes:

```yaml
pbxsense-agent-data:/var/lib/pbxsense-agent
pbxsense-agent-logs:/var/log/pbxsense-agent
```

Agent v1 is mostly stateless, but these give the deployment stable
places for future pairing tokens, local cache, snapshots, or file logs. Current
runtime logs still go to Docker stdout, so use:

```bash
docker compose logs -f
```

The compose file also mounts `/etc/localtime` read-only so timestamps follow the
host timezone.

It also mounts the Asterisk log and spool folders read-only. For the current
Asterisk Docker setup, that gives the Agent access to:

```text
/var/log/asterisk/cdr-custom/Master.csv
/var/spool/asterisk/voicemail
```

### Network Mode

`docker-compose.yml` uses `network_mode: host` so a container running on the PBX
host can reach local AMI at `127.0.0.1:5038`.

If Asterisk is on another LAN host, use the LAN override and set:

```text
ASTERISK_AMI_HOST=192.168.x.x
```

Then run:

```bash
docker compose -f docker-compose.yml -f docker-compose.lan.yml up --build
```

Keep AMI private to the LAN or VPN.

## Minimal Asterisk AMI User

The exact AMI permissions depend on the PBX distribution, but Agent v1 needs to
log in and read channel/endpoint status. A starting point looks like:

```ini
[pbxsense]
secret = your-secret
read = system,call,reporting,command,agent
write =
permit = 127.0.0.1/255.255.255.255
```

If the Agent runs on another LAN host, replace `permit` with that host's IP.
Restart or reload AMI after changing Asterisk manager configuration.

## Current V1 Scope

Agent v1 intentionally starts small:

- Reads active channels with `CoreShowChannels`.
- Reads PJSIP endpoints with `PJSIPShowEndpoints`.
- Tries to infer extension display names from AMI endpoint fields.
- Produces `/home` in the PBXSense app contract shape.
- Streams periodic `home_snapshot` events over `/live`.
- Keeps raw AMI fields inside `technical`, one layer deeper.

This is enough to test real data while preserving the PBXSense philosophy:
Signals first, raw PBX second.
