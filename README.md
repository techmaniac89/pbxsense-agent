# PBXPulse Agent

The Agent is the first Breeze step: a small service installed near the PBX that
turns PBX observations into PBXPulse concepts.

The app should talk to:

- `GET /home`
- `WS /live`

It should not talk directly to AMI, ESL, ARI, SIP, SSH, or raw logs.

Current connector support:

- Asterisk through AMI.
- FreeSWITCH through Event Socket.
- Mock connector for development.

## Recommended Install

The main installation path is a small Linux service installed near the PBX.
This is the simplest production shape: no Docker knowledge required, the Agent
starts with the machine, and it can auto-detect supported local PBX services.

On the PBX host, or on a small Linux machine that can reach the PBX connector:

```bash
cd PBXPulse
sudo ./agent/scripts/install_linux.sh
```

The installer:

- Installs Python runtime packages when `apt-get` is available.
- Auto-detects Asterisk or FreeSWITCH when possible.
- Lets you choose the PBX connector manually when detection is not enough.
- Prompts for connector credentials when they are not already configured.
- Prompts for the Agent timezone.
- Shows CDR and voicemail path previews so you can adjust them before install.
- Creates `/opt/pbxpulse-agent`.
- Creates a private `pbxpulse` service user.
- Creates `/etc/pbxpulse-agent.env`.
- Generates a local pairing token when one is not provided.
- Backs up `/etc/asterisk/manager.conf`.
- Enables AMI when it is disabled.
- Reuses an existing AMI user when one is already configured.
- Creates a dedicated `pbxpulse` AMI user when one is missing.
- Generates a strong AMI password for that user.
- Restricts the AMI user to localhost by default.
- Reloads Asterisk manager when the local `asterisk` CLI is available.
- Verifies AMI login before starting the Agent.
- Verifies FreeSWITCH Event Socket login when FreeSWITCH is detected.
- Writes a pairing QR SVG to `/var/lib/pbxpulse-agent/pairing.svg`.
- Creates and starts `pbxpulse-agent.service`.

After install, useful commands are:

```bash
systemctl status pbxpulse-agent
journalctl -u pbxpulse-agent -f
```

Open the Agent page:

```text
http://<agent-host>:8765/
```

To pair the app, open:

```text
http://<agent-host>:8765/pair?token=<PBXPULSE_AGENT_TOKEN>
```

The token lives in `/etc/pbxpulse-agent.env`. The installer also creates:

```text
/var/lib/pbxpulse-agent/pairing.svg
```

### Installer Defaults

Set the PBX type explicitly when auto-detection is not enough:

```bash
sudo PBXPULSE_PBX_TYPE=freeswitch ./agent/scripts/install_linux.sh
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
manager user created before PBXPulse can read live PBX state. The official
sample also shows `deny`/`permit` on the manager user, not only under
`[general]`. `permit` must match the host running the PBXPulse Agent. If the
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

The installer prepares a dedicated read-only AMI user only when it cannot find
usable AMI credentials. If an AMI user already exists in `manager.conf`, the
installer reads its `secret` and continues from the connection verification
step. It does not rotate an existing AMI password, and the existing user does
not need to be named `pbxpulse`.

Do not expose AMI to the internet. By default the installer writes:

```text
PBXPULSE_AGENT_MODE=ami
PBXPULSE_DISPLAY_NAME=Asterisk
ASTERISK_AMI_HOST=127.0.0.1
ASTERISK_AMI_PORT=5038
ASTERISK_AMI_USERNAME=pbxpulse
ASTERISK_AMI_PASSWORD=<generated-or-existing-secret>
ASTERISK_CDR_CSV_PATH=/var/log/asterisk/cdr-csv/Master.csv
ASTERISK_VOICEMAIL_PATH=/var/spool/asterisk/voicemail
```

It also writes or updates this AMI section:

```ini
[general]
enabled = yes

[pbxpulse]
secret = <generated-password>
read = system,call,reporting,command
write =
permit = 127.0.0.1/255.255.255.255
```

If the Agent runs from another LAN host, install with:

```bash
sudo ASTERISK_AMI_HOST=192.168.x.x ASTERISK_AMI_PERMIT=192.168.x.x/255.255.255.255 ./agent/scripts/install_linux.sh
```

If the Agent host does not have a stable IP, use the trusted LAN range instead:

```bash
sudo ASTERISK_AMI_HOST=192.168.0.254 ASTERISK_AMI_PERMIT=192.168.0.0/255.255.255.0 ./agent/scripts/install_linux.sh
```

If Asterisk is not installed directly on the same Linux host, set
`PBXPULSE_CONFIGURE_ASTERISK_AMI=0` and prepare AMI in that Asterisk environment.

### FreeSWITCH Defaults

For FreeSWITCH, the installer uses Event Socket:

```text
PBXPULSE_PBX_TYPE=freeswitch
FREESWITCH_ESL_HOST=127.0.0.1
FREESWITCH_ESL_PORT=8021
FREESWITCH_ESL_PASSWORD=<event_socket password>
```

It tries to read the password from:

```text
/etc/freeswitch/autoload_configs/event_socket.conf.xml
```

The first FreeSWITCH connector reads active channels. More FreeSWITCH-specific
history, registration, and voicemail observers should be added as connector
work without changing the app contract.

`PBXPULSE_EXTENSION_NAMES` is optional. PBXPulse first tries to use endpoint
labels from AMI. Keep the mapping only if your PBX exposes numbers without
friendly names, or if you want to rename them for the app.

If your Asterisk writes CDR to another location, change
`ASTERISK_CDR_CSV_PATH` in `/etc/pbxpulse-agent.env`.

## Docker Compose Option

Docker is the secondary deployment option. Use it when the PBX already runs in
Compose, when you prefer container lifecycle management, or when the Agent
should stay separate from the host Python environment.

Create `agent/.env` from the example:

```bash
cd agent
cp .env.example .env
```

Edit `.env` and set:

```text
ASTERISK_AMI_PASSWORD=your-secret
```

Keep the Agent timezone aligned with the PBX:

```text
TZ=Your/Timezone
PBXPULSE_TIMEZONE=Your/Timezone
```

`PBXPULSE_TIMEZONE` is optional. If it is empty, PBXPulse uses `TZ` or the
container's local time. Use an IANA name such as `Europe/Athens`,
`Europe/London`, or `America/New_York`.

Live app refresh uses a one-second cadence by default so endpoint recovery,
active calls, and Home Signals feel current without the app talking to the PBX
directly.

Optionally protect the Agent with a shared local token:

```text
PBXPULSE_AGENT_TOKEN=choose-a-long-random-value
```

When this is set, PBXPulse must be connected with the same token. Leave it empty
only for quick local testing on a trusted network.

To generate a random token into `.env` before creating the container:

```bash
python3 scripts/ensure_token.py .env
```

If your main compose file lives one folder above `PBXPulse`, run it from that
parent folder like this:

```bash
python3 ./PBXPulse/agent/scripts/ensure_token.py ./PBXPulse/agent/.env
```

The script only fills `PBXPULSE_AGENT_TOKEN` when it is empty. It will not rotate
an existing token.

PBXPulse defaults to the official Asterisk filesystem layout:

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
configuration files under the mounted config folder. PBXPulse expects standard
Asterisk behavior, so make sure your Asterisk container has these basics:

```text
/etc/asterisk/manager.conf      AMI enabled and a PBXPulse read user
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

If `agent/docker-compose.yml` lives beside the `asterisk` folder, keep:

```text
ASTERISK_LOGS_HOST_PATH=../asterisk/logs
ASTERISK_SPOOL_HOST_PATH=../asterisk/spool
```

If the PBXPulse Agent compose file is in the same folder as the `asterisk`
folder, change those two host paths to:

```text
ASTERISK_LOGS_HOST_PATH=./asterisk/logs
ASTERISK_SPOOL_HOST_PATH=./asterisk/spool
```

If your main compose file is one folder above `PBXPulse` and also contains the
`asterisk` folder, use `agent/docker-compose.parent-example.yml` as the shape for
the PBXPulse service. In that layout the important paths are:

```yaml
build:
  context: ./PBXPulse/agent
env_file:
  - ./PBXPulse/agent/.env
volumes:
  - ./asterisk/logs:/var/log/asterisk:ro
  - ./asterisk/spool:/var/spool/asterisk:ro
```

`PBXPULSE_EXTENSION_NAMES` is optional. PBXPulse first tries to use endpoint
labels from AMI. Keep the mapping only if your PBX exposes numbers without
friendly names, or if you want to rename them for the app.

Keep all PBXPulse/Asterisk values in `.env`. The Dockerfile only sets Python
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

If `PBXPULSE_AGENT_TOKEN` is set, local browser visits to `localhost` or
`127.0.0.1` unlock with an HTTP-only browser cookie. The real Agent token is not
added to local page links.

Remote LAN access still needs the token:

```text
http://<agent-host>:8765/pair?token=your-token
```

The QR contains a `pbxpulse://pair?...` payload with the Agent URL and token.
PBXPulse setup can scan this QR and fill the Agent URL and token automatically.

## GitHub Release Assets

Keep build scripts in the repository, but attach built installers to GitHub
Releases instead of committing them.

Recommended release asset layout:

```text
agent/dist/
  PBXPulseAgent-0.1.54-beta-debian-i386.deb
  PBXPulseAgent-0.1.54-beta-debian-amd64.deb
  PBXPulseAgent-0.1.54-beta-debian-arm64.deb
  PBXPulseAgent-0.1.54-beta-linux-source-installer.tar.gz
```

Create the Linux release packages from a Linux release host and attach the
generated files from `agent/dist/`.

The Debian packages install the Agent under `/opt/pbxpulse-agent`, create the
systemd service, preserve `/etc/pbxpulse-agent.env`, and create the Python
virtual environment on the target machine. The source-installer archive is for
non-Debian Linux systems or manual installs.

For a release tag such as `agent-v0.1.54-beta`, attach the matching files from
`agent/dist/`. The GitHub Release notes should include the Agent version, the
supported PBX connectors, upgrade notes, and any installer changes.

## Development Mode

Use mock mode only for local app or Agent development:

```bash
cd agent
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
PBXPULSE_AGENT_MODE=mock \
  uvicorn pbxpulse_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

Open:

```text
http://127.0.0.1:8765/home
```

To run against AMI without installing a service:

```bash
cd agent
. .venv/bin/activate
PBXPULSE_AGENT_MODE=ami \
ASTERISK_AMI_HOST=127.0.0.1 \
ASTERISK_AMI_PORT=5038 \
ASTERISK_AMI_USERNAME=pbxpulse \
ASTERISK_AMI_PASSWORD=your-secret \
  uvicorn pbxpulse_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

## Troubleshooting AMI

If `/home` says PBXPulse is trying to reach Asterisk, open:

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
docker compose exec pbxpulse-agent sh -lc 'python - <<PY
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
docker compose exec pbxpulse-agent sh -lc 'python - <<PY
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

The compose file defines two named PBXPulse volumes:

```yaml
pbxpulse-agent-data:/var/lib/pbxpulse-agent
pbxpulse-agent-logs:/var/log/pbxpulse-agent
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
[pbxpulse]
secret = your-secret
read = system,call,reporting,command
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
- Produces `/home` in the existing Breeze contract shape.
- Streams periodic `home_snapshot` events over `/live`.
- Keeps raw AMI fields inside `technical`, one layer deeper.

This is enough to test real data while preserving the PBXPulse philosophy:
Signals first, raw Asterisk second.
