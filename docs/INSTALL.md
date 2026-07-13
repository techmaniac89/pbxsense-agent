# PBXSense Agent Install Guide

This guide covers the supported ways to run PBXSense Agent near a PBX.

Use the Linux service installer for most production deployments. Use Docker
Compose when the PBX is already containerized or when container lifecycle
management is preferred. Use development mode only for local testing.

## Linux Service Install

Run the installer on the PBX host, or on a small Linux machine that can reach
the PBX connector.

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
- Lets you confirm `asterisk`, `grandstream`, `freeswitch`, `yeastar`, or `mock` mode interactively.
- Prompts for timezone, Agent port, and connector timeout.
- Prompts for AMI, ESL, or Yeastar API credentials and keeps existing values on reinstall.
- Suggests Asterisk CDR CSV, voicemail, and recording paths from common local locations.
- Reuses a readable Asterisk `manager.conf` user secret or FreeSWITCH Event
  Socket password as a default when it can find one.
- Creates `/opt/pbxsense-agent`.
- Creates a private `pbxsense` service user.
- Creates `/etc/pbxsense-agent.env` from `.env.example` when missing.
- On upgrades, adds missing non-secret defaults without replacing existing
  administrator values or credentials.
- Generates `PBXSENSE_AGENT_TOKEN` when missing.
- Creates and starts `pbxsense-agent.service`.
- Runs Uvicorn on `0.0.0.0:8765` by default.

The installer writes Agent settings only. It does not edit PBX server
configuration, so AMI, ESL, or Yeastar API access must still be enabled and permitted on the
PBX side.

After install, review the environment file for the target PBX:

```bash
sudo nano /etc/pbxsense-agent.env
sudo systemctl restart pbxsense-agent
```

Useful service commands:

```bash
systemctl status pbxsense-agent
journalctl -u pbxsense-agent -f
```

Open the Agent:

```text
http://<agent-host>:8765/
```

Pair the app:

```text
http://<agent-host>:8765/pair?token=<PBXSENSE_AGENT_TOKEN>
```

After the first app enrolls the Agent with the push relay, the same protected
page changes to **Add another app**. Scan its QR on each additional phone. The
Agent installation and relay identity remain shared, while every app registers
its own FCM device and notification preferences.

The protected Agent status page also includes **Paired apps**. It shows the
apps registered with this Agent, including app version, platform, device model,
OS version, notification preferences, and last registration time. Push tokens
are never displayed. Older app registrations show unavailable metadata as
**Not reported** until that app registers again.

The token lives in:

```text
/etc/pbxsense-agent.env
```

## Linux Service Uninstall

Remove the systemd service and installed application files:

```bash
sudo sh ./scripts/uninstall_linux.sh
```

By default, the uninstaller removes `/etc/pbxsense-agent.env` so future
installer runs start with fresh choices. It preserves:

```text
/var/lib/pbxsense-agent
/var/log/pbxsense-agent
```

To remove the service, installed files, local data, logs, and the `pbxsense`
service user:

```bash
sudo sh ./scripts/uninstall_linux.sh --purge
```

## Asterisk Install Notes

Asterisk uses AMI. For a local PBX host, the common defaults are:

```text
PBXSENSE_PBX_TYPE=asterisk
PBXSENSE_AGENT_MODE=ami
PBXSENSE_DISPLAY_NAME=Asterisk
ASTERISK_AMI_HOST=127.0.0.1
ASTERISK_AMI_PORT=5038
ASTERISK_AMI_USERNAME=pbxsense
ASTERISK_AMI_PASSWORD=<secret>
ASTERISK_CDR_CSV_PATH=/var/log/asterisk/cdr-csv/Master.csv
ASTERISK_VOICEMAIL_PATH=/var/spool/asterisk/voicemail
ASTERISK_RECORDINGS_PATH=/var/spool/asterisk/monitor
```

AMI should be enabled in `/etc/asterisk/manager.conf` and restricted to the
Agent host:

```ini
[pbxsense]
secret = <secret>
read = system,call,reporting,command,agent
write =
permit = 127.0.0.1/255.255.255.255
```

If the Agent runs on another LAN host, set `ASTERISK_AMI_HOST` to the PBX IP and
permit only the Agent host or a trusted private subnet. Never expose AMI to the
internet.

When `/etc/asterisk/manager.conf` is readable, the installer can use the first
manager section with a `secret` as the default AMI username/password prompt. It
does not create, rotate, or edit AMI users.

GUI distributions such as FreePBX, Issabel, and VitalPBX use the Asterisk
connector.

## Grandstream UCM / SoftwareUCM

Use `PBXSENSE_PBX_TYPE=grandstream-ucm` when installing the Agent near a
Grandstream UCM. The installer prompts for UCM-specific AMI configuration,
defaulting to port `7777` (or `5039` for TLS). In the UCM web UI, create the
AMI user under **Value-added Features > AMI**, permit only the Agent's IP
address, and grant read privileges for `system`, `call`, `reporting`, `command`,
and `agent`. The `agent` privilege enables read-only queue counts. Do not expose
AMI outside the trusted LAN or VPN.

## FreeSWITCH Install Notes

FreeSWITCH uses Event Socket:

```text
PBXSENSE_PBX_TYPE=freeswitch
PBXSENSE_AGENT_MODE=freeswitch
PBXSENSE_DISPLAY_NAME=FreeSWITCH
FREESWITCH_ESL_HOST=127.0.0.1
FREESWITCH_ESL_PORT=8021
FREESWITCH_ESL_PASSWORD=<event_socket password>
FREESWITCH_CDR_JSON_PATH=
FREESWITCH_VOICEMAIL_PATH=
FREESWITCH_RECORDINGS_PATH=
```

The standard password location is:

```text
/etc/freeswitch/autoload_configs/event_socket.conf.xml
```

When that file is readable, the installer can use its password value as the
default ESL password prompt. It does not edit FreeSWITCH configuration.

FusionPBX uses the FreeSWITCH connector.

Set `FREESWITCH_CDR_JSON_PATH` only when `mod_json_cdr` writes local JSON CDR
files visible to the Agent. Set `FREESWITCH_VOICEMAIL_PATH` only when
FreeSWITCH voicemail metadata files are visible to the Agent.

The connector reads registered Sofia users with `show registrations as json`,
so idle registered phones remain visible in People. If `mod_callcenter` is
loaded, it also reads queue names and waiting counts through
`callcenter_config`. Missing `mod_callcenter` support does not make the
connector unhealthy; queue data is simply omitted.

## Yeastar P-Series Install Notes

Set `PBXSENSE_PBX_TYPE=yeastar` in the installer and provide the PBX base URL,
Client ID, and Client Secret. For a cloud PBX use its Yeastar FQDN; for a local
PBX use its HTTP(S) management URL. Enable the API in `Integrations > API` and,
when IP restriction is enabled, allow the Agent host.

```text
PBXSENSE_PBX_TYPE=yeastar
PBXSENSE_AGENT_MODE=yeastar
PBXSENSE_DISPLAY_NAME=Yeastar P-Series
YEASTAR_BASE_URL=https://pbx.example.com
YEASTAR_CLIENT_ID=<client-id>
YEASTAR_CLIENT_SECRET=<client-secret>
YEASTAR_API_VERSION=v1.0
YEASTAR_VERIFY_TLS=true
```

Use `YEASTAR_VERIFY_TLS=false` only for a trusted self-signed local PBX
certificate. Yeastar recordings are retrieved through the Agent; no recording
filesystem path or Yeastar access token is exposed to the app.

Queue waiting counts require API access to `queue/search` and
`queue/call_status`. If those endpoints are unavailable on the installed
firmware or denied to the API client, other Yeastar data remains available and
queues are omitted.

## Docker Compose Install

Create `.env`:

```bash
cp .env.example .env
python3 scripts/ensure_token.py .env
```

Edit `.env` and set the connector credentials.

Start the Agent:

```bash
docker compose up -d --build
```

Rebuilding or upgrading with this command preserves the named data volume and
`/var/lib/pbxsense-agent/relay_identity.json`, so registered apps remain linked
to the Agent. The Compose project name is fixed to `pbxsense-agent`, making the
volume stable even if the source folder is renamed. Never use `docker compose
down -v` during an upgrade; `-v` deletes the relay identity.

To back up the identity before moving hosts:

```bash
docker compose exec -T pbxsense-agent \
  sh -c 'cat /var/lib/pbxsense-agent/relay_identity.json' \
  > relay_identity.json.backup
chmod 600 relay_identity.json.backup
```

Treat this backup as a secret. Restoring it to the same path and ownership on a
replacement Agent reconnects that installation to its existing relay apps.

Open:

```text
http://127.0.0.1:8765/home
http://127.0.0.1:8765/pair
```

The default compose file uses `network_mode: host` so a container running on the
PBX host can reach local AMI at `127.0.0.1:5038`.

If Asterisk is on another LAN host, use the LAN override and set
`ASTERISK_AMI_HOST` in `.env`:

```bash
docker compose -f docker-compose.yml -f docker-compose.lan.yml up --build
```

## Docker Volume Paths

The compose file mounts Asterisk logs and spool read-only:

```text
ASTERISK_LOGS_HOST_PATH=../asterisk/logs
ASTERISK_SPOOL_HOST_PATH=../asterisk/spool
```

If this repository is in the same folder as the `asterisk` folder, keep those
defaults. If the Agent compose file is in the same folder as the `asterisk`
folder, use:

```text
ASTERISK_LOGS_HOST_PATH=./asterisk/logs
ASTERISK_SPOOL_HOST_PATH=./asterisk/spool
```

For an Agent container, the Agent should still use the container-visible paths:

```text
ASTERISK_CDR_CSV_PATH=/var/log/asterisk/cdr-csv/Master.csv
ASTERISK_VOICEMAIL_PATH=/var/spool/asterisk/voicemail
```

If your Asterisk distribution writes custom CDR CSV, use:

```text
ASTERISK_CDR_CSV_PATH=/var/log/asterisk/cdr-custom/Master.csv
```

For a normal host-installed Agent watching an Asterisk container, use the Docker
host bind-mount paths instead, such as:

```text
ASTERISK_CDR_CSV_PATH=/path/to/asterisk/logs/cdr-csv/Master.csv
ASTERISK_VOICEMAIL_PATH=/path/to/asterisk/spool/voicemail
```

## Parent Compose Layout

If a parent folder owns the main compose file and contains both `pbxsense-agent`
and `asterisk`, use `docker-compose.parent-example.yml` as the service shape.
The important paths are:

```yaml
build:
  context: ./pbxsense-agent
env_file:
  - ./pbxsense-agent/.env
volumes:
  - ./asterisk/logs:/var/log/asterisk:ro
  - ./asterisk/spool:/var/spool/asterisk:ro
```

## Local Development Run

Use mock mode for local development:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
PBXSENSE_AGENT_MODE=mock uvicorn pbxsense_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

Run against local AMI without installing the service:

```bash
. .venv/bin/activate
PBXSENSE_AGENT_MODE=ami \
ASTERISK_AMI_HOST=127.0.0.1 \
ASTERISK_AMI_PORT=5038 \
ASTERISK_AMI_USERNAME=pbxsense \
ASTERISK_AMI_PASSWORD=your-secret \
  uvicorn pbxsense_agent.main:app --host 0.0.0.0 --port 8765 --reload
```
