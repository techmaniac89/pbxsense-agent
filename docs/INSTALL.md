# PBXPulse Agent Install Guide

This guide covers the supported ways to run PBXPulse Agent near a PBX.

Use the Linux service installer for most production deployments. Use Docker
Compose when the PBX is already containerized or when container lifecycle
management is preferred. Use development mode only for local testing.

## Linux Service Install

Run the installer on the PBX host, or on a small Linux machine that can reach
the PBX connector.

```bash
cd pbxpulse-agent
sudo sh ./scripts/install_linux.sh
```

If the folder was copied from Windows to Linux, the scripts may arrive as
`664`. Running them with `sh` works without needing the executable bit. Release
archives preserve executable modes.

The installer:

- Installs Python runtime packages when `apt-get` is available.
- Auto-detects local Asterisk or FreeSWITCH files and commands when possible.
- Lets you confirm `asterisk`, `freeswitch`, or `mock` mode interactively.
- Prompts for timezone, Agent port, and connector timeout.
- Prompts for AMI or ESL credentials and keeps existing values on reinstall.
- Suggests Asterisk CDR CSV and voicemail paths from common local locations.
- Reuses a readable Asterisk `manager.conf` user secret or FreeSWITCH Event
  Socket password as a default when it can find one.
- Creates `/opt/pbxpulse-agent`.
- Creates a private `pbxpulse` service user.
- Creates `/etc/pbxpulse-agent.env` from `.env.example` when missing.
- Generates `PBXPULSE_AGENT_TOKEN` when missing.
- Creates and starts `pbxpulse-agent.service`.
- Runs Uvicorn on `0.0.0.0:8765` by default.

The installer writes Agent settings only. It does not edit Asterisk or
FreeSWITCH server configuration, so AMI/ESL must still be enabled and permitted
on the PBX side.

After install, review the environment file for the target PBX:

```bash
sudo nano /etc/pbxpulse-agent.env
sudo systemctl restart pbxpulse-agent
```

Useful service commands:

```bash
systemctl status pbxpulse-agent
journalctl -u pbxpulse-agent -f
```

Open the Agent:

```text
http://<agent-host>:8765/
```

Pair the app:

```text
http://<agent-host>:8765/pair?token=<PBXPULSE_AGENT_TOKEN>
```

The token lives in:

```text
/etc/pbxpulse-agent.env
```

## Linux Service Uninstall

Remove the systemd service and installed application files:

```bash
sudo sh ./scripts/uninstall_linux.sh
```

By default, the uninstaller removes `/etc/pbxpulse-agent.env` so future
installer runs start with fresh choices. It preserves:

```text
/var/lib/pbxpulse-agent
/var/log/pbxpulse-agent
```

To remove the service, installed files, local data, logs, and the `pbxpulse`
service user:

```bash
sudo sh ./scripts/uninstall_linux.sh --purge
```

## Asterisk Install Notes

Asterisk uses AMI. For a local PBX host, the common defaults are:

```text
PBXPULSE_PBX_TYPE=asterisk
PBXPULSE_AGENT_MODE=ami
PBXPULSE_DISPLAY_NAME=Asterisk
ASTERISK_AMI_HOST=127.0.0.1
ASTERISK_AMI_PORT=5038
ASTERISK_AMI_USERNAME=pbxpulse
ASTERISK_AMI_PASSWORD=<secret>
ASTERISK_CDR_CSV_PATH=/var/log/asterisk/cdr-csv/Master.csv
ASTERISK_VOICEMAIL_PATH=/var/spool/asterisk/voicemail
```

AMI should be enabled in `/etc/asterisk/manager.conf` and restricted to the
Agent host:

```ini
[pbxpulse]
secret = <secret>
read = system,call,reporting,command
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

## FreeSWITCH Install Notes

FreeSWITCH uses Event Socket:

```text
PBXPULSE_PBX_TYPE=freeswitch
PBXPULSE_AGENT_MODE=freeswitch
PBXPULSE_DISPLAY_NAME=FreeSWITCH
FREESWITCH_ESL_HOST=127.0.0.1
FREESWITCH_ESL_PORT=8021
FREESWITCH_ESL_PASSWORD=<event_socket password>
```

The standard password location is:

```text
/etc/freeswitch/autoload_configs/event_socket.conf.xml
```

When that file is readable, the installer can use its password value as the
default ESL password prompt. It does not edit FreeSWITCH configuration.

FusionPBX uses the FreeSWITCH connector.

## Docker Compose Install

Create `.env`:

```bash
cp .env.example .env
python3 scripts/ensure_token.py .env
```

Edit `.env` and set the connector credentials.

Start the Agent:

```bash
docker compose up --build
```

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

If a parent folder owns the main compose file and contains both `pbxpulse-agent`
and `asterisk`, use `docker-compose.parent-example.yml` as the service shape.
The important paths are:

```yaml
build:
  context: ./pbxpulse-agent
env_file:
  - ./pbxpulse-agent/.env
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
PBXPULSE_AGENT_MODE=mock uvicorn pbxpulse_agent.main:app --host 0.0.0.0 --port 8765 --reload
```

Run against local AMI without installing the service:

```bash
. .venv/bin/activate
PBXPULSE_AGENT_MODE=ami \
ASTERISK_AMI_HOST=127.0.0.1 \
ASTERISK_AMI_PORT=5038 \
ASTERISK_AMI_USERNAME=pbxpulse \
ASTERISK_AMI_PASSWORD=your-secret \
  uvicorn pbxpulse_agent.main:app --host 0.0.0.0 --port 8765 --reload
```
