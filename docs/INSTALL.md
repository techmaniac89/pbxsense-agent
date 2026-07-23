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
sudo sh ./scripts/install_debian.sh
```

For Fedora, RHEL, Rocky Linux, AlmaLinux, or another `dnf`-based distribution:

```bash
cd pbxsense-agent
sudo sh ./scripts/install_fedora.sh
```

The Fedora installer installs `python3`, `python3-pip`, `python3-devel`, and
`gcc`, then runs the shared PBXSense configuration and systemd setup. It does
not alter `firewalld`; allow the configured Agent port only from trusted app or
management networks when remote LAN access is required.

If the folder was copied from Windows to Linux, the scripts may arrive as
`664`. Running them with `sh` works without needing the executable bit. Release
archives preserve executable modes.

Both distribution-specific installers:

- Install Python runtime packages through `apt-get` or `dnf`.
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
- Prints the complete authenticated admin URL when installation finishes.
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

Open the authenticated link printed at the end of installation on the
administrator's PC. The browser receives a long-lived HttpOnly authorization
that renews on use and remains until browser site data is cleared or the Agent
token changes. If automatic host detection is unsuitable, run the installer as
`sudo PBXSENSE_ACCESS_HOST=<LAN-IP-or-hostname> sh ./scripts/install_debian.sh`
(or use `install_fedora.sh`).

The underlying Agent address is:

```text
http://<agent-host>:8765/
```

The explicit token-bearing pairing URL remains available for troubleshooting:

```text
http://<agent-host>:8765/pair?token=<PBXSENSE_AGENT_TOKEN>
```

After the first app enrolls the Agent with the push relay, the same protected
page changes to **Add another app**. Scan its QR on each additional phone. The
Agent installation and relay identity remain shared, while every app registers
its own FCM device, notification preferences, encryption key, and relay access
credential.

Closed-app notifications need only `PBXSENSE_RELAY_URL`. Encrypted Home
snapshots are available by default but remain disabled in each app until the
user enables Internet Relay while pairing. To prohibit the feature for the
whole Agent installation, set this and restart it:

```env
PBXSENSE_INTERNET_RELAY_ENABLED=false
```

The app still needs LAN/VPN access for pairing, diagnostics, recordings, and
the one-second live WebSocket experience. Internet Relay is a fifteen-second
sanitized Home fallback, not a public Agent endpoint.

The protected Agent status page also includes **Paired apps**. It shows the
apps registered with this Agent, including app version, platform, device model,
OS version, notification preferences, last registration time, and recent secure
Internet Relay presence. **Connected now** means that app contacted the secure
relay within the last 90 seconds; local-only traffic cannot be attributed to an
individual registration. Push tokens are never displayed. Older app
registrations show unavailable metadata as **Not reported** until that app
registers again.

Each card has **Remove app**. After browser confirmation, the Agent revokes
only that app's push and Internet Relay device registration. The removed app
must scan a fresh pairing QR before it can register with this Agent again.

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

## Cisco CUCM Install Notes

Use `PBXSENSE_PBX_TYPE=cucm` and configure a dedicated read-only CUCM
application user with AXL and Serviceability access. The Agent connects to the
Publisher over HTTPS port 8443, uses AXL for phone/line inventory, and uses
RisPort70 for current registration presence.

```text
PBXSENSE_PBX_TYPE=cucm
PBXSENSE_AGENT_MODE=cucm
CUCM_HOST=cucm-publisher.example.com
CUCM_USERNAME=pbxsense-readonly
CUCM_PASSWORD=<application-user password>
CUCM_AXL_VERSION=15.0
CUCM_VERIFY_TLS=true
CUCM_CDR_PATH=/var/lib/pbxsense-agent/cucm/cdr
CUCM_CMR_PATH=/var/lib/pbxsense-agent/cucm/cmr
CUCM_JTAPI_ENABLED=false
CUCM_JTAPI_CLASSPATH=/opt/pbxsense-agent/vendor/jtapi/*
```

Enable the Cisco AXL Web Service and Cisco RIS Data Collector services. Import
the CUCM certificate authority into the Agent host trust store; disabling TLS
verification is intended only for temporary diagnosis.

Configure CUCM CDR Management to deliver CDR and CMR CSV files to an SFTP
inbox exposed at the configured paths. PBXSense reads files already present in
those directories; it does not provide or configure the SFTP server. Completed
calls and media quality then appear in history.

To enable live calls, download the Cisco JTAPI Client plugin from this CUCM
cluster, copy all supplied jar files to `/opt/pbxsense-agent/vendor/jtapi/`,
and set `CUCM_JTAPI_ENABLED=true`. The JTAPI application user needs **Standard
CTI Enabled** and the monitored phones assigned as controlled devices. A Java
8 runtime is required by Cisco's CUCM 14/15 compatibility matrix; the Linux
installer installs the distribution's headless runtime when JTAPI is enabled,
and the Docker image includes Java 8. For Compose, place the
jars under `./vendor/jtapi/`. Do not copy JTAPI jars from a different CUCM
release because Cisco couples the client plugin to the cluster version.

Cisco currently documents Java 8 for CUCM 14 and 15 JTAPI clients. The bundled
bridge bytecode targets Java 8. Cisco's downloadable Linux libraries are x86
32/64-bit, so run a JTAPI-enabled Agent container/service on a supported x86
host rather than a Raspberry Pi/ARM host. Core AXL/RisPort and CDR/CMR support
can still run on the Raspberry Pi with JTAPI disabled.

Vendor references: [Install Plugins](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/admin/12_5_1/systemConfig/cucm_b_system-configuration-guide-1251/cucm_b_system-configuration-guide-1251_chapter_0110001.html),
[JTAPI/UCM compatibility](https://developer.cisco.com/site/jtapi/jtapi-ucm-compatibility-matrix/),
and [supported JVM versions](https://developer.cisco.com/site/jtapi/cisco-unified-jtapi-supported-jvm-versions/).

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

Run the interactive Docker setup wizard:

```bash
sh ./scripts/setup_docker.sh
```

It checks Docker Compose, creates or preserves `.env`, generates the Agent
token, and presents the same connector-specific questions as the native Linux
installers. It then offers to build and start the Agent. Existing administrator
values remain the defaults when the wizard is run again.

If you choose not to start it in the wizard, run:

```bash
docker compose --env-file .env -f docker/docker-compose.yml \
  -f docker/docker-compose.asterisk.yml up -d --build
```

The example above is for Asterisk. The wizard prints the exact command for the
selected connector. For a manual install, use the matching connector command:

```bash
# FreeSWITCH / FusionPBX
docker compose --env-file .env -f docker/docker-compose.yml \
  -f docker/docker-compose.freeswitch.yml up -d --build

# Grandstream UCM
docker compose --env-file .env -f docker/docker-compose.yml \
  -f docker/docker-compose.grandstream.yml up -d --build

# CUCM
docker compose --env-file .env -f docker/docker-compose.yml \
  -f docker/docker-compose.cucm.yml up -d --build

# Yeastar or mock (API/generated data; no PBX filesystem mount)
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
```

The Docker wizard prints the authenticated PC link when it finishes. Override
automatic address detection by running it with
`PBXSENSE_ACCESS_HOST=<LAN-IP-or-hostname> sh ./scripts/setup_docker.sh`.

Rebuilding or upgrading with this command preserves the named data volume and
`/var/lib/pbxsense-agent/relay_identity.json`, so registered apps remain linked
to the Agent. The Compose project name is fixed to `pbxsense-agent`, making the
volume stable even if the source folder is renamed. Never add `down -v` to the
Compose command during an upgrade; `-v` deletes the relay identity.

To back up the identity before moving hosts:

```bash
docker compose --env-file .env -f docker/docker-compose.yml \
  exec -T pbxsense-agent \
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

These examples use the default port. If `PBXSENSE_AGENT_PORT` is changed, the
Docker listener, health check, LAN override mapping, and setup-wizard link all
use that configured value.

The default compose file uses `network_mode: host` so a container running on the
PBX host can reach local AMI at `127.0.0.1:5038`.

If Asterisk is on another LAN host, use the LAN override and set
`ASTERISK_AMI_HOST` in `.env`:

```bash
docker compose --env-file .env -f docker/docker-compose.yml \
  -f docker/docker-compose.lan.yml up --build
```

When Asterisk filesystem history is also needed, combine all three files:

```bash
docker compose --env-file .env -f docker/docker-compose.yml \
  -f docker/docker-compose.asterisk.yml \
  -f docker/docker-compose.lan.yml up --build
```

The LAN override publishes `PBXSENSE_AGENT_PORT` on the same host and container
port. Docker Compose reads this value from the project `.env` file.

## Docker Volume Paths

Connector overrides mount their PBX files read-only. The common
`docker/docker-compose.yml` contains only Agent data/log volumes and creates no
connector-specific host directories.

For Asterisk:

```text
ASTERISK_LOGS_HOST_PATH=../../asterisk/logs
ASTERISK_SPOOL_HOST_PATH=../../asterisk/spool
```

For FreeSWITCH/FusionPBX, `FREESWITCH_FILES_HOST_PATH` is a root containing
`cdr/`, `voicemail/`, and `recordings/`:

```text
FREESWITCH_FILES_HOST_PATH=../freeswitch
```

For Grandstream UCM, `GRANDSTREAM_UCM_FILES_HOST_PATH` is a root containing
`cdr/Master.csv`, `voicemail/`, `recordings/`, and optionally `security/`:

```text
GRANDSTREAM_UCM_FILES_HOST_PATH=../grandstream
```

CUCM uses the separate history and JTAPI paths documented in the CUCM section.
All connector mounts are optional operational inputs; use the common Compose
file alone when the selected connector does not need local files.

If this repository is in the same folder as the `asterisk` folder, keep those
defaults. If the Agent compose file is in the same folder as the `asterisk`
folder, use:

```text
ASTERISK_LOGS_HOST_PATH=../asterisk/logs
ASTERISK_SPOOL_HOST_PATH=../asterisk/spool
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
and `asterisk`, use `docker/docker-compose.parent-example.yml` as the service shape.
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
