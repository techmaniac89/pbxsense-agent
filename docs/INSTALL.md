# PBXSense Agent Install Guide

## Authorize a new PC

A new browser now shows an authorization page instead of a raw token error.
On an already-authorized PC, open Agent home and choose **Authorize another
browser**, then **Create access code**. Share the code only with someone who
should have full administrator access. On the new PC, open `/session` and enter
the code over private HTTPS or a loopback SSH tunnel.

For an SSH tunnel, run `ssh -L 8765:127.0.0.1:8765 user@agent-host` on the new PC,
then open `http://localhost:8765/session` while the tunnel is running. Substitute
your server username/host. Plain LAN HTTP shows guidance but never accepts a
code by default. The existing installer setup links still work over protected transport.

### Optional trusted-LAN HTTP (Agent 0.6.40-beta)

No reverse proxy is required. Customers who deliberately accept unencrypted
administrator access on a trusted private LAN can set:

```dotenv
PBXSENSE_TRUSTED_LAN_HTTP=true
```

The native/Docker setup wizard offers this option, disabled by default, and
prints a LAN setup link when enabled without TLS. Existing installations can
add it to `.env` (Docker) or `/etc/pbxsense-agent.env` (native). Generate a fresh
browser setup code using `python3 scripts/ensure_token.py .env` from the source
folder (substitute the native env path if applicable). Recreate Docker using
the same Compose files/options as usual; restarting alone does not load changed
environment values. Restart the native service after changing its env file.
If a custom Compose file lists environment variables individually instead of
using `env_file`, include the new variable there too.

Within 15 minutes, open `http://<Agent-LAN-IP>:8765/session` and enter the new
`PBXSENSE_BROWSER_BOOTSTRAP_TOKEN` value, not `PBXSENSE_AGENT_TOKEN`. Use your
configured port if different. Codes remain single-use. An already-authorized
browser can instead create a code through **Authorize another browser**.

Only RFC1918 IPv4 and IPv6 ULA peer addresses qualify for the HTTP opt-in;
public, link-local and reserved/documentation addresses remain blocked. The page
shows an explicit warning. HTTP setup codes AND subsequent admin cookies can be
intercepted by anyone able to observe the network. Never port-forward this
Agent or publish it through an Internet-facing proxy; a private proxy peer is
not proof that its downstream users are private. Restrict access at the firewall.
Turning the option off prevents new LAN-HTTP authorization, but does not revoke
previously issued browser cookies. Clear site data or rotate the administrator
credential when responding to a suspected compromise. This setting is browser
administration only: paired apps, API credentials and release-app TLS rules do
not change.

Codes work once, expire after 15 minutes and are invalidated by an Agent restart.
After authorization, the browser keeps the existing installation-lived session.
If no authorized browser remains, the server administrator can rerun native
installation or Docker setup for a fresh short-lived setup link. This does not
require sharing or changing the long-lived `PBXSENSE_AGENT_TOKEN`.

This guide covers the supported ways to run PBXSense Agent near a PBX.

Keep `/var/lib/pbxsense-agent` persistent across updates and container recreation.
Agent 0.6.39-beta adds `daily_summary.sqlite3` there alongside existing identity
and app state. Losing it does not remove pairing, but resets daily Moment/volume
learning; a fresh mid-day install cannot certify a complete day. A preserved
database retains counts, while a long stop still invalidates coverage.

Use the Linux service installer for most production deployments. Use Docker
Compose when the PBX is already containerized or when container lifecycle
management is preferred. Use development mode only for local testing.

## Linux Service Install

Run the installer on the PBX host, or on a small Linux machine that can reach
the PBX connector.

Download the current archive and checksum from the repository's latest GitHub
Release, verify it, and enter the extracted directory:

```bash
curl -fLO https://github.com/techmaniac89/pbxsense-agent/releases/latest/download/PBXSenseAgent-0.6.47-beta-linux-source-installer.tar.gz
curl -fLO https://github.com/techmaniac89/pbxsense-agent/releases/latest/download/SHA256SUMS.txt
sha256sum --check --ignore-missing SHA256SUMS.txt
tar -xzf PBXSenseAgent-0.6.47-beta-linux-source-installer.tar.gz
cd PBXSenseAgent-0.6.47-beta-linux-source-installer
```

The checksum command must report `OK` before installation. On a machine where
the repository was cloned or copied directly, start from its root instead.

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
- Auto-detect local Asterisk or FreeSWITCH files and commands when possible.
- Lets you confirm `asterisk`, `grandstream`, `freeswitch`, `yeastar`, or `mock` mode interactively.
- Prompts for timezone, Agent port, and connector timeout.
- Prompts for AMI, ESL, or Yeastar API credentials and keeps existing values on reinstall.
- Offers detected Asterisk/FreeSWITCH CDR, voicemail and recording paths, with manual entry under an advanced choice.
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

Open the setup link printed at the end of installation. It contains a separate,
single-use browser credential that expires after 15 minutes; the durable Agent
token is not printed. The credential is carried in a URL fragment, removed from
browser history, and exchanged for a long-lived HttpOnly authorization. Without
TLS the link uses `127.0.0.1` and must be opened on the Agent host. For setup from
another private LAN or VPN device, configure native or reverse-proxy HTTPS and
`PBXSENSE_AGENT_PUBLIC_URL` first.

The underlying Agent address is:

```text
http://<agent-host>:8765/
```

After browser authorization, open the pairing page without a query credential:

```text
http://<agent-host>:8765/pair
```

Normal Agent HTTP and WebSocket routes reject query-string tokens. Native apps
authenticate with the Bearer or `X-PBXSense-Token` header obtained from the
custom-scheme pairing QR.

Those HTTP examples are for debug-app LAN development. Production/release apps
require HTTPS/WSS for direct LAN or VPN access. Provide a certificate and key
readable by the `pbxsense` service, then configure:

```env
PBXSENSE_AGENT_TLS_CERTFILE=/etc/pbxsense-agent/tls/fullchain.pem
PBXSENSE_AGENT_TLS_KEYFILE=/etc/pbxsense-agent/tls/privkey.pem
PBXSENSE_AGENT_PUBLIC_URL=https://pbxsense-agent.example:8765
```

Restart the service and open the HTTPS pairing URL. The certificate must chain
to a CA trusted by the phone and its hostname must match the public URL. If a
reverse proxy terminates TLS, leave the native TLS file settings empty, proxy
HTTPS/WSS to the local Agent port, and set `PBXSENSE_AGENT_PUBLIC_URL` to the
proxy's canonical HTTPS origin. Do not expose the Agent directly to the public
Internet.

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
the one-second live WebSocket experience. Internet Relay is a server-managed
sanitized Home fallback, currently polled every 60 seconds by default, not a
public Agent endpoint.

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

The standard deployment is a native Agent installation on the PBX host. Like an
Asterisk-based PBX, it reads PBX history and voicemail directly from local
filesystem paths and needs no Docker volume mapping.

Set `FREESWITCH_CDR_JSON_PATH` only when `mod_json_cdr` writes local JSON CDR
files visible to the Agent. The installer reads running PBX directory variables
and local configuration, then offers detected directories and common-location
fallbacks. Event Socket itself does
not expose completed call history. Depending on the FreeSWITCH build,
`mod_json_cdr` may write `*.cdr.json` directly in its configured `log-dir`; use
the directory that actually contains the files. Set `FREESWITCH_VOICEMAIL_PATH` only when
FreeSWITCH voicemail metadata files are visible to the Agent.

The connector reads registered Sofia users with `show registrations as json`,
so idle registered phones remain visible in People. If `mod_callcenter` is
loaded, it also reads queue names and waiting counts through
`callcenter_config`. Missing `mod_callcenter` support does not make the
connector unhealthy; queue data is simply omitted.

## Asterisk/FreeSWITCH discovery and verification (Agent 0.6.42-beta)

Agent 0.6.43-beta improves the manual workflow without adding automation:
four named setup stages, explicit Enter/keep guidance, PBX-account versus
Linux/browser-credential explanations, and exact path-selection defaults.
Optional sources explain which feature is disabled when skipped. The final
report labels capabilities **Ready**, **Not enabled**, **Needs confirmation**
or **Needs attention**, with suggested actions. Ready live connectivity or
folder access is not proof of call delivery or complete history. Both native
and Docker installers print a capability recheck command so you can fix an item
and validate it without repeating installation. Existing settings remain
preserved by default; setup is not transactional, so answers already saved
before Ctrl+C may remain. No PBX configuration/permissions are changed.

For a new native installation, the installer asks for connection details first,
then offers numbered choices for completed calls, voicemail and recordings.
Press Enter to accept the first detected candidate, choose another number,
choose `m` for an advanced absolute path, or `s` to disable an optional source.
Existing native settings are preserved by default on reinstall; choose a detected
number explicitly to replace them. A nonexistent default is no longer invented
when nothing is detected. Remote PBXs do not use local discovery; provide files
already synchronized or mounted on the Agent host, or skip optional sources.

Asterisk discovery checks `core show settings` and the `[directories]` section
of `asterisk.conf`, then searches supported CSV locations under its log directory
and voicemail/monitor folders under its spool directory. `cdr show status`
warns when logging is disabled or no standard CSV backend is confirmed. Arbitrary
SQL/custom layouts are not converted into the Agent's standard Master.csv format.
Custom dialplan recording locations may still need the advanced choice.

FreeSWITCH discovery checks directory variables through local `fs_cli`, literal
directory settings in `vars.xml`, and `json_cdr.conf.xml` disk `log-dir`.
It expands known directory variables and offers both direct JSON output and
the `json_cdr` subdirectory, followed by common paths. It checks whether
`mod_json_cdr` is loaded when the CLI is reachable. No module is loaded and no
PBX configuration is edited. Conditional includes, runtime per-channel overrides,
unknown XML variables, custom voicemail/recording layouts, and CLI authentication
failures can still require an administrator's manual choice.

At the end of native installation, a read-only capability report uses `runuser`
to check the selected sources as `pbxsense`, not as root. It performs a live
snapshot with the configured connector and parses a small recent-CDR sample
without displaying caller data. Missing files, permission failures, no parseable
records and unavailable live monitoring are reported separately. Native service
sandbox paths such as `/home`, `/root` and `/tmp` are not treated as ready.
This is an account-level preflight, not a full reproduction of every systemd
namespace/SELinux/AppArmor rule; verify Agent diagnostics after startup too.
The installer never broadens PBX file permissions or changes ownership. Grant
only necessary read access through your site's group/ACL policy if required.

The installer prints a standalone `watch-cdr` command. Run it, make and end an
answered test call, and it watches up to 60 seconds for changed parseable call
evidence under the same runtime user. A changed file containing only old valid
rows does not qualify. Other PBX calls may also produce new evidence, so confirm
the specific test call in the app. No evidence is a failed/unverified test, not
proof that live connectivity means CDR works. Longer vendor write delays need
another check. Voicemail/recordings directory access does not prove that every
nested file is readable or that the PBX is producing content.

For interactive Docker setup, select native-host discovery or supply the local
PBX container name. Container discovery reads its directories/configuration and
maps paths through inspected mounts into host paths. Files only inside the PBX
container's writable layer cannot be safely shared this way; expose an existing
volume/bind source explicitly. Detected source choices create the local ignored
`docker/docker-compose.detected.yml` override with read-only long-syntax binds,
`create_host_path: false`, and separate container-visible environment paths.
It replaces the generic Asterisk/FreeSWITCH prepared-root override in commands
printed by the wizard. Sources must already exist; no empty host directories
are created. Existing detected overrides are preserved, not overwritten.

After Docker startup, the report runs inside the Agent container as its default
non-root user. Actual numeric group ownership, Docker namespace access and
SELinux restrictions still matter; discovery cannot grant access. Noninteractive
Docker setup preserves existing path/mount configuration and skips automatic
mount generation. Existing manual/prepared-root and named-volume overrides remain
supported; keep the same Compose files/options for subsequent updates. Native
installation remains the recommended default on on-premise PBX hosts.

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
CUCM_PERFMON_ENABLED=true
CUCM_PERFMON_HOST=cucm-subscriber.example.com
CUCM_CDR_PATH=/var/lib/pbxsense-agent/cucm/cdr
CUCM_CMR_PATH=/var/lib/pbxsense-agent/cucm/cmr
CUCM_JTAPI_ENABLED=false
CUCM_JTAPI_CLASSPATH=/opt/pbxsense-agent/vendor/jtapi/*
```

Enable the Cisco AXL Web Service and Cisco RIS Data Collector services. Import
the CUCM certificate authority into the Agent host trust store; disabling TLS
verification is intended only for temporary diagnosis.

SIP-trunk monitoring also reads AXL SIP-trunk/profile inventory and RisPortExt
state. Enable Outbound OPTIONS Ping on the trunk's SIP profile so Registered,
Partially Registered, and Out of Service are trustworthy reachability evidence.
PerfMon collection is enabled by default and reads `Cisco SIP` call counters
from `CUCM_PERFMON_HOST`, falling back to `CUCM_HOST`; disable it explicitly if
the application user cannot access that service. PerfMon and recent completed
CDRs corroborate working call processing but never override a current explicit
out-of-service state.

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

The Docker wizard creates a sibling `pbxsense-config/.env` outside the source
folder. Existing source-folder `.env` credentials are copied only when no saved
configuration exists. Subsequent runs reuse the saved configuration. Override
the location with `PBXSENSE_DOCKER_CONFIG_DIR` if required.

The standard Compose setup stores authorization, pairing and history in named
Docker volumes, not in the source directory. Keep the same Compose project name
when updating; never use `docker compose down -v` unless intentionally resetting
the installation. Replace the source and rerun `sh ./scripts/setup_docker.sh`,
or use the exact Compose command printed by the wizard (including connector
overrides and the external `--env-file`). Recheck discovered PBX mounts after
replacing source files. Manual legacy `../.env` setups remain supported.

Custom Compose installations that bind the source directory to
`/var/lib/pbxsense-agent` must back up and migrate their existing runtime state
before switching to a named volume; changing the mount alone creates a fresh
identity. The wizard does not automatically migrate custom running containers.

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

The following applies only when the Agent runs in Docker. For the generic
FreeSWITCH override, `FREESWITCH_FILES_HOST_PATH` is a prepared
root containing `cdr/`, `voicemail/`, and `recordings/`:

```text
FREESWITCH_FILES_HOST_PATH=../freeswitch
```

This Docker prepared-root convention is not FusionPBX Docker's native storage layout.
FusionPBX commonly uses separate `freeswitch_lib` and `freeswitch_log` named
volumes. To consume CDR written directly under `/var/log/freeswitch`, add the
log volume to the Agent service:

```yaml
services:
  pbxsense-agent:
    volumes:
      - freeswitch_lib:/var/lib/pbxsense-agent/freeswitch:ro
      - freeswitch_log:/var/lib/pbxsense-agent/freeswitch-log:ro

volumes:
  freeswitch_lib:
    external: true
    name: fusionpbx-docker_freeswitch_lib
  freeswitch_log:
    external: true
    name: fusionpbx-docker_freeswitch_log
```

Then use the container-visible paths:

```text
FREESWITCH_CDR_JSON_PATH=/var/lib/pbxsense-agent/freeswitch-log
FREESWITCH_VOICEMAIL_PATH=/var/lib/pbxsense-agent/freeswitch/storage/voicemail
```

Volume names can differ when the FusionPBX Compose project has another name;
confirm them with `docker volume ls` or `docker inspect fusionpbx-freeswitch`.

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
