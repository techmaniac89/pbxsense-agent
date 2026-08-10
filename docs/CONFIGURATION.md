# PBXSense Agent Configuration

PBXSense Agent is configured with environment variables. Docker and development
mode normally use `.env`; Linux service installs use:

```text
/etc/pbxsense-agent.env
```

Use `.env.example` as the starting point.

## Core Settings

| Variable | Default | Description |
| --- | --- | --- |
| `PBXSENSE_PBX_TYPE` | `asterisk` | PBX family. Supports `asterisk`, `grandstream`, `freeswitch`, `yeastar`, `cucm`, `mock`, and aliases listed below. |
| `PBXSENSE_AGENT_MODE` | derived | Connector mode. Usually `ami`, `freeswitch`, `yeastar`, `cucm`, or `mock`. |
| `PBXSENSE_DISPLAY_NAME` | connector name | Friendly PBX name shown by the Agent. |
| `PBXSENSE_TIMEZONE` | `TZ` or empty | IANA timezone for history and timestamps. |
| `PBXSENSE_AGENT_TOKEN` | empty | Shared token for local/VPN/direct-Agent pairing and protected endpoints; it is not sent to the hosted relay. |
| `PBXSENSE_CONNECT_TIMEOUT` | `3` | Connector TCP/login timeout in seconds. |
| `PBXSENSE_AGENT_PORT` | `8765` | Agent HTTP or HTTPS port used by the Linux service and Docker container, including its health check and LAN port mapping. |
| `PBXSENSE_AGENT_TLS_CERTFILE` | empty | PEM certificate chain for native Agent HTTPS/WSS. Configure together with `PBXSENSE_AGENT_TLS_KEYFILE`; release apps require TLS for direct LAN/VPN access. |
| `PBXSENSE_AGENT_TLS_KEYFILE` | empty | PEM private key for native Agent HTTPS/WSS. Keep it readable only by the Agent service account. |
| `PBXSENSE_AGENT_PUBLIC_URL` | empty | Canonical root origin embedded in pairing QR codes, such as `https://pbxsense-agent.example:8765`. Required when TLS terminates at a reverse proxy or request host/scheme is not canonical. |
| `PBXSENSE_EXTENSION_NAMES` | empty | Optional friendly-name map such as `101=Reception,120=Support`. |
| `PBXSENSE_SNAPSHOT_POLL_SECONDS` | `1` | Central live PBX polling cadence, clamped to at least 0.5 seconds. |
| `PBXSENSE_HISTORY_POLL_SECONDS` | `30` | CDR, voicemail, recording, and security-history refresh cadence, clamped to at least 5 seconds. |
| `PBXSENSE_ENDPOINT_ACTIVITY_PATH` | `/var/lib/pbxsense-agent/endpoint_activity.json` | Persistent last-active timestamps captured when monitored devices transition offline. Keep this inside the Agent data volume. |
| `PBXSENSE_ENDPOINT_OUTAGE_CONFIRMATION_SECONDS` | `30` | Continuous unavailable period required before a per-device Health Signal and notification. |
| `PBXSENSE_ENDPOINT_RECOVERY_CONFIRMATION_SECONDS` | `60` | Continuous reachable period required before recovery and a later outage notification can be armed. |
| `PBXSENSE_TRUNK_OUTAGE_CONFIRMATION_SECONDS` | `5` | Continuous unavailable period required before a trunk Health Signal and notification. |
| `PBXSENSE_QUALITY_FREQUENCY_SECONDS` | `180` | Evidence window before aggregate availability Tips are emitted. |
| `PBXSENSE_RELAY_URL` | hosted PBXSense URL in `.env.example` | Shared notification/encrypted-data relay URL. Production URLs must use HTTPS; plain HTTP is accepted only for localhost development. Leave empty only for deliberately local-only installs. |
| `PBXSENSE_RELAY_IDENTITY_PATH` | `/var/lib/pbxsense-agent/relay_identity.json` | Persistent Agent Ed25519 identity and durable relay state. Back up and preserve it across rebuilds. |
| `PBXSENSE_RELAY_TIMEOUT` | `5` | Outbound relay HTTP timeout in seconds. |
| `PBXSENSE_RELAY_ENROLLMENT_TICKET` | empty | Operator-only bootstrap override for controlled testing/support. In production the subscribed app obtains a short-lived ticket and passes it automatically during QR pairing; end users do not configure it. Existing enrolled Agents authenticate with their durable identity. |
| `PBXSENSE_INTERNET_RELAY_ENABLED` | `true` | Makes encrypted Internet Relay available to apps that explicitly enable it while pairing. Set `false` to prohibit it for this Agent. |
| `PBXSENSE_INTERNET_RELAY_POLL_SECONDS` | `15` | Changed-snapshot check cadence, clamped to at least 5 seconds. Unchanged snapshots are not rewritten; control checks run at most once every five minutes. |

Endpoint confirmation controls when a per-device Health Signal becomes valid;
it is separate from push correlation. On PBXs with three or more monitored
phones, confirmed outages may wait up to 15 additional seconds so clustered
failures can become one notification. Grouped push updates are limited to every
30 seconds, grouped recovery requires 15 stable seconds, and the completed
episode has a two-minute cooldown. These correlation timings are currently
product defaults rather than environment settings.

Internet Relay remains opt-in per app. The Agent capability is ready by default,
but no snapshot is uploaded until an app explicitly enables it and registers an
encryption key. Every opted-in app receives a distinct envelope;
the relay cannot decrypt it. The projection removes PBX host/port details and
recording references. Diagnostics, recordings, and PBX control are never sent
through this path. Restart the Agent after changing either relay setting.
Permanent relay `4xx` rejections are quarantined so one invalid entry cannot
block the outbox; retryable `408`, `425`, `429`, and `5xx` responses remain
queued. The relay status exposes the rejected count and latest rejection.

`PBXSENSE_PBX_TYPE` aliases:

| Alias | Normalized Type |
| --- | --- |
| `ami`, `asteriskami`, `asterisk` | `asterisk` |
| `freepbx`, `issabel`, `vitalpbx` | `asterisk` |
| `grandstream`, `grandstream-ucm`, `ucm`, `ucm6xxx`, `ucm62xx`, `ucm63xx`, `ucm6100`, `ucm6200`, `ucm6300`, `ucm6300a`, `ucm6300audio`, `ucm6510` | `grandstream` |
| `fs`, `freeswitch` | `freeswitch` |
| `fusionpbx` | `freeswitch` |
| `yeastar`, `yeastar-p-series`, `pseries` | `yeastar` |
| `cucm`, `cisco-cucm`, `cisco-unified-communications-manager` | `cucm` |
| `mock` | `mock` |

## Asterisk AMI Settings

| Variable | Default | Description |
| --- | --- | --- |
| `ASTERISK_AMI_HOST` | `127.0.0.1` | AMI host or PBX IP. |
| `ASTERISK_AMI_PORT` | `5038` | AMI TCP port. |
| `ASTERISK_AMI_USERNAME` | empty | AMI manager username. |
| `ASTERISK_AMI_PASSWORD` | empty | AMI manager password. |
| `ASTERISK_AMI_TIMEOUT` | `3` | Deprecated compatibility fallback used only when `PBXSENSE_CONNECT_TIMEOUT` is unset. |
| `ASTERISK_CDR_CSV_PATH` | `/var/log/asterisk/cdr-csv/Master.csv` | CDR CSV path inside the Agent runtime. |
| `ASTERISK_CDR_CUSTOM_PATH` | unset | Legacy fallback for `ASTERISK_CDR_CSV_PATH`. |
| `ASTERISK_VOICEMAIL_PATH` | `/var/spool/asterisk/voicemail` | Voicemail spool path inside the Agent runtime. |
| `ASTERISK_RECORDINGS_PATH` | `/var/spool/asterisk/monitor` | MixMonitor recording root visible to the Agent. |
| `ASTERISK_SECURITY_LOG_PATH` | `/var/log/asterisk/security` | Local Asterisk security log used for aggregate authentication/ACL Security Signals. |
| `PBXSENSE_TRUNK_ENDPOINTS` | empty | Comma-separated exact Asterisk endpoint or outbound-registration names used as SIP trunks. Matching is case-insensitive. |

For PJSIP provider trunks, the Agent combines endpoint/contact qualification,
`PJSIPShowRegistrationsOutbound`, and observed active calls. `Registered`
confirms healthy service; `Rejected`, `Unregistered`, `Stopped`, or `Failed`
confirms an unavailable trunk. Transitional registration states remain
uncertain instead of generating a false outage.

## Cross-connector trunk evidence

All connectors preserve the identity of previously observed trunks when an
optional trunk-health query temporarily fails. The retained sample becomes
`Unknown` with low confidence: it cannot declare either an outage or a
recovery, and an existing incident keeps its notification episode instead of
being recreated. A successfully returned empty inventory is treated as a real
configuration change after the normal recovery window.

- Asterisk and compatible Grandstream AMI use endpoint/contact state,
  outbound-registration state when supported, and active calls. Diagnostics
  show whether `PJSIPShowRegistrationsOutbound` is available.
- FreeSWITCH uses Sofia gateway state and status. `UNREGED` is down;
  `REGED` with a down reachability status is degraded rather than unknown.
- Yeastar uses the P-Series trunk status API. Disabled, registering,
  unmonitored, and unrecognized values remain unknown instead of creating a
  false outage.
- CUCM combines SIP OPTIONS serviceability, RisPort, PerfMon, and recent CDRs.
  Traffic evidence can strengthen an unknown or healthy result but never
  override an explicit current `OutOfService`/down state.

For Docker, the CDR and voicemail paths are container paths. Mount the host
folders into those locations with:

```text
ASTERISK_LOGS_HOST_PATH=../../asterisk/logs
ASTERISK_SPOOL_HOST_PATH=../../asterisk/spool
```

## Grandstream UCM AMI Settings

| Variable | Default | Description |
| --- | --- | --- |
| `GRANDSTREAM_UCM_AMI_HOST` | `127.0.0.1` | UCM AMI host or LAN IP. |
| `GRANDSTREAM_UCM_AMI_PORT` | `7777` | Plain AMI port. Use `5039` when TLS is enabled unless the UCM was customized. |
| `GRANDSTREAM_UCM_AMI_USERNAME` | empty | Dedicated UCM AMI username. |
| `GRANDSTREAM_UCM_AMI_PASSWORD` | empty | Dedicated UCM AMI password. |
| `GRANDSTREAM_UCM_AMI_TLS` | `false` | Set `true` for UCM's TLS AMI listener. |
| `GRANDSTREAM_UCM_AMI_VERIFY_TLS` | `true` | Set `false` only for a trusted local UCM with a self-signed certificate. |
| `GRANDSTREAM_UCM_AMI_TIMEOUT` | `3` | Deprecated compatibility fallback used only when `PBXSENSE_CONNECT_TIMEOUT` is unset. |
| `GRANDSTREAM_UCM_CDR_CSV_PATH` | empty | Optional UCM CDR CSV file visible to the Agent. |
| `GRANDSTREAM_UCM_VOICEMAIL_PATH` | empty | Optional UCM voicemail folder visible to the Agent. |
| `GRANDSTREAM_UCM_RECORDINGS_PATH` | empty | Optional UCM recording root visible to the Agent. |
| `GRANDSTREAM_UCM_SECURITY_LOG_PATH` | empty | Optional UCM security log used for aggregate authentication/ACL Security Signals. |
| `GRANDSTREAM_UCM_FILES_HOST_PATH` | `../grandstream` | Docker-only host root, relative to `docker/`, mounted read-only by `docker/docker-compose.grandstream.yml`; expected children are `cdr/Master.csv`, `voicemail/`, `recordings/`, and optionally `security/`. |

UCM AMI users are created under **Value-added Features > AMI**. Restrict the
user to the Agent IP and grant only `system`, `call`, `reporting`, `command`,
and `agent` read privileges. The `agent` privilege enables read-only queue
metrics.

Security logs are optional. When configured, PBXSense reads only recent
security-event types and returns aggregate counts/service names; raw log lines,
account names, and source addresses never leave the Agent.

Failed-call, rejected-login, ACL, and malformed-request clusters use a rolling
15-minute window. Events outside that window cannot keep a Security Signal
active.

## FreeSWITCH ESL Settings

| Variable | Default | Description |
| --- | --- | --- |
| `FREESWITCH_ESL_HOST` | `127.0.0.1` | Event Socket host. |
| `FREESWITCH_ESL_PORT` | `8021` | Event Socket port. |
| `FREESWITCH_ESL_PASSWORD` | empty | Event Socket password. |
| `FREESWITCH_CDR_JSON_PATH` | empty | Optional local `mod_json_cdr` folder visible to the Agent. |
| `FREESWITCH_VOICEMAIL_PATH` | empty | Optional local FreeSWITCH voicemail metadata folder visible to the Agent. |
| `FREESWITCH_RECORDINGS_PATH` | empty | Optional local FreeSWITCH recording root visible to the Agent. |
| `FREESWITCH_FILES_HOST_PATH` | `../freeswitch` | Docker-only host root, relative to `docker/`, mounted read-only by `docker/docker-compose.freeswitch.yml`; expected children are `cdr/`, `voicemail/`, and `recordings/`. |

## Yeastar P-Series Settings

| Variable | Default | Description |
| --- | --- | --- |
| `YEASTAR_BASE_URL` | empty | Local PBX URL or Yeastar Cloud FQDN, without `/openapi`. |
| `YEASTAR_CLIENT_ID` | empty | API Client ID from `Integrations > API`. |
| `YEASTAR_CLIENT_SECRET` | empty | API Client Secret from `Integrations > API`. |
| `YEASTAR_API_VERSION` | `v1.0` | Yeastar OpenAPI version used by the connector. |
| `YEASTAR_VERIFY_TLS` | `true` | Set `false` only for a trusted local PBX with a self-signed certificate. |

The Yeastar connector reads extension availability, active calls, queue waiting
status, CDRs, voicemail metadata, and recorded-call metadata through the
P-Series API. Queue visibility requires permission for `queue/search` and
`queue/call_status`. The Agent keeps the short-lived Yeastar access token in
memory and proxies a recording download, so the token is never returned to the
app.

## Cisco Unified Communications Manager Settings

| Variable | Default | Description |
| --- | --- | --- |
| `CUCM_HOST` | empty | CUCM Publisher hostname or IP. SOAP services use HTTPS port 8443. |
| `CUCM_USERNAME` | empty | Dedicated CUCM application user. |
| `CUCM_PASSWORD` | empty | Application-user password. |
| `CUCM_AXL_VERSION` | `15.0` | AXL schema version matching the CUCM cluster. |
| `CUCM_VERIFY_TLS` | `true` | Verify the CUCM certificate. Import its CA rather than disabling this in production. |
| `CUCM_CDR_PATH` | `/var/lib/pbxsense-agent/cucm/cdr` | Inbox containing CUCM CDR CSV files. |
| `CUCM_CMR_PATH` | `/var/lib/pbxsense-agent/cucm/cmr` | Inbox containing CUCM CMR CSV files. |
| `CUCM_HISTORY_HOST_PATH` | `../cucm-history` | Docker-only host directory mounted read-only at `/var/lib/pbxsense-agent/cucm`; place the `cdr/` and `cmr/` inboxes below it. |
| `CUCM_JTAPI_HOST_PATH` | `../vendor/jtapi` | Docker-only host directory containing the CUCM-matched Cisco JTAPI Client jars and native libraries. |
| `CUCM_JTAPI_ENABLED` | `false` | Start the optional Cisco JTAPI live-call bridge. |
| `CUCM_JTAPI_CLASSPATH` | `/opt/pbxsense-agent/vendor/jtapi/*` | Classpath containing the JTAPI Client jars downloaded from this CUCM cluster. |
| `CUCM_JTAPI_JAVA` | `java` | Cisco-supported Java 8 executable used for the bridge. |
| `CUCM_JTAPI_USERNAME` | empty | JTAPI application user; blank falls back to `CUCM_USERNAME`. |
| `CUCM_JTAPI_PASSWORD` | empty | JTAPI password; blank falls back to `CUCM_PASSWORD`. |
| `CUCM_JTAPI_POLL_SECONDS` | `1` | Bridge polling interval. Core AXL/RisPort polling remains independently cached. |
| `CUCM_JTAPI_STALE_SECONDS` | `10` | Stop presenting live calls when no fresh bridge snapshot arrives within this interval. |
| `CUCM_JTAPI_RESTART_SECONDS` | `15` | Minimum delay between failed bridge restarts. |

Assign the application user `Standard AXL API Users`, `Standard AXL Read Only
API Access`, and `Standard CCM Server Monitoring`. Enable **Cisco AXL Web
Service** on the Publisher and **Cisco SOAP - Real-Time Service APIs** on the
call-processing nodes. The connector uses a read-only SQL query through AXL to
map directory numbers to devices, then uses RisPort70 for cluster-wide phone
registration. It does not expose configuration writes.

For live calls, download the Cisco JTAPI Client plugin from the same CUCM
cluster and copy its jar files into `/opt/pbxsense-agent/vendor/jtapi/` (or
`./vendor/jtapi/` beside the Compose file). Use a dedicated application user
with **Standard CTI Enabled** and associate only the phones PBXSense should
observe as controlled devices. Enable `CUCM_JTAPI_ENABLED=true`; a separate
JTAPI username/password is optional when the Core user also has the required
CTI permissions. The Agent starts and supervises the bundled Java bridge,
consumes its JSON stream locally, and never exposes the JTAPI password in its
command line. If the bridge or Java runtime fails, Core presence and completed
CDR/CMR history continue normally while live calls report unavailable.
Cisco currently supports its CUCM 14/15 JTAPI client on Java 8 and distributes
Linux native libraries for x86 platforms. Raspberry Pi/ARM deployments should
leave JTAPI disabled and run the JTAPI-enabled Agent on a supported x86 host.

For history, configure CUCM CDR Management to push CDR and CMR files to an SFTP
account whose destination directories are mounted at the two paths above. The
Agent does not run an SFTP daemon itself. It reads completed-call records,
correlates CMRs by CUCM global call ID, and emits a quality Insight at 2% packet
loss, 30 ms jitter, or 150 ms latency. Keep the SFTP account write-only where
your server supports it and keep the Agent directories read-only to the
container where practical.

## Recorded Calls

When an eligible history record includes a recording filename, `/home` adds a
`recording` object with an Agent-relative URL. Use the Agent URL and the same
pairing authentication to play or download it. Asterisk CSV history needs the
recording filename in CDR `userfield`; FreeSWITCH JSON CDR needs one of
`recording_file`, `record_file`, or `record_path`. Files are matched by an exact
filename/stem or a delimiter-bounded call ID. Ambiguous matches are rejected
instead of returning an unrelated recording.

## Token Handling

Generate a token for `.env`:

```bash
python3 scripts/ensure_token.py .env
```

Generate or preserve a token for the Linux service file:

```bash
sudo python3 /opt/pbxsense-agent/scripts/ensure_token.py /etc/pbxsense-agent.env
```

The helper only fills an empty or missing `PBXSENSE_AGENT_TOKEN`. It does not
rotate an existing token.

## Endpoint Access

If `PBXSENSE_AGENT_TOKEN` is empty, local testing is simpler but protected Agent
endpoints have no shared-token authentication. Production and LAN deployments
should set a long random token. Internet Relay uses a separate per-app device
credential and does not reuse this token.

Localhost, private LAN, and VPN clients must authenticate just like other
clients. The installer prints an authenticated browser URL at completion; a
valid HTML visit creates a long-lived, renewable HTTP-only, same-site cookie.
The pairing page embeds the token in its QR payload so the app can authenticate
`/home`, `/live`, diagnostics, recordings, and push-device registration:

Use `PBXSENSE_ACCESS_HOST=<agent-host>` when invoking an installer if automatic
host detection would print an unsuitable address.

`GET /health` is intentionally unauthenticated for container/service probes and
returns no connector, PBX, or relay details.

## Upgrade Behavior

The Linux installer preserves every existing value in
`/etc/pbxsense-agent.env`. On upgrade it also copies newly introduced
non-secret defaults from `.env.example`. Credentials, usernames, client IDs,
passwords, secrets, and tokens are never populated into an existing file.

## Configuration Changes

After changing `.env` in Docker:

```bash
sh ./scripts/setup_docker.sh
```

The wizard preserves existing values and selects the matching connector
override. For unattended upgrades, repeat the same `-f` files used at install
and add `--force-recreate`.

After changing `/etc/pbxsense-agent.env` on Linux:

```bash
sudo systemctl restart pbxsense-agent
```
