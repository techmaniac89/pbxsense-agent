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
| `PBXSENSE_PBX_TYPE` | `asterisk` | PBX family. Supports `asterisk`, `grandstream`, `freeswitch`, `yeastar`, `mock`, and aliases listed below. |
| `PBXSENSE_AGENT_MODE` | derived | Connector mode. Usually `ami`, `freeswitch`, `yeastar`, or `mock`. |
| `PBXSENSE_DISPLAY_NAME` | connector name | Friendly PBX name shown by the Agent. |
| `PBXSENSE_TIMEZONE` | `TZ` or empty | IANA timezone for history and timestamps. |
| `PBXSENSE_AGENT_TOKEN` | empty | Optional shared token for pairing and remote access. |
| `PBXSENSE_CONNECT_TIMEOUT` | `3` | Connector TCP/login timeout in seconds. |
| `PBXSENSE_AGENT_PORT` | `8765` | Service port used by the Linux systemd installer. |
| `PBXSENSE_EXTENSION_NAMES` | empty | Optional friendly-name map such as `101=Reception,120=Support`. |

`PBXSENSE_PBX_TYPE` aliases:

| Alias | Normalized Type |
| --- | --- |
| `ami`, `asteriskami`, `asterisk` | `asterisk` |
| `freepbx`, `issabel`, `vitalpbx` | `asterisk` |
| `grandstream`, `grandstream-ucm`, `ucm`, `ucm6xxx`, `ucm62xx`, `ucm63xx`, `ucm6100`, `ucm6200`, `ucm6300`, `ucm6300a`, `ucm6300audio`, `ucm6510` | `grandstream` |
| `fs`, `freeswitch` | `freeswitch` |
| `fusionpbx` | `freeswitch` |
| `yeastar`, `yeastar-p-series`, `pseries` | `yeastar` |
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

For Docker, the CDR and voicemail paths are container paths. Mount the host
folders into those locations with:

```text
ASTERISK_LOGS_HOST_PATH=../asterisk/logs
ASTERISK_SPOOL_HOST_PATH=../asterisk/spool
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

If `PBXSENSE_AGENT_TOKEN` is empty, local testing is simpler but remote access is
not protected by the Agent token. Production and LAN deployments should set a
long random token.

Localhost, private LAN, and VPN clients must authenticate just like other
clients. A valid token on an HTML request creates an HTTP-only, same-site cookie.
The pairing page embeds the token in its QR payload so the app can authenticate
`/home`, `/live`, diagnostics, recordings, and push-device registration:

```text
http://<agent-host>:8765/pair?token=<PBXSENSE_AGENT_TOKEN>
```

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
docker compose up -d --build
```

After changing `/etc/pbxsense-agent.env` on Linux:

```bash
sudo systemctl restart pbxsense-agent
```
