# PBXPulse Agent Configuration

PBXPulse Agent is configured with environment variables. Docker and development
mode normally use `.env`; Linux service installs use:

```text
/etc/pbxpulse-agent.env
```

Use `.env.example` as the starting point.

## Core Settings

| Variable | Default | Description |
| --- | --- | --- |
| `PBXPULSE_PBX_TYPE` | `asterisk` | PBX family. Supports `asterisk`, `freeswitch`, `mock`, and aliases listed below. |
| `PBXPULSE_AGENT_MODE` | derived | Connector mode. Usually `ami`, `freeswitch`, or `mock`. |
| `PBXPULSE_DISPLAY_NAME` | `Asterisk` or `FreeSWITCH` | Friendly PBX name shown by the Agent. |
| `PBXPULSE_TIMEZONE` | `TZ` or empty | IANA timezone for history and timestamps. |
| `PBXPULSE_AGENT_TOKEN` | empty | Optional shared token for pairing and remote access. |
| `PBXPULSE_CONNECT_TIMEOUT` | `3` | Connector TCP/login timeout in seconds. |
| `PBXPULSE_AGENT_PORT` | `8765` | Service port used by the Linux systemd installer. |
| `PBXPULSE_EXTENSION_NAMES` | empty | Optional friendly-name map such as `101=Reception,120=Support`. |

`PBXPULSE_PBX_TYPE` aliases:

| Alias | Normalized Type |
| --- | --- |
| `ami`, `asteriskami`, `asterisk` | `asterisk` |
| `freepbx`, `issabel`, `vitalpbx` | `asterisk` |
| `fs`, `freeswitch` | `freeswitch` |
| `fusionpbx` | `freeswitch` |
| `mock` | `mock` |

## Asterisk AMI Settings

| Variable | Default | Description |
| --- | --- | --- |
| `ASTERISK_AMI_HOST` | `127.0.0.1` | AMI host or PBX IP. |
| `ASTERISK_AMI_PORT` | `5038` | AMI TCP port. |
| `ASTERISK_AMI_USERNAME` | empty | AMI manager username. |
| `ASTERISK_AMI_PASSWORD` | empty | AMI manager password. |
| `ASTERISK_AMI_TIMEOUT` | `3` | Legacy timeout fallback used when `PBXPULSE_CONNECT_TIMEOUT` is unset. |
| `ASTERISK_CDR_CSV_PATH` | `/var/log/asterisk/cdr-csv/Master.csv` | CDR CSV path inside the Agent runtime. |
| `ASTERISK_CDR_CUSTOM_PATH` | unset | Legacy fallback for `ASTERISK_CDR_CSV_PATH`. |
| `ASTERISK_VOICEMAIL_PATH` | `/var/spool/asterisk/voicemail` | Voicemail spool path inside the Agent runtime. |

For Docker, the CDR and voicemail paths are container paths. Mount the host
folders into those locations with:

```text
ASTERISK_LOGS_HOST_PATH=../asterisk/logs
ASTERISK_SPOOL_HOST_PATH=../asterisk/spool
```

## FreeSWITCH ESL Settings

| Variable | Default | Description |
| --- | --- | --- |
| `FREESWITCH_ESL_HOST` | `127.0.0.1` | Event Socket host. |
| `FREESWITCH_ESL_PORT` | `8021` | Event Socket port. |
| `FREESWITCH_ESL_PASSWORD` | empty | Event Socket password. |

## Token Handling

Generate a token for `.env`:

```bash
python3 scripts/ensure_token.py .env
```

Generate or preserve a token for the Linux service file:

```bash
sudo python3 /opt/pbxpulse-agent/scripts/ensure_token.py /etc/pbxpulse-agent.env
```

The helper only fills an empty or missing `PBXPULSE_AGENT_TOKEN`. It does not
rotate an existing token.

## Endpoint Access

If `PBXPULSE_AGENT_TOKEN` is empty, local testing is simpler but remote access is
not protected by the Agent token. Production and LAN deployments should set a
long random token.

Requests from localhost, private LAN, or VPN client IPs are treated as trusted
for Agent HTTP pages, JSON endpoints, and `/live`. Browser HTML pages also get
an HTTP-only cookie. The pairing page still embeds the token in the QR payload
so the app can store it for non-LAN or stricter future access:

```text
http://<agent-host>:8765/pair?token=<PBXPULSE_AGENT_TOKEN>
```

## Configuration Changes

After changing `.env` in Docker:

```bash
docker compose up -d --build
```

After changing `/etc/pbxpulse-agent.env` on Linux:

```bash
sudo systemctl restart pbxpulse-agent
```
