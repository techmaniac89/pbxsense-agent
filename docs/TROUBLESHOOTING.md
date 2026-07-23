# PBXSense Agent Troubleshooting

Start with the Agent landing page:

```text
http://<agent-host>:8765/
```

Then check the main diagnostics endpoint:

```text
http://<agent-host>:8765/diagnostics
```

For older Asterisk-specific flows, this alias is also available:

```text
http://<agent-host>:8765/diagnostics/ami
```

## Service Health

Linux service:

```bash
systemctl status pbxsense-agent
journalctl -u pbxsense-agent -f
```

Docker:

```bash
docker compose --env-file .env -f docker/docker-compose.yml ps
docker compose --env-file .env -f docker/docker-compose.yml logs -f
```

Health endpoint:

```text
http://<agent-host>:8765/health
```

## Asterisk AMI Checks

Diagnostics fields:

- `tcpConnected: false`: the Agent cannot reach `ASTERISK_AMI_HOST:ASTERISK_AMI_PORT`.
- `bannerReceived: false`: TCP connected, but AMI did not send a greeting before timeout.
- `loginAccepted: false`: AMI answered, but credentials or AMI permissions are wrong.

Common fixes:

- Confirm Asterisk AMI is enabled in `manager.conf`.
- Confirm the AMI user has read permissions such as `system,call,reporting,command`.
- Confirm `permit` allows the Agent host.
- Keep AMI restricted to localhost, LAN, or VPN.
- Restart or reload Asterisk manager after config changes.

Minimal AMI user:

```ini
[pbxsense]
secret = your-secret
read = system,call,reporting,command,agent
write =
permit = 127.0.0.1/255.255.255.255
```

If the Agent runs on another host, replace `permit` with that host IP or a
trusted private subnet.

## FreeSWITCH ESL Checks

Diagnostics fields:

- `tcpConnected: false`: the Agent cannot reach `FREESWITCH_ESL_HOST:FREESWITCH_ESL_PORT`.
- `loginAccepted: false`: the Event Socket password is missing or wrong.
- `commandAccepted: false`: login worked, but the test command failed.

Check the Event Socket password in:

```text
/etc/freeswitch/autoload_configs/event_socket.conf.xml
```

Then update `FREESWITCH_ESL_PASSWORD` and restart the Agent.

## Yeastar API Checks

Open `/diagnostics` and check `tokenAccepted` and `apiReachable`. If either is
false, confirm `YEASTAR_BASE_URL`, Client ID, and Client Secret. In Yeastar,
enable API access under `Integrations > API`; if IP restriction is enabled, add
the Agent host. Keep `YEASTAR_VERIFY_TLS=true` unless the local PBX deliberately
uses a trusted self-signed certificate.

If extensions work but Yeastar queues are empty, grant the API client access to
`queue/search` and `queue/call_status`. If FreeSWITCH extensions work but queues
are empty, confirm `mod_callcenter` is loaded and that
`callcenter_config queue list` works through `fs_cli`.

## Pairing Problems

If `/pair` opens locally but not from another device:

- Confirm the other device can reach `http://<agent-host>:8765/`.
- Confirm host firewall rules allow TCP port `8765`.
- Private LAN/VPN addresses do not bypass Agent authentication. Open the
  authenticated link printed by the installer on the intended PC. If the link
  used the wrong address, rerun setup with an explicit host:

```bash
sudo PBXSENSE_ACCESS_HOST=<agent-host> sh ./scripts/install_debian.sh
```

If the token is missing, generate one:

```bash
python3 scripts/ensure_token.py .env
```

For Linux service installs, the token is in:

```text
/etc/pbxsense-agent.env
```

If the pairing page says **Local pairing ready**, the Agent deliberately fell
back to a local-only QR because cloud relay activation was unavailable. The page
must not return HTTP 500 for this condition. Check relay connectivity and write
access to `PBXSENSE_RELAY_IDENTITY_PATH`, then refresh the page before pairing
when closed-app push notifications are required.

If push notifications work but the app cannot use encrypted Home snapshots
away from the LAN:

- Confirm the hosted relay reports service `0.4.8` and use current Breeze
  app/Agent builds.
- Confirm `PBXSENSE_INTERNET_RELAY_ENABLED` is `true` (the default) and restart
  the Agent after changing an explicit override.
- Open Agent diagnostics and confirm Internet relay is enabled and connected.
- Scan a fresh protected pairing QR; manually entering only an Agent IP/token
  cannot create the app's encryption key and per-device relay credential.
- Keep `/var/lib/pbxsense-agent/relay_identity.json` persistent across Docker
  rebuilds. If the identity was recreated, pair the app again.

The app allows 105 seconds from the current Agent heartbeat (or 60 seconds from
the envelope timestamp for older relay responses). If the Agent or its Internet
connection is down, a brief secure connection may therefore change to
reconnecting; this prevents stale PBX state appearing live.

## Missing History Or Voicemail

If live calls work but history, tips, or voicemail evidence is missing:

- Check `/diagnostics` for the `history` section.
- Confirm `ASTERISK_CDR_CSV_PATH` points to the CDR CSV visible inside the Agent runtime.
- Confirm `ASTERISK_VOICEMAIL_PATH` points to the voicemail spool visible inside the Agent runtime.
- Confirm `ASTERISK_RECORDINGS_PATH` points to the MixMonitor root visible inside the Agent runtime.
- For Docker, confirm the host log and spool folders are mounted read-only.
- For Linux service installs, confirm the `pbxsense` service user can traverse
  each parent folder and read the CDR/voicemail files. Home directories are
  often private, so paths under `/home/...` may need ACLs or a shared mount.

Common CDR paths:

```text
/var/log/asterisk/cdr-csv/Master.csv
/var/log/asterisk/cdr-custom/Master.csv
```

If journalctl shows `Permission denied`, either move/mount the Asterisk logs
under a service-readable path or grant read/traverse access. Also check for
typos: Asterisk commonly uses `cdr-custom`, not `csv-custom`.

For recorded calls, a standard Asterisk CSV only advertises a recording when its
CDR `userfield` contains the recording filename. The Agent never exposes host
paths: it serves matching audio only through `GET /recordings/{recording-id}`.
If more than one file matches a shortened recording ID, the Agent returns no
recording; configure the CDR source to provide the complete filename.

## Docker Network Problems

The default compose file uses `network_mode: host`, so `127.0.0.1` points to the
host network namespace on Linux.

If the PBX is on another LAN host:

```text
ASTERISK_AMI_HOST=192.168.x.x
```

Then run:

```bash
docker compose --env-file .env -f docker/docker-compose.yml \
  -f docker/docker-compose.lan.yml up --build
```

## Endpoint Quick Check

These endpoints should respond when the Agent is running:

```text
GET /
GET /health
GET /home
GET /pair
GET /diagnostics
WS  /live
```
