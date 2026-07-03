# PBXPulse Agent Troubleshooting

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
systemctl status pbxpulse-agent
journalctl -u pbxpulse-agent -f
```

Docker:

```bash
docker compose ps
docker compose logs -f
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
[pbxpulse]
secret = your-secret
read = system,call,reporting,command
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

## Pairing Problems

If `/pair` opens locally but not from another device:

- Confirm the other device can reach `http://<agent-host>:8765/`.
- Confirm host firewall rules allow TCP port `8765`.
- Include the token for remote LAN pairing:

```text
http://<agent-host>:8765/pair?token=<PBXPULSE_AGENT_TOKEN>
```

If the token is missing, generate one:

```bash
python3 scripts/ensure_token.py .env
```

For Linux service installs, the token is in:

```text
/etc/pbxpulse-agent.env
```

## Missing History Or Voicemail

If live calls work but history, tips, or voicemail evidence is missing:

- Check `/diagnostics` for the `history` section.
- Confirm `ASTERISK_CDR_CSV_PATH` points to the CDR CSV visible inside the Agent runtime.
- Confirm `ASTERISK_VOICEMAIL_PATH` points to the voicemail spool visible inside the Agent runtime.
- For Docker, confirm the host log and spool folders are mounted read-only.

Common CDR paths:

```text
/var/log/asterisk/cdr-csv/Master.csv
/var/log/asterisk/cdr-custom/Master.csv
```

## Docker Network Problems

The default compose file uses `network_mode: host`, so `127.0.0.1` points to the
host network namespace on Linux.

If the PBX is on another LAN host:

```text
ASTERISK_AMI_HOST=192.168.x.x
```

Then run:

```bash
docker compose -f docker-compose.yml -f docker-compose.lan.yml up --build
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
