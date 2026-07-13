# PBXSense Agent Security

PBXSense Agent is designed to run near the PBX on a trusted host, LAN, or VPN.
Do not expose PBX management protocols or the Agent directly to the public
internet.

## Network Boundaries

- Keep Asterisk AMI private to localhost, a single Agent host, LAN, or VPN.
- Keep FreeSWITCH Event Socket private to localhost, a single Agent host, LAN,
  or VPN.
- Do not expose AMI, ESL, SIP management surfaces, SSH, or raw PBX logs to the
  public internet.
- If remote access is needed, put it behind a VPN or another controlled private
  network.

## Agent Token

Set `PBXSENSE_AGENT_TOKEN` for production and LAN deployments.

When a token is set, every protected HTTP and `/live` request must authenticate,
including requests from localhost, a private LAN, or a VPN. A valid token on an
HTML request creates an HTTP-only, same-site cookie for later Agent-page links.
The Agent does not enable cross-origin browser access. `GET /health` is the only
unauthenticated route and returns only a basic service status.

Generate a token:

```bash
python3 scripts/ensure_token.py .env
```

For Linux service installs, the token is stored in:

```text
/etc/pbxsense-agent.env
```

Keep this file readable only by root:

```bash
sudo chmod 600 /etc/pbxsense-agent.env
sudo chown root:root /etc/pbxsense-agent.env
```

The relay identity under `/var/lib/pbxsense-agent` contains the installation's
private signing key and queued device registrations. The Agent enforces `0700`
on its directory and `0600` on the identity file on Linux.

Preserve `relay_identity.json` across rebuilds and host migrations. Anyone who
obtains it can authenticate as that Agent, so store backups like credentials.
Deleting the Docker data volume or identity file creates a new relay identity;
the previous app registrations remain isolated under the old identity and must
be recovered from backup or replaced by pairing the apps again.

Rotate the token if it is shared accidentally. After rotation, reconnect the
PBXSense app with the new pairing URL or QR payload.

## Linux Service Hardening

The installer creates a dedicated `pbxsense` service user and runs the Agent
from `/opt/pbxsense-agent`.

The systemd unit uses:

```text
NoNewPrivileges=true
PrivateTmp=true
```

Do not run the Agent as root outside the installer. The service only needs
network access to the PBX connector and read access to mounted CDR/voicemail
paths.

## PBX Credentials

- Use a dedicated AMI or ESL user/password for PBXSense.
- Grant read-only AMI permissions when possible.
- Do not reuse admin web UI credentials.
- Do not commit `.env`, `/etc/pbxsense-agent.env`, generated tokens, or PBX
  passwords.

Minimal Asterisk AMI shape:

```ini
[pbxsense]
secret = <strong-secret>
read = system,call,reporting,command
write =
permit = 127.0.0.1/255.255.255.255
```

If the Agent runs on another host, replace `permit` with that Agent host or a
trusted private subnet.

## Docker Notes

Mount Asterisk logs and spool read-only:

```yaml
volumes:
  - ./asterisk/logs:/var/log/asterisk:ro
  - ./asterisk/spool:/var/spool/asterisk:ro
```

Keep `.env` out of source control. It contains PBX credentials and the Agent
token.

## Diagnostics Data

Diagnostics should explain connection and configuration failures without
promoting raw PBX events into the app layer. Connector-specific protocol details
belong under diagnostics or `technical` evidence.

When sharing diagnostics externally, review them for hostnames, IP addresses,
usernames, tokens, and deployment-specific paths.
