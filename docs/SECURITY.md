# PBXSense Agent Security

PBXSense Agent is designed to run near the PBX on a trusted host, LAN, or VPN.
Do not expose PBX management protocols or the Agent directly to the public
internet.

## Network Boundaries

- Keep Asterisk AMI private to localhost, a single Agent host, LAN, or VPN.
- Keep FreeSWITCH Event Socket private to localhost, a single Agent host, LAN,
  or VPN.
- Keep CUCM AXL, RisPort, and JTAPI access on the trusted management network.
  Associate the JTAPI user only with phones PBXSense is intended to observe.
- Do not expose AMI, ESL, SIP management surfaces, SSH, or raw PBX logs to the
  public internet.
- If remote access is needed, put it behind a VPN or another controlled private
  network.

Direct release-app connectivity requires HTTPS/WSS. Configure
`PBXSENSE_AGENT_TLS_CERTFILE` and `PBXSENSE_AGENT_TLS_KEYFILE` for native TLS,
or terminate TLS at a trusted reverse proxy and set
`PBXSENSE_AGENT_PUBLIC_URL` to its canonical HTTPS origin. The certificate must
be trusted by Android and valid for the advertised hostname. TLS does not make
public exposure safe by itself: keep the Agent behind controlled access and
retain token authentication.

The hosted PBXSense relay carries activation, Agent presence, paired-device
registration, eligible Signal notifications, and opaque encrypted Home
snapshots for apps that explicitly enable Internet Relay while pairing. The
Agent capability is available by default but publishes no encrypted snapshot
without an opted-in app encryption key. It never
receives PBX credentials or plaintext PBX snapshots.

Each app creates its own X25519 key during QR pairing and stores the private key
in platform secure storage. The Agent receives only that app's public key and
creates a separate AES-256-GCM envelope using an ephemeral X25519 key and
HKDF-SHA256. Agent identity, device identity, sequence, and creation time are
authenticated as associated data. Relay data is rejected after 60 seconds on
legacy envelope timing, or after 105 seconds when current Agent-heartbeat
liveness is present. Recordings are removed before encryption. Diagnostics, recordings, and
interactive PBX control remain local/VPN-only.

The outbound control session uses the Agent's Ed25519 installation identity.
Secure requests sign a nonce, HTTP method, path, and body digest; the relay
records nonces to reject replay. The command allowlist remains limited to the
operator `ping`/`pong` smoke test.

## Agent Token

`PBXSENSE_AGENT_TOKEN` is mandatory for every non-mock deployment. The Agent
refuses to start without it; the native and Docker setup wizards generate it
automatically.

Native and Docker installers print a browser setup URL containing a separate,
single-use credential that expires after 15 minutes; they never print the
installation-wide Agent token. The credential is carried in the URL fragment,
which is never sent in the HTTP request and is removed from browser history
before a Bearer-authenticated session exchange. Its consumed hash is persisted
under the Agent data directory so an Agent restart cannot reuse it. Plain HTTP
setup is restricted to loopback; private LAN and VPN setup requires HTTPS.
Successful access creates a long-lived, renewable HttpOnly, SameSite=Strict
cookie. HTTPS Agent origins also mark the cookie `Secure`.

When a token is set, every protected HTTP and `/live` request must authenticate,
including requests from localhost, a private LAN, or a VPN. Tokens are accepted
through Bearer or `X-PBXSense-Token` headers; query-string credentials are
rejected. The Agent does not enable cross-origin browser access. `GET /health`,
`GET /health/live`, `GET /health/ready`, the favicon, and the token-free
`/session` bootstrap page are the only
unauthenticated routes and disclose no PBX state.

All Agent responses use `Cache-Control: no-store, private`, `Referrer-Policy:
no-referrer`, MIME-sniffing and frame protections, and a restrictive Content
Security Policy so protected PBX data and recordings are not retained by normal
browser caches.

State-changing Agent routes accept native-app Bearer/header authentication.
When the protected Agent page uses its local HTTP-only admin cookie instead,
the Agent also requires an exact matching browser Origin or Referer. This
prevents another web service on the same host but a different port from using
that cookie for push registration or paired-app removal.

Push registration bodies and relay text fields have explicit size limits.
Oversized request bodies are rejected before they can be persisted to the
Agent outbox, Firestore, or Firebase Cloud Messaging.

The hosted Relay fails closed for new enrollment when its mode is not
configured. Production deployment explicitly uses ticket enrollment. In the
target subscription flow, tickets are short-lived, single-use authorizations
issued by trusted subscription code and passed from the subscribed app to the
local Agent during QR pairing; end users never type or store them. Ticket mode
must not be enabled for new customers until that automatic entitlement exchange
is deployed. Existing Agents continue authenticating with
their durable Ed25519 identity. Firestore transactions enforce the hourly
notification quota across Cloud Run instances and restarts, and ticketed
accounts have a configurable Agent-count ceiling. In-memory source limits remain
an inexpensive first layer, while Google Cloud budgets and instance caps remain
the outer cost guardrails.

Release dependencies require `cryptography` 50.x. Versions before 49/50 are
affected by published 2026 advisories. Production installers, containers, and
release CI consume the generated `requirements.lock` files with
`--require-hashes`; edit the input `requirements.txt` files and regenerate both
locks together when updating dependencies.

Every push and pull request runs an exact-commit-pinned dependency audit,
GitHub CodeQL extended security analysis, and a hardened-container build that
confirms the non-root runtime user. Dependabot monitors GitHub Actions, Python
dependencies, and both Docker build contexts. Release jobs generate a CycloneDX
SBOM before checksums, then use GitHub's OIDC-backed Sigstore service to attach
both SLSA build provenance and an SBOM attestation to the installer. Release
consumers can verify provenance with:

```bash
gh attestation verify \
  PBXSenseAgent-0.6.5-beta-linux-source-installer.tar.gz \
  --repo techmaniac89/pbxsense-agent
```

All third-party workflow actions are pinned to immutable commits. Review and
merge Dependabot updates rather than allowing unattended security-tool changes.

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

The Agent refuses non-local `http://` relay URLs. Hosted relay traffic must use
HTTPS for activation secrets, device registrations, Signals, presence, and
encrypted snapshot envelopes. Plain HTTP is reserved for an explicit localhost
development relay.

`endpoint_activity.json` in the same persistent data directory contains only
extension identifiers and last-active timestamps. It contains no PBX
credentials, but it is operational metadata and should remain protected by the
Agent data-directory permissions and backup policy.

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

The installed application tree is root-owned and read-only to the service user.
Only `/var/lib/pbxsense-agent` and `/var/log/pbxsense-agent` are writable. The
systemd unit also uses:

```text
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
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

The supplied Compose profile runs with a read-only root filesystem, drops all
Linux capabilities, enables `no-new-privileges`, and keeps only the Agent data
and log volumes writable.

CUCM and Yeastar HTTPS certificate verification should remain enabled. If an
operator disables it for a legacy PBX, diagnostics retain a security warning;
use a trusted internal CA instead of leaving verification disabled.

Cisco's JTAPI Client jars are cluster-supplied proprietary dependencies and
are intentionally not committed, packaged, or uploaded in the Docker build
context. Store them only in the ignored `vendor/jtapi` deployment directory.
The bridge receives its credential through the protected Agent environment,
not through command-line arguments, and runs with the same unprivileged
`pbxsense` identity as the Agent.

## Diagnostics Data

Diagnostics should explain connection and configuration failures without
promoting raw PBX events into the app layer. Connector-specific protocol details
belong under diagnostics or `technical` evidence.

When sharing diagnostics externally, review them for hostnames, IP addresses,
usernames, tokens, and deployment-specific paths.
