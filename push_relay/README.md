# PBXSense push relay

## Scope

This service is the production **notification and encrypted data relay**. It provides short-lived
Agent activation, signed Agent enrollment, presence heartbeats, paired-device
registration and revocation, and Firebase Cloud Messaging delivery for
eligible Signals.

It does not proxy the Agent's HTTP or WebSocket endpoints. Current Agents
publishes sanitized, per-app encrypted Home snapshots that the relay cannot
decrypt. Diagnostics, recordings, and PBX control remain local/VPN-only.

## Customer Agent installations

Customers do **not** deploy their own push relay. PBXSense operates one shared,
multi-site relay for customer Agents and their paired phones. Use the hosted URL
in every customer Agent environment:

```env
PBXSENSE_RELAY_URL=https://pbxsense-push-relay-299065188499.europe-west1.run.app
```

The protected Agent-page QR enrolls each Agent with the shared relay. Each Agent
gets its own cryptographic identity, and each phone is registered only with the
Agent it was paired to. Customers do not need Firebase credentials, a service
account key, a manual claim code, Cloud Run, Firestore, or Cloud Scheduler.

For a normal customer rollout, install the PBXSense Agent, keep the hosted relay
URL above, then scan the pairing QR from the app. That is the complete relay
setup for enrollment and push notifications. The Agent capability is ready by
default, while encrypted Home fallback remains an explicit per-app choice on
the pairing screen. To prohibit Internet Relay data for the whole installation:

```env
PBXSENSE_INTERNET_RELAY_ENABLED=false
```

Restart the Agent after changing this override. It does not affect push
notifications and never makes diagnostics, recordings, or PBX control remote.

## Optional self-hosted relay

The rest of this document is for PBXSense infrastructure administrators or an
enterprise customer that has explicitly chosen a private, self-hosted relay. It
is not required for standard Agent installations.

Deploy this directory to Cloud Run in the same Google Cloud project as the
Firebase app used by that deployment. The Cloud Run runtime service account
needs only Firebase Cloud Messaging Admin permission and Firestore access. Do
not create or download a service account key.

The protected Agent-page QR creates a short-lived activation for each Agent.
An enrolled Agent owns an Ed25519 private key locally and signs every
device-registration and event request. The relay stores only its public key.

Required Google Cloud services:

- Cloud Run
- Firestore in Native mode
- Firebase Cloud Messaging API

Required runtime configuration:

- `PBXSENSE_RELAY_ADMIN_TOKEN`, injected from Secret Manager
- a dedicated Cloud Run service account with Firebase Cloud Messaging Admin and
  Cloud Datastore User roles

Example build and deploy (run only by the relay project administrator):

```sh
GOOGLE_CLOUD_PROJECT=your-project-id sh ./deploy_cloud_run.sh
```

The deployment profile deliberately uses request-based scale-to-zero with
`min-instances=0`, `max-instances=3`, concurrency 80, a 15-second timeout,
one CPU, and 512 MiB memory. The maximum-instance setting is a strong cost
guardrail, not an absolute monetary cap: Cloud Run can briefly exceed it during
a traffic spike.

Create two independent Secret Manager secrets:

- `pbxsense-relay-admin` authenticates administrative sweep/ticket operations.
- `pbxsense-relay-ticket` signs enrollment capabilities and must not be placed
  in the open-source Agent, app, repository, image, or customer environment.

### Enrollment rollout

`PBXSENSE_RELAY_ENROLLMENT_MODE` supports three modes:

- `open` keeps compatibility while upgraded Agents roll out. New identities
  can enroll, so this is not the final paid-service setting.
- `ticket` requires a short-lived, single-use server-signed ticket for a new
  Agent identity. Already enrolled Agents create later pairing activations
  using their durable Ed25519 signature.
- `closed` pauses all new Agent identities while existing signed identities
  continue to pair apps.

The deployment script defaults to `open` for a safe staged upgrade. After
Agents have upgraded and the billing/licensing service can provision tickets,
deploy with:

```sh
GOOGLE_CLOUD_PROJECT=your-project-id \
PBXSENSE_RELAY_ENROLLMENT_MODE=ticket \
sh ./deploy_cloud_run.sh
```

Trusted billing/admin code obtains a 30-minute ticket with:

```http
POST /v1/internal/enrollment-tickets
X-PBXSense-Admin-Token: <Secret Manager admin token>
Content-Type: application/json

{"accountId":"customer_123","lifetimeMinutes":30}
```

Provision the returned opaque value once as
`PBXSENSE_RELAY_ENROLLMENT_TICKET` on the new Agent. It is consumed only when
the first app claims the activation. It is not a Firebase credential and cannot
be used to sign another ticket.

The relay additionally enforces:

- six activation requests per source address per minute per instance;
- 120 total requests per source address per minute per instance;
- ten paired apps per Agent by default;
- 60 notification events per Agent per hour per instance;
- a 2 MiB encrypted-snapshot request limit;
- bounded identifiers before Agent/device Firestore lookups;
- signed activation refreshes for existing identities in `ticket`/`closed`
  mode.

These application limits complement Cloud Run scaling; they do not replace an
edge DDoS service for a high-volume public deployment.

### Billing guardrail

Keep the relay in its own Google Cloud project. Create a project-scoped monthly
budget after choosing an amount:

```sh
GOOGLE_CLOUD_PROJECT=your-project-id \
GOOGLE_CLOUD_BILLING_ACCOUNT=000000-000000-000000 \
PBXSENSE_RELAY_MONTHLY_BUDGET=25EUR \
sh ./create_budget.sh
```

This creates actual-spend alerts at 20%, 40%, 80%, and 100%, plus a forecast
alert at 60%. A Google Cloud budget sends alerts but does not stop billing.
Connect it to Pub/Sub before implementing an automated emergency shutdown, and
keep that shutdown project-scoped so it cannot affect unrelated services.

A self-hosted Agent uses the resulting HTTPS URL instead of the PBXSense-hosted
URL in `PBXSENSE_RELAY_URL`. Pairing through its protected QR page completes
enrollment; it never needs a Firebase service-account key or a manual claim
code.

Create a Cloud Scheduler job that POSTs to
`/v1/internal/sweep-agent-heartbeats` once per minute with the
`X-PBXSense-Admin-Token` header. Agents send a heartbeat every 30 seconds; the
relay marks one as lost after 90 seconds without one, then sends a recovery
notification on the next heartbeat. Because Cloud Scheduler runs once a minute,
loss delivery can occur up to one additional minute after that 90-second limit.

The relay is publicly reachable only so Agents behind customer NAT can post to
it. Every Agent request is Ed25519-signed and every administrative request
requires the Secret Manager-backed administrator token; do not grant public
access to Firestore itself.

Cloud Logging records only FCM outcome counts (eligible, accepted, failed, and
invalid registrations removed); it never logs FCM tokens.
Relay service `0.5.1` provides the encrypted Internet Relay data path and
cost/enrollment guardrails. Updated apps
create an X25519 key during QR activation; the service returns a random,
per-device access credential and stores only its hash. Agents publish a
separate AES-256-GCM envelope for each device. Firestore and the Cloud Run
service see only encrypted snapshot bytes and routing metadata.

The snapshot API deliberately excludes recordings and does not expose
diagnostics or PBX control. Envelopes carry authenticated sequence and creation
metadata. Current apps allow 105 seconds from Agent heartbeat liveness, while
older envelope-only responses retain a 60-second limit. Older apps can
still claim an activation for push delivery without requesting an encryption
key, which permits staged rollout of the Agent, relay, and app. Every newly
paired app receives a scoped device bearer credential. **Reset connection**
uses it to delete only that app's FCM registration directly from the relay, so
revocation still works while the Agent is offline or being rebuilt.
The next registration removes older records carrying the same FCM token across
Agent identities, migrating push-only pairings left behind by Agent rebuilds
before scoped credentials existed.

The 0.5.1 cost profile is local-first: Agents check for changed relay snapshots
every 15 seconds, do not rewrite unchanged ciphertext, cache device lists for
five minutes, and poll the bounded control channel at most every five minutes.
Remote apps default to a server-controlled 60-second fallback interval when the
LAN Agent is unavailable. The relay returns this policy with encrypted snapshot
responses, so operators can tune it between 15 and 300 seconds without shipping
another app build. Snapshot liveness comes from the existing 30-second Agent
heartbeat, so cost tuning never weakens Agent-down detection.

### Privacy-safe usage monitoring

The authenticated `GET /v1/internal/usage` endpoint reports current UTC-day
totals for heartbeats, control exchanges, encrypted snapshot publication,
remote snapshot reads, and encrypted bytes. It also reports active Agents,
registered apps, and recently connected apps. Agent identifiers are one-way
SHA-256 prefixes; PBX state, calls, extensions, FCM tokens, and encrypted
payloads are never returned.

Heartbeat and remote-read counters reuse Firestore writes already required for
presence and snapshot delivery. Snapshot publication adds one small metadata
write only when the Agent publishes changed encrypted state; no extra write is
added for each heartbeat or app poll. Query the report from an administrator
workstation:

```sh
TOKEN="$(gcloud secrets versions access latest \
  --secret=pbxsense-relay-admin \
  --project="$GOOGLE_CLOUD_PROJECT")"
curl -fsS \
  -H "X-PBXSense-Admin-Token: $TOKEN" \
  "$PBXSENSE_RELAY_URL/v1/internal/usage"
```

`PBXSENSE_RELAY_REMOTE_APP_POLL_SECONDS` controls the remote app fallback
interval (15–300 seconds). `PBXSENSE_RELAY_CONTROL_EXCHANGE_SECONDS` controls
the Agent's capability-scoped control exchange (60–900 seconds). Keep presence
at 30/90 seconds; adjust these two noncritical intervals after reviewing real
usage and Cloud Run/Firestore billing metrics.

An administrator can verify an enabled Agent session with an authenticated
`POST /v1/internal/agents/{agent_id}/secure/ping`. The Agent returns `pong` on
its following outbound exchange; inspect the `secureCommands` document for its
completed state. This endpoint is an operator smoke test, not an app API.
