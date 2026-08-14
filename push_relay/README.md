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

The Relay application itself defaults to `closed`, so a missing environment
variable cannot accidentally expose public enrollment. The official deployment
script explicitly defaults to `ticket`; use `open` only as a deliberate,
temporary development or migration override.

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

The target production subscription flow does not ask users to enter this
ticket: after a purchase or restore, the app will ask the subscription backend
for a short-lived authorization and pass it to the local Agent during QR
pairing. That automatic entitlement exchange must be deployed before switching
new customer enrollment to ticket mode. Until then, beta deployments must
explicitly choose `open`, while `PBXSENSE_RELAY_ENROLLMENT_TICKET` remains an
operator-only bootstrap mechanism for controlled testing and support. A ticket
is consumed when the first app claims the activation and is not a Firebase
credential.

The relay additionally enforces:

- 60 activation requests per trusted source address per minute and 12 per
  Agent public key per instance;
- 120 total requests per source address per minute per instance;
- ten paired apps per Agent by default;
- ten Agents per subscription account by default;
- 60 notification events per Agent per hour, enforced transactionally in
  Firestore across instances and cold starts;
- a 2 MiB encrypted-snapshot request limit;
- bounded identifiers before Agent/device Firestore lookups;
- nonce-bound signed activation refreshes for every existing Agent identity,
  including during staged `open` enrollment.

Ticket enrollment fails startup unless `PBXSENSE_RELAY_TICKET_SECRET` is set,
and it must differ from the administrator token. Administrative browser
sessions store a derived, eight-hour HttpOnly cookie rather than the raw admin
token. Signed Agent mutations include a one-time nonce; replayed requests are
rejected even inside the five-minute timestamp window.

Enable Firestore TTL on the `expiresAt` field for the `activationNonces`,
`secureNonces`, and `rateLimits` collection groups. Nonce documents are
authentication state and rate-limit documents are short-lived quota counters;
both are safe to delete after their enforcement windows.

Deploy compatibility note: Agent `0.6.0-beta` sends both the legacy signature
and the nonce-bound signature. Upgrade Agents first, then deploy Relay `0.5.17`,
which requires nonce-bound signatures. Older Agents will receive HTTP 401 from
signed Relay endpoints after that Relay upgrade.

These application limits complement Cloud Run scaling; they do not replace an
edge DDoS service for a high-volume public deployment.

### Grouped phone-availability delivery

The Agent may publish multiple event IDs for successive states of one grouped
phone-availability incident while assigning them one stable Android
notification tag. The event IDs preserve relay idempotency; the stable tag
causes the newest count or final recovery to replace the earlier notification.

The Relay transports the Agent's selected wording and does not infer outage
scope. The Agent must use shared network/PBX wording only for three or more
currently affected phones. If the count drops below three, subsequent updates
must use individual or remaining-phone wording.

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
Relay service `0.5.17` provides the encrypted Internet Relay data path and
cost/enrollment guardrails. Updated apps
create an X25519 key during QR activation; the service returns a random,
per-device access credential and stores only its hash. Agents publish a
separate AES-256-GCM envelope for each device. Firestore and the Cloud Run
service see only encrypted snapshot bytes and routing metadata.

Paired-device registrations are renewed whenever the app registers its current
FCM token and expire after 90 days without renewal. This tolerates normal gaps
between app launches without retaining abandoned records indefinitely.

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

The 0.5.17 cost profile is local-first: Agents check for changed relay snapshots
every 15 seconds, do not rewrite unchanged ciphertext, cache device lists for
five minutes, and poll the bounded control channel at most every five minutes.
Remote apps default to a server-controlled 60-second fallback interval when the
LAN Agent is unavailable. The relay returns this policy with encrypted snapshot
responses, so operators can tune it between 15 and 300 seconds without shipping
another app build. Snapshot liveness comes from the existing 30-second Agent
heartbeat, so cost tuning never weakens Agent-down detection.

### Privacy-safe usage monitoring

Open `/admin/usage` and enter the Relay administrator token for the private
operator dashboard. It shows current fleet presence, the remotely delivered
policy, per-day counters, and hashed Agent activity. Relay `0.5.17` also shows
Firebase acceptance/failure and latency, notification-quota pressure,
heartbeat-scheduler freshness, remote-snapshot availability, encrypted-data
coverage, expiring registrations, retention expectations, and a seven-day
workload trend. Its secure, HTTP-only session expires after eight hours and the
dashboard refreshes every five minutes.

The workload figure is deliberately labeled as a proxy. It combines protocol
operations and encrypted bytes but is not a Google Cloud invoice. Use Cloud
Run, Firestore, Firebase, and Cloud Billing metrics as the authoritative source
for platform latency and cost. Firebase acceptance means FCM accepted a send;
it does not prove Android displayed the notification.

The portal allocates a gross estimated Relay cost to each hashed Agent for the
current UTC day and projects that workload over 30 days. The model covers Cloud
Run requests, estimated request CPU/memory time, estimated Firestore
reads/writes/deletes, and encrypted-snapshot egress. It intentionally excludes
free-tier allocation, discounts, taxes, stored data, shared scheduler/dashboard
overhead, and unobserved platform work. It is suitable for capacity planning,
not customer invoicing.
The projection annualizes the current UTC day's observed workload with a
one-hour minimum denominator, so it can move noticeably early in the day.

The compiled defaults use the public
[Cloud Run](https://cloud.google.com/run/pricing) and
[Firestore](https://cloud.google.com/firestore/pricing) reference list prices
and a 50 ms average request duration. Firebase documents
[Cloud Messaging as a no-cost product](https://firebase.google.com/docs/projects/billing/firebase-pricing-plans).
Calibrate these Relay service variables from the deployed project's Cloud
Billing export:

```env
PBXSENSE_RELAY_COST_CURRENCY=USD
PBXSENSE_RELAY_COST_CLOUD_RUN_REQUEST_USD=0.0000004
PBXSENSE_RELAY_COST_CLOUD_RUN_VCPU_SECOND_USD=0.000024
PBXSENSE_RELAY_COST_CLOUD_RUN_GIB_SECOND_USD=0.0000025
PBXSENSE_RELAY_COST_AVERAGE_REQUEST_SECONDS=0.05
PBXSENSE_RELAY_COST_AVERAGE_REQUEST_VCPU=1
PBXSENSE_RELAY_COST_AVERAGE_REQUEST_MEMORY_GIB=0.5
PBXSENSE_RELAY_COST_FIRESTORE_READ_USD=0.0000003
PBXSENSE_RELAY_COST_FIRESTORE_WRITE_USD=0.0000009
PBXSENSE_RELAY_COST_FIRESTORE_DELETE_USD=0.0000001
PBXSENSE_RELAY_COST_EGRESS_GIB_USD=0.12
```

The authenticated `GET /v1/internal/usage` endpoint exposes the same data as
JSON. It reports current UTC-day totals for heartbeats, control exchanges,
encrypted snapshot publication, remote snapshot reads, and encrypted bytes,
plus seven days of daily history. It also reports active Agents, registered
apps, and recently connected apps. Agent identifiers are one-way SHA-256
prefixes; PBX state, calls, extensions, FCM tokens, and encrypted payloads are
never returned.

Heartbeat and remote-read counters reuse Firestore writes already required for
presence and snapshot delivery. When an entity first becomes active on a new
UTC day—or the dashboard observes its completed day—the Relay archives the
previous counters once under an idempotent hashed entity key. Snapshot
publication adds one small metadata write only when the Agent publishes changed
encrypted state; no rollup write is added for each heartbeat or app poll. Query
the JSON report from an administrator workstation:

Rollup entity records carry a 90-day `expiresAt` timestamp. Enable Firestore TTL
for the `entities` collection group's `expiresAt` field so historical operator
metadata is deleted automatically after that window.

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
