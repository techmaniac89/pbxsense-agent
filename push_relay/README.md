# PBXSense push relay

## Scope

This service is the production **notification and encrypted data relay**. It provides short-lived
Agent activation, signed Agent enrollment, presence heartbeats, paired-device
registration and revocation, and Firebase Cloud Messaging delivery for
eligible Signals.

It does not proxy the Agent's HTTP or WebSocket endpoints. Agent 0.4.0 instead
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
setup for enrollment and push notifications. Encrypted Home fallback is an
explicit Agent opt-in:

```env
PBXSENSE_INTERNET_RELAY_ENABLED=true
```

Restart the Agent after enabling it. This setting is not required for push
notifications and does not make diagnostics, recordings, or PBX control remote.

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
gcloud run deploy pbxsense-push-relay \
  --source . \
  --region europe-west1 \
  --allow-unauthenticated \
  --service-account pbxsense-push-relay@PROJECT_ID.iam.gserviceaccount.com \
  --set-secrets PBXSENSE_RELAY_ADMIN_TOKEN=pbxsense-relay-admin:latest
```

A self-hosted Agent uses the resulting HTTPS URL instead of the PBXSense-hosted
URL in `PBXSENSE_RELAY_URL`. Pairing through its protected QR page completes
enrollment; it never needs a Firebase service-account key or a manual claim
code.

Create a Cloud Scheduler job that POSTs to
`/v1/internal/sweep-agent-heartbeats` once per minute with the
`X-PBXSense-Admin-Token` header. Agents send a heartbeat every 15 seconds; the
relay marks one as lost after 60 seconds without one, then sends a recovery
notification on the next heartbeat. Because Cloud Scheduler runs once a minute,
loss delivery can occur up to one additional minute after that 60-second limit.

The relay is publicly reachable only so Agents behind customer NAT can post to
it. Every Agent request is Ed25519-signed and every administrative request
requires the Secret Manager-backed administrator token; do not grant public
access to Firestore itself.

Cloud Logging records only FCM outcome counts (eligible, accepted, failed, and
invalid registrations removed); it never logs FCM tokens.
Relay service `0.4.6` provides the encrypted Internet Relay data path. Updated apps
create an X25519 key during QR activation; the service returns a random,
per-device access credential and stores only its hash. Agents publish a
separate AES-256-GCM envelope for each device. Firestore and the Cloud Run
service see only encrypted snapshot bytes and routing metadata.

The snapshot API deliberately excludes recordings and does not expose
diagnostics or PBX control. Envelopes carry authenticated sequence and creation
metadata and updated apps reject data older than 60 seconds. Older apps can
still claim an activation for push delivery without requesting an encryption
key, which permits staged rollout of the Agent, relay, and app. Every newly
paired app receives a scoped device bearer credential. **Reset connection**
uses it to delete only that app's FCM registration directly from the relay, so
revocation still works while the Agent is offline or being rebuilt.
The next registration removes older records carrying the same FCM token across
Agent identities, migrating push-only pairings left behind by Agent rebuilds
before scoped credentials existed.

The 0.4.6 cost profile is local-first: Agents check for changed relay snapshots
every 15 seconds, do not rewrite unchanged ciphertext, cache device lists for
five minutes, and poll the bounded control channel at most every five minutes.
Remote apps read snapshots every 15 seconds. Snapshot liveness comes from the
existing Agent heartbeat, so unchanged PBX state no longer needs periodic
ciphertext rewrites.

An administrator can verify an enabled Agent session with an authenticated
`POST /v1/internal/agents/{agent_id}/secure/ping`. The Agent returns `pong` on
its following outbound exchange; inspect the `secureCommands` document for its
completed state. This endpoint is an operator smoke test, not an app API.
