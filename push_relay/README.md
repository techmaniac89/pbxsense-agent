# PBXSense push relay

## Scope

This service is the production **notification relay**. It provides short-lived
Agent activation, signed Agent enrollment, presence heartbeats, paired-device
registration and revocation, and Firebase Cloud Messaging delivery for
eligible Signals.

It does not proxy the Agent's `/health`, `/home`, `/live`, diagnostics, or
recording endpoints to the mobile app. It is therefore not the full Canopy
Internet-access Relay described in the app roadmap. Until that separate data
path is implemented, live app access away from the LAN requires a VPN or a
directly reachable HTTPS Agent.

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
setup on the customer side.

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
