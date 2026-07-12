# PBXSense push relay

Deploy this directory to Cloud Run in the same Google Cloud project as Firebase.
The Cloud Run runtime service account needs only the Firebase Cloud Messaging
Admin permission and Firestore access. Do not create or download a service
account key.

The relay creates one-time Agent claim codes through `POST /v1/admin/claims`.
Protect that endpoint with `PBXSENSE_RELAY_ADMIN_TOKEN` stored in Secret
Manager. An enrolled Agent owns an Ed25519 private key locally and signs every
device-registration and event request. The relay stores only its public key.

Required Google Cloud services:

- Cloud Run
- Firestore in Native mode
- Firebase Cloud Messaging API

Required runtime configuration:

- `PBXSENSE_RELAY_ADMIN_TOKEN`, injected from Secret Manager
- a dedicated Cloud Run service account with Firebase Cloud Messaging Admin and
  Cloud Datastore User roles

Example build and deploy (run by a project administrator):

```sh
gcloud run deploy pbxsense-push-relay \
  --source . \
  --region europe-west1 \
  --allow-unauthenticated \
  --service-account pbxsense-push-relay@PROJECT_ID.iam.gserviceaccount.com \
  --set-secrets PBXSENSE_RELAY_ADMIN_TOKEN=pbxsense-relay-admin:latest
```

The Agent needs the resulting HTTPS URL and a one-time claim code. It never
needs a Firebase service-account key.

The relay is publicly reachable only so Agents behind customer NAT can post to
it. Every Agent request is Ed25519-signed and every administrative request
requires the Secret Manager-backed administrator token; do not grant public
access to Firestore itself.
