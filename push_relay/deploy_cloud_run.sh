#!/bin/sh
set -eu

: "${GOOGLE_CLOUD_PROJECT:?Set GOOGLE_CLOUD_PROJECT}"

REGION="${PBXSENSE_RELAY_REGION:-europe-west1}"
SERVICE="${PBXSENSE_RELAY_SERVICE:-pbxsense-push-relay}"
SERVICE_ACCOUNT="${PBXSENSE_RELAY_SERVICE_ACCOUNT:-pbxsense-push-relay@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com}"
ENROLLMENT_MODE="${PBXSENSE_RELAY_ENROLLMENT_MODE:-open}"

gcloud run deploy "$SERVICE" \
  --project "$GOOGLE_CLOUD_PROJECT" \
  --source "$(dirname "$0")" \
  --region "$REGION" \
  --allow-unauthenticated \
  --service-account "$SERVICE_ACCOUNT" \
  --min-instances 0 \
  --max-instances 3 \
  --concurrency 80 \
  --timeout 15s \
  --cpu 1 \
  --memory 512Mi \
  --set-secrets "PBXSENSE_RELAY_ADMIN_TOKEN=pbxsense-relay-admin:latest,PBXSENSE_RELAY_TICKET_SECRET=pbxsense-relay-ticket:latest" \
  --set-env-vars "PBXSENSE_RELAY_ENROLLMENT_MODE=$ENROLLMENT_MODE,PBXSENSE_RELAY_MAX_DEVICES_PER_AGENT=10,PBXSENSE_RELAY_MAX_EVENTS_PER_AGENT_HOUR=60,PBXSENSE_RELAY_MAX_SNAPSHOT_BYTES=2097152,PBXSENSE_RELAY_REMOTE_APP_POLL_SECONDS=60,PBXSENSE_RELAY_CONTROL_EXCHANGE_SECONDS=300"
