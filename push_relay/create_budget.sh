#!/bin/sh
set -eu

: "${GOOGLE_CLOUD_PROJECT:?Set GOOGLE_CLOUD_PROJECT}"
: "${GOOGLE_CLOUD_BILLING_ACCOUNT:?Set GOOGLE_CLOUD_BILLING_ACCOUNT}"

BUDGET_AMOUNT="${PBXSENSE_RELAY_MONTHLY_BUDGET:-25EUR}"

gcloud billing budgets create \
  --billing-account "$GOOGLE_CLOUD_BILLING_ACCOUNT" \
  --display-name "PBXSense relay monthly guardrail" \
  --budget-amount "$BUDGET_AMOUNT" \
  --calendar-period month \
  --filter-projects "projects/$GOOGLE_CLOUD_PROJECT" \
  --threshold-rule percent=0.2,basis=current-spend \
  --threshold-rule percent=0.4,basis=current-spend \
  --threshold-rule percent=0.6,basis=forecasted-spend \
  --threshold-rule percent=0.8,basis=current-spend \
  --threshold-rule percent=1.0,basis=current-spend
