#!/bin/sh
set -eu

scheme=http
if [ -n "${PBXSENSE_AGENT_TLS_CERTFILE:-}" ]; then
  scheme=https
fi

exec curl --fail --silent --show-error --insecure --max-time 3 \
  "${scheme}://127.0.0.1:${PBXSENSE_AGENT_PORT:-8765}/health"
