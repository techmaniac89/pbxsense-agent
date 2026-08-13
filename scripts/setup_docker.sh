#!/bin/sh
# Interactive PBXSense Docker configuration and startup.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ENV_FILE="$PROJECT_DIR/.env"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker with the Compose plugin is required."
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "The Docker Compose plugin is required (docker compose)."
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for the interactive configuration wizard."
  exit 1
fi

PBXSENSE_CONFIGURE_ONLY=true \
PBXSENSE_ENV_FILE="$ENV_FILE" \
  sh "$SCRIPT_DIR/install_common.sh"

pbx_type="$(awk -F= '$1 == "PBXSENSE_PBX_TYPE" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
compose_files="--env-file .env -f docker/docker-compose.yml"
case "$pbx_type" in
  asterisk|ami|freepbx|issabel|vitalpbx)
    compose_files="$compose_files -f docker/docker-compose.asterisk.yml"
    ;;
  freeswitch|fusionpbx)
    compose_files="$compose_files -f docker/docker-compose.freeswitch.yml"
    ;;
  grandstream|grandstream-ucm|ucm6300)
    compose_files="$compose_files -f docker/docker-compose.grandstream.yml"
    ;;
  cucm|cisco|cisco-cucm)
    compose_files="$compose_files -f docker/docker-compose.cucm.yml"
    ;;
esac

start_agent="yes"
if [ -t 0 ]; then
  printf "Build and start PBXSense Agent now? [Y/n]: "
  read -r answer
  case "$answer" in
    n|N|no|NO) start_agent="no" ;;
  esac
fi

if [ "$start_agent" = "yes" ]; then
  cd "$PROJECT_DIR"
  # compose_files contains repository-controlled filenames without spaces.
  # Intentional word splitting passes each -f argument to Docker Compose.
  docker compose $compose_files up -d --build
  echo "PBXSense Agent is running."
else
  echo "Configuration saved. Start later with: docker compose $compose_files up -d --build"
fi

bootstrap_token="$(awk -F= '$1 == "PBXSENSE_BROWSER_BOOTSTRAP_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
port="$(awk -F= '$1 == "PBXSENSE_AGENT_PORT" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
[ -n "$port" ] || port="8765"
public_url="$(awk -F= '$1 == "PBXSENSE_AGENT_PUBLIC_URL" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
certificate="$(awk -F= '$1 == "PBXSENSE_AGENT_TLS_CERTFILE" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
if [ -n "$public_url" ]; then
  admin_origin="${public_url%/}"
elif [ -n "$certificate" ]; then
  host="${PBXSENSE_ACCESS_HOST:-}"
  if [ -z "$host" ]; then
    host="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  [ -n "$host" ] || host="$(hostname 2>/dev/null || printf '%s' '127.0.0.1')"
  admin_origin="https://$host:$port"
else
  admin_origin="http://127.0.0.1:$port"
fi
echo "Open PBXSense Agent on this PC:"
echo "$admin_origin/session#token=$bootstrap_token"
if [ -z "$certificate" ] && [ -z "$public_url" ]; then
  echo "Because TLS is not configured, open this loopback setup link on the Agent host."
fi
echo "This setup credential is single-use and expires after 15 minutes."
echo "The browser remains authorized until its site data is cleared or the Agent token changes."
