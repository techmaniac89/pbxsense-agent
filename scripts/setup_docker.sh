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
    if [ ! -f "$PROJECT_DIR/docker/docker-compose.detected.yml" ]; then
      compose_files="$compose_files -f docker/docker-compose.asterisk.yml"
    fi
    ;;
  freeswitch|fusionpbx)
    if [ ! -f "$PROJECT_DIR/docker/docker-compose.detected.yml" ]; then
      compose_files="$compose_files -f docker/docker-compose.freeswitch.yml"
    fi
    ;;
  grandstream|grandstream-ucm|ucm6300)
    compose_files="$compose_files -f docker/docker-compose.grandstream.yml"
    ;;
  cucm|cisco|cisco-cucm)
    compose_files="$compose_files -f docker/docker-compose.cucm.yml"
    ;;
esac
case "$pbx_type" in
  asterisk|ami|freepbx|issabel|vitalpbx|freeswitch|fusionpbx)
    if [ -f "$PROJECT_DIR/docker/docker-compose.detected.yml" ]; then
      compose_files="$compose_files -f docker/docker-compose.detected.yml"
    fi
    ;;
esac

start_agent="yes"
echo "[4/4] Start and check the Agent"
echo "Starting builds the Agent image and uses the read-only PBX mounts selected above."
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
  case "$pbx_type" in
    asterisk|freeswitch)
      docker compose $compose_files exec -T pbxsense-agent python scripts/installer_paths.py report --mode docker || true
      echo "Recheck without reinstalling: docker compose $compose_files exec -T pbxsense-agent python scripts/installer_paths.py report --mode docker"
      echo "For a completed-call check, run: docker compose $compose_files exec -T pbxsense-agent python scripts/installer_paths.py watch-cdr --mode docker"
      ;;
  esac
else
  echo "Configuration saved. Start later with: docker compose $compose_files up -d --build"
fi

bootstrap_token="$(awk -F= '$1 == "PBXSENSE_BROWSER_BOOTSTRAP_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
port="$(awk -F= '$1 == "PBXSENSE_AGENT_PORT" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
[ -n "$port" ] || port="8765"
public_url="$(awk -F= '$1 == "PBXSENSE_AGENT_PUBLIC_URL" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
certificate="$(awk -F= '$1 == "PBXSENSE_AGENT_TLS_CERTFILE" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
trusted_lan="$(awk -F= '$1 == "PBXSENSE_TRUSTED_LAN_HTTP" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")"
if [ -n "$public_url" ]; then
  admin_origin="${public_url%/}"
elif [ -n "$certificate" ] || [ "$trusted_lan" = "true" ]; then
  host="${PBXSENSE_ACCESS_HOST:-}"
  if [ -z "$host" ]; then
    host="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  [ -n "$host" ] || host="$(hostname 2>/dev/null || printf '%s' '127.0.0.1')"
  if [ -n "$certificate" ]; then
    admin_origin="https://$host:$port"
  else
    admin_origin="http://$host:$port"
    echo "WARNING: trusted-LAN HTTP is unencrypted; codes and admin sessions can be intercepted."
  fi
else
  admin_origin="http://127.0.0.1:$port"
fi
echo "Open PBXSense Agent on this PC:"
echo "$admin_origin/session#token=$bootstrap_token"
if [ -z "$certificate" ] && [ -z "$public_url" ] && [ "$trusted_lan" != "true" ]; then
  echo "Because TLS is not configured, open this loopback setup link on the Agent host."
fi
echo "This setup credential is single-use and expires after 15 minutes."
echo "Open the setup link above to authorize this browser, then pair the mobile app from the Agent page."
echo "If you chose not to start now, the link may expire before startup; generate a fresh setup credential before recreating the container."
echo "The browser remains authorized until its site data is cleared or the Agent token changes."
