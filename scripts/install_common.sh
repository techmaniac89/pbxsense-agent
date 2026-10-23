#!/bin/sh
# Shared service setup used by the distribution-specific entry points.
set -e

SERVICE_USER="pbxsense"
SERVICE_NAME="pbxsense-agent"
INSTALL_DIR="${PBXSENSE_INSTALL_DIR:-/opt/pbxsense-agent}"
ENV_FILE="${PBXSENSE_ENV_FILE:-/etc/pbxsense-agent.env}"
AGENT_PORT="${PBXSENSE_AGENT_PORT:-8765}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

is_interactive() {
  [ -t 0 ]
}

env_value() {
  awk -F= -v key="$1" '
    $1 == key {
      sub(/^[^=]*=/, "")
      print
      exit
    }
  ' "$ENV_FILE" 2>/dev/null || true
}

set_env_value() {
  python3 - "$ENV_FILE" "$1" "$2" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
line = f"{key}={value}"

lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
updated = []
found = False

for existing in lines:
    if existing.startswith(f"{key}="):
        updated.append(line)
        found = True
    else:
        updated.append(existing)

if not found:
    if updated and updated[-1].strip():
        updated.append("")
    updated.append(line)

path.write_text("\n".join(updated) + "\n", encoding="utf-8")
PY
}

normalize_pbx_type() {
  normalized="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '_' | tr -d '-' | tr -d '[:space:]')"
  case "$normalized" in
    ami|asteriskami|asterisk|freepbx|issabel|vitalpbx) printf '%s\n' "asterisk" ;;
    grandstream|grandstreamucm|ucm|ucm6xxx|ucm62xx|ucm63xx|ucm6100|ucm6200|ucm6300|ucm6300a|ucm6300audio|ucm6510) printf '%s\n' "grandstream" ;;
    fs|freeswitch|fusionpbx) printf '%s\n' "freeswitch" ;;
    yeastar|yeastarpseries|pseries) printf '%s\n' "yeastar" ;;
    cucm|ciscocucm|ciscounifiedcommunicationsmanager) printf '%s\n' "cucm" ;;
    mock) printf '%s\n' "mock" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

prompt_value() {
  key="$1"
  label="$2"
  default="$3"
  current="$(env_value "$key")"
  if [ -n "$current" ] && [ "$current" != "change-me-before-running" ]; then
    default="$current"
  fi

  if is_interactive; then
    printf "%s [%s]: " "$label" "$default"
    read -r answer
    if [ -n "$answer" ]; then
      default="$answer"
    fi
  fi

  set_env_value "$key" "$default"
}

prompt_secret() {
  key="$1"
  label="$2"
  default="$3"
  current="$(env_value "$key")"
  if [ -n "$current" ] && [ "$current" != "change-me-before-running" ]; then
    default="$current"
  fi

  if is_interactive; then
    if [ -n "$default" ]; then
      printf "%s [keep existing]: " "$label"
    else
      printf "%s: " "$label"
    fi
    if command -v stty >/dev/null 2>&1; then
      trap 'stty echo 2>/dev/null || true' 0
      trap 'exit 130' INT
      trap 'exit 143' TERM
      stty -echo
      read -r answer
      stty echo
      trap - 0 INT TERM
      printf "\n"
    else
      read -r answer
    fi
    if [ -n "$answer" ]; then
      default="$answer"
    fi
  fi

  set_env_value "$key" "$default"
}

first_existing_path() {
  for candidate in "$@"; do
    if [ -e "$candidate" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  printf '%s\n' "$1"
}

detect_timezone() {
  current="$(env_value PBXSENSE_TIMEZONE)"
  if [ -n "$current" ]; then
    printf '%s\n' "$current"
    return
  fi
  if [ -n "${TZ:-}" ]; then
    printf '%s\n' "$TZ"
    return
  fi
  if command -v timedatectl >/dev/null 2>&1; then
    detected="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
    if [ -n "$detected" ]; then
      printf '%s\n' "$detected"
      return
    fi
  fi
  if [ -r /etc/timezone ]; then
    head -n 1 /etc/timezone
    return
  fi
  printf '%s\n' "UTC"
}

detect_asterisk() {
  command -v asterisk >/dev/null 2>&1 || [ -d /etc/asterisk ]
}

detect_freeswitch() {
  command -v fs_cli >/dev/null 2>&1 || [ -d /etc/freeswitch ]
}

detect_ami_credentials() {
  manager_conf="/etc/asterisk/manager.conf"
  if [ ! -r "$manager_conf" ]; then
    return
  fi

  awk '
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
      section=$0
      gsub(/^[[:space:]]*\[/, "", section)
      gsub(/\][[:space:]]*$/, "", section)
      next
    }
    /^[[:space:]]*secret[[:space:]]*=/ && section != "" && section != "general" {
      value=$0
      sub(/^[^=]*=[[:space:]]*/, "", value)
      print section "|" value
      exit
    }
  ' "$manager_conf"
}

detect_freeswitch_password() {
  config="/etc/freeswitch/autoload_configs/event_socket.conf.xml"
  if [ ! -r "$config" ]; then
    return
  fi

  sed -n 's/.*<param[[:space:]][^>]*name="password"[^>]*value="\([^"]*\)".*/\1/p' "$config" | head -n 1
}

choose_manual_pbx_type() {
  manual_default="$1"
  case "$manual_default" in
    asterisk|freeswitch|yeastar|grandstream|cucm) ;;
    *) manual_default="asterisk" ;;
  esac
  while :; do
    echo "Available phone systems:" >&2
    echo "  1) Asterisk (FreePBX / Issabel / VitalPBX)" >&2
    echo "  2) FreeSWITCH / FusionPBX" >&2
    echo "  3) Yeastar P-Series" >&2
    echo "  4) Grandstream UCM" >&2
    echo "  5) Cisco CUCM" >&2
    printf "Choose a number or PBX type [%s]: " "$manual_default" >&2
    read -r answer || return 1
    case "$answer" in
      1) answer="asterisk" ;; 2) answer="freeswitch" ;;
      3) answer="yeastar" ;; 4) answer="grandstream" ;;
      5) answer="cucm" ;; "") answer="$manual_default" ;;
    esac
    selected="$(normalize_pbx_type "$answer")"
    case "$selected" in
      asterisk|freeswitch|yeastar|grandstream|cucm) printf '%s\n' "$selected"; return ;;
      *) echo "Choose one of the five supported phone systems." >&2 ;;
    esac
  done
}

choose_pbx_type() {
  # Explicit automation configuration remains supported, including developer mock.
  if [ -n "${PBXSENSE_PBX_TYPE:-}" ]; then
    normalize_pbx_type "$PBXSENSE_PBX_TYPE"
    return
  fi
  requested=""
  if [ "$ENV_CREATED" -eq 0 ]; then
    requested="$(env_value PBXSENSE_PBX_TYPE)"
  fi
  if ! is_interactive && [ -n "$requested" ]; then
    normalize_pbx_type "$requested"
    return
  fi
  if is_interactive; then
    while :; do
      echo "How would you like to select your PBX?" >&2
      echo "  1) Automatically detect a local PBX" >&2
      echo "  2) Select manually (also for remote PBXs and appliances)" >&2
      printf "Choose [1/2] [2]: " >&2
      read -r method || return 1
      case "$method" in
        1|auto|automatic) break ;;
        2|manual|"") choose_manual_pbx_type "$requested"; return ;;
        *) echo "Enter 1 or 2." >&2 ;;
      esac
    done
  fi
  has_asterisk=0
  has_freeswitch=0
  detect_asterisk && has_asterisk=1
  detect_freeswitch && has_freeswitch=1
  detected=""
  if [ "$has_asterisk" -eq 1 ] && [ "$has_freeswitch" -eq 0 ]; then
    detected="asterisk"
  elif [ "$has_freeswitch" -eq 1 ] && [ "$has_asterisk" -eq 0 ]; then
    detected="freeswitch"
  fi
  if [ -n "$detected" ]; then
    echo "Local $detected commands or configuration found; connection is not yet verified." >&2
    if is_interactive; then
      printf "Use this phone system? [Y/n]: " >&2
      read -r answer || return 1
      case "$answer" in
        n|N|no|NO) choose_manual_pbx_type "$requested"; return ;;
      esac
    fi
    printf '%s\n' "$detected"
    return
  fi
  echo "No single local PBX could be identified. Remote PBXs and appliances require manual selection." >&2
  if is_interactive; then
    choose_manual_pbx_type "$requested"
  else
    echo "Set PBXSENSE_PBX_TYPE explicitly for unattended setup." >&2
    return 1
  fi
}

configure_asterisk_env() {
  echo "Configuring Asterisk AMI settings in $ENV_FILE"
  echo "Use a PBX AMI monitoring account, not your Linux login or Agent browser code."
  set_env_value PBXSENSE_PBX_TYPE "asterisk"
  set_env_value PBXSENSE_AGENT_MODE "ami"
  prompt_value PBXSENSE_DISPLAY_NAME "Display name" "Asterisk"
  prompt_value ASTERISK_AMI_HOST "Asterisk AMI host" "${ASTERISK_AMI_HOST:-127.0.0.1}"
  prompt_value ASTERISK_AMI_PORT "Asterisk AMI port" "${ASTERISK_AMI_PORT:-5038}"

  detected_creds="$(detect_ami_credentials || true)"
  detected_user="$(printf '%s' "$detected_creds" | awk -F'|' '{print $1}')"
  detected_secret="$(printf '%s' "$detected_creds" | awk -F'|' '{print $2}')"
  [ -n "$detected_user" ] || detected_user="${ASTERISK_AMI_USERNAME:-pbxsense}"
  prompt_value ASTERISK_AMI_USERNAME "Asterisk AMI username" "$detected_user"
  prompt_secret ASTERISK_AMI_PASSWORD "Asterisk AMI password" "${ASTERISK_AMI_PASSWORD:-$detected_secret}"

  configure_history_paths asterisk
}

configure_freeswitch_env() {
  echo "Configuring FreeSWITCH Event Socket settings in $ENV_FILE"
  echo "Use the PBX Event Socket password, not your Linux login or Agent browser code."
  set_env_value PBXSENSE_PBX_TYPE "freeswitch"
  set_env_value PBXSENSE_AGENT_MODE "freeswitch"
  prompt_value PBXSENSE_DISPLAY_NAME "Display name" "FreeSWITCH"
  prompt_value FREESWITCH_ESL_HOST "FreeSWITCH ESL host" "${FREESWITCH_ESL_HOST:-127.0.0.1}"
  prompt_value FREESWITCH_ESL_PORT "FreeSWITCH ESL port" "${FREESWITCH_ESL_PORT:-8021}"
  prompt_secret FREESWITCH_ESL_PASSWORD "FreeSWITCH ESL password" "${FREESWITCH_ESL_PASSWORD:-$(detect_freeswitch_password || true)}"
  configure_history_paths freeswitch
}

configure_history_paths() {
  path_mode="native"
  [ "${PBXSENSE_CONFIGURE_ONLY:-false}" != "true" ] || path_mode="docker"
  fresh=""
  [ "$ENV_CREATED" -ne 1 ] || fresh="--fresh"
  python3 "$SOURCE_DIR/scripts/installer_paths.py" select --env-file "$ENV_FILE" --pbx "$1" --mode "$path_mode" $fresh
}

print_admin_link() {
  bootstrap_token="$(env_value PBXSENSE_BROWSER_BOOTSTRAP_TOKEN)"
  port="$(env_value PBXSENSE_AGENT_PORT)"
  [ -n "$port" ] || port="8765"
  public_url="$(env_value PBXSENSE_AGENT_PUBLIC_URL)"
  certificate="$(env_value PBXSENSE_AGENT_TLS_CERTFILE)"
  trusted_lan="$(env_value PBXSENSE_TRUSTED_LAN_HTTP)"
  if [ -n "$public_url" ]; then
    admin_origin="${public_url%/}"
  elif [ -n "$certificate" ] || [ "$trusted_lan" = "true" ]; then
    host="${PBXSENSE_ACCESS_HOST:-}"
    if [ -z "$host" ] && command -v hostname >/dev/null 2>&1; then
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
  echo "The browser remains authorized until its site data is cleared or the Agent token changes."
}

configure_grandstream_env() {
  echo "Configuring Grandstream UCM AMI settings in $ENV_FILE"
  echo "Use the UCM AMI monitoring account enabled in the PBX administrator interface."
  set_env_value PBXSENSE_PBX_TYPE "grandstream"
  set_env_value PBXSENSE_AGENT_MODE "ami"
  prompt_value PBXSENSE_DISPLAY_NAME "Display name" "Grandstream UCM"
  prompt_value GRANDSTREAM_UCM_AMI_HOST "Grandstream UCM AMI host" "${GRANDSTREAM_UCM_AMI_HOST:-127.0.0.1}"
  prompt_value GRANDSTREAM_UCM_AMI_TLS "Use Grandstream UCM AMI TLS (true/false)" "${GRANDSTREAM_UCM_AMI_TLS:-false}"
  if [ "$(env_value GRANDSTREAM_UCM_AMI_TLS)" = "true" ]; then
    prompt_value GRANDSTREAM_UCM_AMI_PORT "Grandstream UCM AMI TLS port" "${GRANDSTREAM_UCM_AMI_PORT:-5039}"
  else
    prompt_value GRANDSTREAM_UCM_AMI_PORT "Grandstream UCM AMI port" "${GRANDSTREAM_UCM_AMI_PORT:-7777}"
  fi
  prompt_value GRANDSTREAM_UCM_AMI_USERNAME "Grandstream UCM AMI username" "${GRANDSTREAM_UCM_AMI_USERNAME:-pbxsense}"
  prompt_secret GRANDSTREAM_UCM_AMI_PASSWORD "Grandstream UCM AMI password" "${GRANDSTREAM_UCM_AMI_PASSWORD:-}"
  set_env_value GRANDSTREAM_UCM_AMI_VERIFY_TLS "true"
  if [ "$(env_value GRANDSTREAM_UCM_AMI_TLS)" = "true" ]; then
    prompt_value GRANDSTREAM_UCM_AMI_CA_FILE "Private/self-signed CA PEM path (optional)" "${GRANDSTREAM_UCM_AMI_CA_FILE:-}"
  fi
  prompt_value GRANDSTREAM_UCM_CDR_CSV_PATH "Grandstream UCM CDR CSV path (optional)" "${GRANDSTREAM_UCM_CDR_CSV_PATH:-}"
  prompt_value GRANDSTREAM_UCM_VOICEMAIL_PATH "Grandstream UCM voicemail path (optional)" "${GRANDSTREAM_UCM_VOICEMAIL_PATH:-}"
  prompt_value GRANDSTREAM_UCM_RECORDINGS_PATH "Grandstream UCM recordings path (optional)" "${GRANDSTREAM_UCM_RECORDINGS_PATH:-}"
}

configure_yeastar_env() {
  echo "Configuring Yeastar P-Series API settings in $ENV_FILE"
  echo "Use the Client ID and Client Secret from the PBX API integration, not a user-account password."
  set_env_value PBXSENSE_PBX_TYPE "yeastar"
  set_env_value PBXSENSE_AGENT_MODE "yeastar"
  prompt_value PBXSENSE_DISPLAY_NAME "Display name" "Yeastar P-Series"
  prompt_value YEASTAR_BASE_URL "Yeastar PBX base URL" "${YEASTAR_BASE_URL:-https://pbx.example.com}"
  prompt_value YEASTAR_CLIENT_ID "Yeastar API Client ID" "${YEASTAR_CLIENT_ID:-}"
  prompt_secret YEASTAR_CLIENT_SECRET "Yeastar API Client Secret" "${YEASTAR_CLIENT_SECRET:-}"
  prompt_value YEASTAR_API_VERSION "Yeastar API version" "${YEASTAR_API_VERSION:-v1.0}"
  prompt_value YEASTAR_VERIFY_TLS "Verify Yeastar TLS certificate (true/false)" "${YEASTAR_VERIFY_TLS:-true}"
}

configure_cucm_env() {
  echo "Configuring Cisco Unified Communications Manager settings in $ENV_FILE"
  echo "Use a CUCM application user with the required AXL and monitoring permissions."
  set_env_value PBXSENSE_PBX_TYPE "cucm"
  set_env_value PBXSENSE_AGENT_MODE "cucm"
  prompt_value PBXSENSE_DISPLAY_NAME "Display name" "Cisco Unified Communications Manager"
  prompt_value CUCM_HOST "CUCM Publisher host" "${CUCM_HOST:-}"
  prompt_value CUCM_USERNAME "CUCM read-only application user" "${CUCM_USERNAME:-}"
  prompt_secret CUCM_PASSWORD "CUCM application-user password" "${CUCM_PASSWORD:-}"
  prompt_value CUCM_AXL_VERSION "CUCM AXL schema version" "${CUCM_AXL_VERSION:-15.0}"
  prompt_value CUCM_VERIFY_TLS "Verify CUCM TLS certificate (true/false)" "${CUCM_VERIFY_TLS:-true}"
  prompt_value CUCM_CDR_PATH "CUCM CDR inbox" "${CUCM_CDR_PATH:-/var/lib/pbxsense-agent/cucm/cdr}"
  prompt_value CUCM_CMR_PATH "CUCM CMR inbox" "${CUCM_CMR_PATH:-/var/lib/pbxsense-agent/cucm/cmr}"
  prompt_value CUCM_JTAPI_ENABLED "Enable optional JTAPI live calls (true/false)" "${CUCM_JTAPI_ENABLED:-false}"
  prompt_value CUCM_JTAPI_CLASSPATH "Cisco JTAPI classpath" "${CUCM_JTAPI_CLASSPATH:-/opt/pbxsense-agent/vendor/jtapi/*}"
  prompt_value CUCM_JTAPI_JAVA "Java executable" "${CUCM_JTAPI_JAVA:-java}"
  prompt_value CUCM_JTAPI_USERNAME "JTAPI application user (blank uses CUCM user)" "${CUCM_JTAPI_USERNAME:-}"
  prompt_secret CUCM_JTAPI_PASSWORD "JTAPI password (blank uses CUCM password)" "${CUCM_JTAPI_PASSWORD:-}"
  prompt_value CUCM_JTAPI_POLL_SECONDS "JTAPI live-call poll seconds" "${CUCM_JTAPI_POLL_SECONDS:-1}"
}

configure_mock_env() {
  echo "Configuring mock connector settings in $ENV_FILE"
  echo "Demo mode uses simulated PBX data; no PBX credentials are required."
  set_env_value PBXSENSE_PBX_TYPE "mock"
  set_env_value PBXSENSE_AGENT_MODE "mock"
  prompt_value PBXSENSE_DISPLAY_NAME "Display name" "Mock PBX"
}

configure_agent_env() {
  echo ""
  echo "PBXSense setup: Enter keeps the displayed value. Passwords are hidden."
  echo "Existing settings are kept unless you explicitly replace them. Ctrl+C stops setup; saved answers may remain."
  echo "[1/4] Choose your phone system"
  pbx_type="$(choose_pbx_type)"
  case "$pbx_type" in
    asterisk|freeswitch|yeastar|grandstream|cucm|mock) ;;
    *) echo "Unrecognized PBX type. Choose asterisk, freeswitch, yeastar, grandstream or cucm." >&2; exit 1 ;;
  esac
  echo "[2/4] Agent location and browser access"
  echo "Choose the PBX timezone (for example Europe/Athens) to match its local dates and daylight-saving changes. The detected default is this server's timezone; verify it for a remote PBX."
  echo "Keep the default port/timeout unless your site needs another value."
  prompt_value PBXSENSE_TIMEZONE "PBX timezone" "$(detect_timezone)"
  prompt_value PBXSENSE_CONNECT_TIMEOUT "Connector timeout seconds" "${PBXSENSE_CONNECT_TIMEOUT:-3}"
  prompt_value PBXSENSE_AGENT_PORT "Agent HTTP port" "$AGENT_PORT"
  AGENT_PORT="$(env_value PBXSENSE_AGENT_PORT)"
  echo "Optional trusted-LAN HTTP avoids certificates/tunnels, but codes and admin sessions are unencrypted."
  echo "Never expose it publicly. Leave disabled unless you accept this private-network risk."
  prompt_value PBXSENSE_TRUSTED_LAN_HTTP "Allow trusted-LAN HTTP administrator access (true/false)" "${PBXSENSE_TRUSTED_LAN_HTTP:-false}"
  echo "[3/4] PBX connection and optional history sources"
  echo "PBX host means the phone-system server. Use 127.0.0.1 only when this Agent can reach the PBX locally."

  case "$pbx_type" in
    grandstream) configure_grandstream_env ;;
    freeswitch) configure_freeswitch_env ;;
    yeastar) configure_yeastar_env ;;
    cucm) configure_cucm_env ;;
    mock) configure_mock_env ;;
    *) configure_asterisk_env ;;
  esac
}

if [ "${PBXSENSE_CONFIGURE_ONLY:-false}" = "true" ]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to configure PBXSense Agent."
    exit 1
  fi
  ENV_CREATED=0
  if [ ! -f "$ENV_FILE" ]; then
    cp "$SOURCE_DIR/.env.example" "$ENV_FILE"
    ENV_CREATED=1
  fi
  python3 "$SOURCE_DIR/scripts/ensure_token.py" "$ENV_FILE"
  configure_agent_env
  if [ -n "${PBXSENSE_DOCKER_ENV_FILE:-}" ]; then
    set_env_value PBXSENSE_DOCKER_ENV_FILE "$PBXSENSE_DOCKER_ENV_FILE"
  fi
  # Prompts can take longer than the bootstrap lifetime; rotate immediately
  # before returning the link to the administrator.
  python3 "$SOURCE_DIR/scripts/ensure_token.py" "$ENV_FILE"
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  echo "PBXSense Docker environment saved to $ENV_FILE"
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer with sudo or as root."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to install PBXSense Agent."
  exit 1
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/pbxsense-agent --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/vendor/jtapi" /var/lib/pbxsense-agent/cucm/cdr /var/lib/pbxsense-agent/cucm/cmr /var/log/pbxsense-agent

for entry in pbxsense_agent jtapi_bridge scripts docs docker requirements.txt requirements.lock .env.example CODEX.md README.md; do
  if [ -e "$SOURCE_DIR/$entry" ]; then
    rm -rf "$INSTALL_DIR/$entry"
    cp -R "$SOURCE_DIR/$entry" "$INSTALL_DIR/$entry"
  fi
done

ENV_CREATED=0
if [ ! -f "$ENV_FILE" ]; then
  cp "$INSTALL_DIR/.env.example" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  chown root:root "$ENV_FILE"
  ENV_CREATED=1
fi

# Add newly introduced non-secret defaults during upgrades while preserving
# every existing administrator value. Credentials are always configured by the
# prompts or by the administrator and are never copied into an existing file.
python3 - "$INSTALL_DIR/.env.example" "$ENV_FILE" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

example = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
target = Path(sys.argv[2])
lines = target.read_text(encoding="utf-8").splitlines()
existing = {
    line.split("=", 1)[0]
    for line in lines
    if line and not line.lstrip().startswith("#") and "=" in line
}
sensitive = re.compile(r"(?:TOKEN|PASSWORD|SECRET|USERNAME|CLIENT_ID)$")
missing = []
for line in example:
    if not line or line.lstrip().startswith("#") or "=" not in line:
        continue
    key = line.split("=", 1)[0]
    if key not in existing and not sensitive.search(key):
        missing.append(line)
if missing:
    if lines and lines[-1].strip():
        lines.append("")
    lines.append("# Defaults added by a PBXSense Agent upgrade.")
    lines.extend(missing)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

python3 "$INSTALL_DIR/scripts/ensure_token.py" "$ENV_FILE"
configure_agent_env

if [ "$(env_value CUCM_JTAPI_ENABLED)" = "true" ]; then
  if ! command -v java >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y openjdk-8-jre-headless 2>/dev/null || true
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y java-1.8.0-openjdk-headless 2>/dev/null || true
    fi
  fi
  if ! command -v java >/dev/null 2>&1; then
    echo "Install a Cisco-supported Java 8 runtime before enabling CUCM JTAPI."
    exit 1
  fi
  java_major="$(java -version 2>&1 | awk -F'[\".]' '/version/ { if ($2 == "1") print $3; else print $2; exit }')"
  if [ "$java_major" != "8" ]; then
    echo "CUCM JTAPI requires Cisco-supported Java 8; detected Java ${java_major:-unknown}."
    exit 1
  fi
fi

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/python" -m pip install --require-hashes -r "$INSTALL_DIR/requirements.lock"
# Dependency installation can outlast the bootstrap lifetime. Refresh only the
# short-lived setup credential immediately before the service is restarted.
python3 "$INSTALL_DIR/scripts/ensure_token.py" "$ENV_FILE"

chown -R root:root "$INSTALL_DIR"
chmod -R go-w "$INSTALL_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" /var/lib/pbxsense-agent /var/log/pbxsense-agent
# Remove the retired access helper when upgrading from Agent 0.5.5/0.5.6.
rm -f /usr/local/bin/pbxsense-agent
chmod 600 "$ENV_FILE"
chown root:root "$ENV_FILE"

if command -v systemctl >/dev/null 2>&1; then
  cat >"/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=PBXSense Agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=PBXSENSE_AGENT_PORT=$AGENT_PORT
Environment=PYTHONDONTWRITEBYTECODE=1
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/.venv/bin/python -m pbxsense_agent.server
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/pbxsense-agent /var/log/pbxsense-agent

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME.service"
  systemctl restart "$SERVICE_NAME.service"
fi

echo "PBXSense Agent installed."
echo "[4/4] Check the installation and authorize your browser"
echo "Environment: $ENV_FILE"
echo "Service: sudo systemctl status $SERVICE_NAME"
case "$(env_value PBXSENSE_PBX_TYPE)" in
  asterisk|freeswitch)
    "$INSTALL_DIR/.venv/bin/python" "$INSTALL_DIR/scripts/installer_paths.py" report --env-file "$ENV_FILE" --service-user "$SERVICE_USER" || true
    echo "Recheck without reinstalling: sudo $INSTALL_DIR/.venv/bin/python $INSTALL_DIR/scripts/installer_paths.py report --env-file $ENV_FILE --service-user $SERVICE_USER"
    echo "To watch a completed test call: sudo $INSTALL_DIR/.venv/bin/python $INSTALL_DIR/scripts/installer_paths.py watch-cdr --env-file $ENV_FILE --service-user $SERVICE_USER"
    ;;
esac
print_admin_link
echo "Open the single-use setup link above within 15 minutes. Pair the mobile app from the Agent page."
echo "If a capability needs attention, fix that item and rerun the printed check; a successful install alone does not verify calls or history."
