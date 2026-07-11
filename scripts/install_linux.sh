#!/bin/sh
set -e

SERVICE_USER="pbxsense"
SERVICE_NAME="pbxsense-agent"
INSTALL_DIR="/opt/pbxsense-agent"
ENV_FILE="/etc/pbxsense-agent.env"
AGENT_PORT="${PBXSENSE_AGENT_PORT:-8765}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer with sudo or as root."
  exit 1
fi

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
      stty -echo
      read -r answer
      stty echo
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

choose_pbx_type() {
  if [ -n "${PBXSENSE_PBX_TYPE:-}" ]; then
    normalize_pbx_type "$PBXSENSE_PBX_TYPE"
    return
  fi

  requested=""
  if [ "$ENV_CREATED" -eq 0 ]; then
    requested="$(env_value PBXSENSE_PBX_TYPE)"
  fi
  if [ -n "$requested" ]; then
    normalize_pbx_type "$requested"
    return
  fi

  has_asterisk=0
  has_freeswitch=0
  detect_asterisk && has_asterisk=1
  detect_freeswitch && has_freeswitch=1

  detected="asterisk"
  if [ "$has_freeswitch" -eq 1 ] && [ "$has_asterisk" -eq 0 ]; then
    detected="freeswitch"
  elif [ "$has_asterisk" -eq 0 ] && [ "$has_freeswitch" -eq 0 ]; then
    detected="asterisk"
  fi

  if is_interactive; then
    echo "PBX detection:" >&2
    [ "$has_asterisk" -eq 1 ] && echo "  - Asterisk files or commands found." >&2
    [ "$has_freeswitch" -eq 1 ] && echo "  - FreeSWITCH files or commands found." >&2
    [ "$has_asterisk" -eq 0 ] && [ "$has_freeswitch" -eq 0 ] && echo "  - No local PBX files found; using Asterisk defaults." >&2
    printf "PBX type: asterisk, grandstream, freeswitch, yeastar, or mock [%s]: " "$detected" >&2
    read -r answer
    if [ -n "$answer" ]; then
      detected="$answer"
    fi
  fi

  normalize_pbx_type "$detected"
}

configure_asterisk_env() {
  echo "Configuring Asterisk AMI settings in $ENV_FILE"
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
  prompt_value ASTERISK_AMI_TIMEOUT "Asterisk AMI timeout seconds" "${ASTERISK_AMI_TIMEOUT:-3}"

  cdr_path="$(first_existing_path \
    /var/log/asterisk/cdr-csv/Master.csv \
    /var/log/asterisk/cdr-custom/Master.csv \
    /var/log/asterisk/cdr/Master.csv)"
  voicemail_path="$(first_existing_path \
    /var/spool/asterisk/voicemail \
    /var/lib/asterisk/voicemail)"
  prompt_value ASTERISK_CDR_CSV_PATH "Asterisk CDR CSV path" "$cdr_path"
  prompt_value ASTERISK_VOICEMAIL_PATH "Asterisk voicemail path" "$voicemail_path"
  recordings_path="$(first_existing_path /var/spool/asterisk/monitor /var/lib/asterisk/monitor)"
  prompt_value ASTERISK_RECORDINGS_PATH "Asterisk recordings path" "$recordings_path"
}

configure_freeswitch_env() {
  echo "Configuring FreeSWITCH Event Socket settings in $ENV_FILE"
  set_env_value PBXSENSE_PBX_TYPE "freeswitch"
  set_env_value PBXSENSE_AGENT_MODE "freeswitch"
  prompt_value PBXSENSE_DISPLAY_NAME "Display name" "FreeSWITCH"
  prompt_value FREESWITCH_ESL_HOST "FreeSWITCH ESL host" "${FREESWITCH_ESL_HOST:-127.0.0.1}"
  prompt_value FREESWITCH_ESL_PORT "FreeSWITCH ESL port" "${FREESWITCH_ESL_PORT:-8021}"
  prompt_secret FREESWITCH_ESL_PASSWORD "FreeSWITCH ESL password" "${FREESWITCH_ESL_PASSWORD:-$(detect_freeswitch_password || true)}"
  prompt_value FREESWITCH_CDR_JSON_PATH "FreeSWITCH JSON CDR folder (optional)" "${FREESWITCH_CDR_JSON_PATH:-}"
  prompt_value FREESWITCH_VOICEMAIL_PATH "FreeSWITCH voicemail metadata folder (optional)" "${FREESWITCH_VOICEMAIL_PATH:-}"
  prompt_value FREESWITCH_RECORDINGS_PATH "FreeSWITCH recordings folder (optional)" "${FREESWITCH_RECORDINGS_PATH:-}"
}

configure_grandstream_env() {
  echo "Configuring Grandstream UCM AMI settings in $ENV_FILE"
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
  prompt_value GRANDSTREAM_UCM_AMI_VERIFY_TLS "Verify Grandstream UCM TLS certificate (true/false)" "${GRANDSTREAM_UCM_AMI_VERIFY_TLS:-true}"
  prompt_value GRANDSTREAM_UCM_AMI_TIMEOUT "Grandstream UCM AMI timeout seconds" "${GRANDSTREAM_UCM_AMI_TIMEOUT:-3}"
  prompt_value GRANDSTREAM_UCM_CDR_CSV_PATH "Grandstream UCM CDR CSV path (optional)" "${GRANDSTREAM_UCM_CDR_CSV_PATH:-}"
  prompt_value GRANDSTREAM_UCM_VOICEMAIL_PATH "Grandstream UCM voicemail path (optional)" "${GRANDSTREAM_UCM_VOICEMAIL_PATH:-}"
  prompt_value GRANDSTREAM_UCM_RECORDINGS_PATH "Grandstream UCM recordings path (optional)" "${GRANDSTREAM_UCM_RECORDINGS_PATH:-}"
}

configure_yeastar_env() {
  echo "Configuring Yeastar P-Series API settings in $ENV_FILE"
  set_env_value PBXSENSE_PBX_TYPE "yeastar"
  set_env_value PBXSENSE_AGENT_MODE "yeastar"
  prompt_value PBXSENSE_DISPLAY_NAME "Display name" "Yeastar P-Series"
  prompt_value YEASTAR_BASE_URL "Yeastar PBX base URL" "${YEASTAR_BASE_URL:-https://pbx.example.com}"
  prompt_value YEASTAR_CLIENT_ID "Yeastar API Client ID" "${YEASTAR_CLIENT_ID:-}"
  prompt_secret YEASTAR_CLIENT_SECRET "Yeastar API Client Secret" "${YEASTAR_CLIENT_SECRET:-}"
  prompt_value YEASTAR_API_VERSION "Yeastar API version" "${YEASTAR_API_VERSION:-v1.0}"
  prompt_value YEASTAR_VERIFY_TLS "Verify Yeastar TLS certificate (true/false)" "${YEASTAR_VERIFY_TLS:-true}"
}

configure_mock_env() {
  echo "Configuring mock connector settings in $ENV_FILE"
  set_env_value PBXSENSE_PBX_TYPE "mock"
  set_env_value PBXSENSE_AGENT_MODE "mock"
  prompt_value PBXSENSE_DISPLAY_NAME "Display name" "Mock PBX"
}

configure_agent_env() {
  pbx_type="$(choose_pbx_type)"
  prompt_value PBXSENSE_TIMEZONE "Agent timezone" "$(detect_timezone)"
  prompt_value PBXSENSE_CONNECT_TIMEOUT "Connector timeout seconds" "${PBXSENSE_CONNECT_TIMEOUT:-3}"
  prompt_value PBXSENSE_AGENT_PORT "Agent HTTP port" "$AGENT_PORT"
  AGENT_PORT="$(env_value PBXSENSE_AGENT_PORT)"

  case "$pbx_type" in
    grandstream) configure_grandstream_env ;;
    freeswitch) configure_freeswitch_env ;;
    yeastar) configure_yeastar_env ;;
    mock) configure_mock_env ;;
    *) configure_asterisk_env ;;
  esac
}

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y python3 python3-venv python3-pip
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to install PBXSense Agent."
  exit 1
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/pbxsense-agent --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

mkdir -p "$INSTALL_DIR" /var/lib/pbxsense-agent /var/log/pbxsense-agent

for entry in pbxsense_agent scripts docs requirements.txt .env.example CODEX.md README.md SECURITY.md Dockerfile docker-compose.yml docker-compose.lan.yml docker-compose.parent-example.yml; do
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

python3 "$INSTALL_DIR/scripts/ensure_token.py" "$ENV_FILE"
configure_agent_env

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/.venv/bin/python" -m pip install -r "$INSTALL_DIR/requirements.txt"

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" /var/lib/pbxsense-agent /var/log/pbxsense-agent
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
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/.venv/bin/uvicorn pbxsense_agent.main:app --host 0.0.0.0 --port \${PBXSENSE_AGENT_PORT}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME.service"
  systemctl restart "$SERVICE_NAME.service"
fi

echo "PBXSense Agent installed."
echo "Environment: $ENV_FILE"
echo "Service: sudo systemctl status $SERVICE_NAME"
