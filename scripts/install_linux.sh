#!/bin/sh
set -e

SERVICE_USER="pbxpulse"
SERVICE_NAME="pbxpulse-agent"
INSTALL_DIR="/opt/pbxpulse-agent"
ENV_FILE="/etc/pbxpulse-agent.env"
AGENT_PORT="${PBXPULSE_AGENT_PORT:-8765}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer with sudo or as root."
  exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y python3 python3-venv python3-pip
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/pbxpulse-agent --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

mkdir -p "$INSTALL_DIR" /var/lib/pbxpulse-agent /var/log/pbxpulse-agent

for entry in pbxpulse_agent scripts requirements.txt .env.example README.md CONNECTORS.md Dockerfile docker-compose.yml docker-compose.lan.yml docker-compose.parent-example.yml; do
  if [ -e "$SOURCE_DIR/$entry" ]; then
    rm -rf "$INSTALL_DIR/$entry"
    cp -R "$SOURCE_DIR/$entry" "$INSTALL_DIR/$entry"
  fi
done

if [ ! -f "$ENV_FILE" ]; then
  cp "$INSTALL_DIR/.env.example" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  chown root:root "$ENV_FILE"
fi

python3 "$INSTALL_DIR/scripts/ensure_token.py" "$ENV_FILE"

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/.venv/bin/python" -m pip install -r "$INSTALL_DIR/requirements.txt"

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" /var/lib/pbxpulse-agent /var/log/pbxpulse-agent

if command -v systemctl >/dev/null 2>&1; then
  cat >"/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=PBXPulse Agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=PBXPULSE_AGENT_PORT=$AGENT_PORT
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/.venv/bin/uvicorn pbxpulse_agent.main:app --host 0.0.0.0 --port \${PBXPULSE_AGENT_PORT}
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

echo "PBXPulse Agent installed."
echo "Edit $ENV_FILE for PBX credentials, then run: sudo systemctl restart $SERVICE_NAME"
