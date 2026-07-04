#!/bin/sh
set -e

SERVICE_USER="pbxpulse"
SERVICE_NAME="pbxpulse-agent"
INSTALL_DIR="/opt/pbxpulse-agent"
ENV_FILE="/etc/pbxpulse-agent.env"
SYSTEMD_UNIT="/etc/systemd/system/$SERVICE_NAME.service"
DATA_DIR="/var/lib/pbxpulse-agent"
LOG_DIR="/var/log/pbxpulse-agent"
PURGE=0

usage() {
  cat <<EOF
Usage: sudo sh ./scripts/uninstall_linux.sh [--purge]

Removes the PBXPulse Agent service and installed application files.

Options:
  --purge   Also remove $DATA_DIR, $LOG_DIR, and the $SERVICE_USER user.
  -h,--help Show this help.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown option: $arg"
      usage
      exit 1
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this uninstaller with sudo or as root."
  exit 1
fi

echo "Stopping $SERVICE_NAME if it is running..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop "$SERVICE_NAME.service" >/dev/null 2>&1 || true
  systemctl disable "$SERVICE_NAME.service" >/dev/null 2>&1 || true
fi

if [ -f "$SYSTEMD_UNIT" ]; then
  echo "Removing $SYSTEMD_UNIT"
  rm -f "$SYSTEMD_UNIT"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed "$SERVICE_NAME.service" >/dev/null 2>&1 || true
fi

if [ -d "$INSTALL_DIR" ]; then
  echo "Removing $INSTALL_DIR"
  rm -rf "$INSTALL_DIR"
fi

if [ -f "$ENV_FILE" ]; then
  echo "Removing $ENV_FILE"
  rm -f "$ENV_FILE"
fi

if [ "$PURGE" -eq 1 ]; then
  echo "Purging PBXPulse Agent local state..."
  rm -rf "$DATA_DIR" "$LOG_DIR"

  if id "$SERVICE_USER" >/dev/null 2>&1; then
    if command -v userdel >/dev/null 2>&1; then
      userdel "$SERVICE_USER" >/dev/null 2>&1 || true
    else
      echo "userdel is not available; leaving user $SERVICE_USER in place."
    fi
  fi
else
  echo "Preserved $DATA_DIR"
  echo "Preserved $LOG_DIR"
  echo "Run with --purge to remove preserved data, logs, and user."
fi

echo "PBXPulse Agent uninstalled."
