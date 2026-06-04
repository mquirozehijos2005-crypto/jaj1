#!/usr/bin/env bash
# Instalación rápida en VPS Debian/Ubuntu.
set -euo pipefail

INSTALL_DIR="/opt/ciberbot"
USER_NAME="ciberbot"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

apt update
apt install -y python3 python3-venv python3-pip git whois libmagic1 \
              libzbar0 build-essential libssl-dev libffi-dev

id -u "$USER_NAME" >/dev/null 2>&1 || useradd -r -m -d "$INSTALL_DIR" -s /usr/sbin/nologin "$USER_NAME"

mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/data" "$INSTALL_DIR/logs"
chown -R "$USER_NAME:$USER_NAME" "$INSTALL_DIR"

if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
  sudo -u "$USER_NAME" python3 -m venv "$INSTALL_DIR/.venv"
fi

sudo -u "$USER_NAME" "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
sudo -u "$USER_NAME" "$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

if [[ ! -f "$INSTALL_DIR/.env" ]]; then
  cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
  echo ">> Edita $INSTALL_DIR/.env y pega tu TELEGRAM_BOT_TOKEN"
fi

cp "$INSTALL_DIR/deploy/ciberbot.service" /etc/systemd/system/ciberbot.service
systemctl daemon-reload
systemctl enable ciberbot
echo ">> Listo. Arranca con: systemctl start ciberbot"
