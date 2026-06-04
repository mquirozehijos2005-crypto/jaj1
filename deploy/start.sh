#!/usr/bin/env bash
# Arranque manual del bot SIN systemd (contenedores / sandboxes / HF Spaces).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p logs data

if [[ ! -d .venv ]]; then
  echo ">> Creando venv..."
  python3 -m venv .venv
  ./.venv/bin/pip install --upgrade pip
  ./.venv/bin/pip install -r requirements.txt
fi

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo ">> Edita .env y pega TELEGRAM_BOT_TOKEN antes de continuar."
  exit 1
fi

# Detener instancia previa si existe
if [[ -f bot.pid ]] && kill -0 "$(cat bot.pid)" 2>/dev/null; then
  echo ">> Deteniendo instancia previa (PID $(cat bot.pid))..."
  kill "$(cat bot.pid)" || true
  sleep 2
fi

echo ">> Arrancando ciberbot en background..."
nohup ./.venv/bin/python -m ciberbot > logs/bot.log 2>&1 &
echo $! > bot.pid
sleep 1
echo ">> PID $(cat bot.pid). Logs: tail -f logs/bot.log"
