#!/usr/bin/env bash
# Detiene el bot lanzado con start.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f bot.pid ]]; then
  echo "No hay bot.pid. ¿Está corriendo?"
  exit 0
fi

PID="$(cat bot.pid)"
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  echo ">> Señal enviada al PID $PID."
else
  echo "PID $PID no existe."
fi
rm -f bot.pid
