#!/usr/bin/env bash
# Muestra estado del bot.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f bot.pid ]] && kill -0 "$(cat bot.pid)" 2>/dev/null; then
  echo "✅ corriendo (PID $(cat bot.pid))"
  ps -fp "$(cat bot.pid)" || true
else
  echo "❌ detenido"
fi

echo
echo "Últimas líneas del log:"
tail -n 30 logs/bot.log 2>/dev/null || echo "(sin log)"
