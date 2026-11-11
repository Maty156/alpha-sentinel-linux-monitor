#!/bin/bash
# Alpha Sentinel - launcher for Linux.
# Usage: ./start-sentinel.sh [server|collector|once]
#   server     dashboard + API on 127.0.0.1:8443 AND log collection in one process (default)
#   collector  collection only (cron/systemd); add SERVER_URL + ALPHA_SENTINEL_COLLECTOR_KEY to forward alerts
#   once       process new log lines once and exit (cron)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
if [[ -x "$SCRIPT_DIR/.venv/bin/python" ]]; then PYTHON="$SCRIPT_DIR/.venv/bin/python"; else PYTHON="python3"; fi

CONFIG="${ALPHA_SENTINEL_CONFIG:-/etc/alpha-sentinel/config.yaml}"
BIND="${ALPHA_SENTINEL_BIND:-127.0.0.1}"
PORT="${ALPHA_SENTINEL_PORT:-8443}"

if [[ $EUID -ne 0 ]]; then
  echo "[WARN] Not running as root - /var/log/auth.log and the journal may be unreadable." >&2
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "[INFO] No config at $CONFIG - using built-in defaults (auth.log + journal: sshd, sudo)."
  echo "       To customise: copy config.example.yaml there and edit it."
  CONFIG=""
fi
CFG_ARGS=(); [[ -n "$CONFIG" ]] && CFG_ARGS=(--config "$CONFIG")

case "${1:-server}" in
  server)
    # create the first dashboard login if none exists (asks for a password interactively)
    "$PYTHON" - <<'PY' || "$PYTHON" -m alpha_sentinel create-admin
import sys
from alpha_sentinel import store
sys.exit(0 if store.has_users() else 1)
PY
    exec "$PYTHON" -m alpha_sentinel server --host "$BIND" --port "$PORT" --collect "${CFG_ARGS[@]}"
    ;;
  collector)
    ARGS=("${CFG_ARGS[@]}")
    [[ -n "${SERVER_URL:-}" ]] && ARGS+=(--server "$SERVER_URL")
    exec "$PYTHON" -m alpha_sentinel collector "${ARGS[@]}"
    ;;
  once)
    exec "$PYTHON" -m alpha_sentinel collector --once "${CFG_ARGS[@]}"
    ;;
  *) echo "Usage: $0 [server|collector|once]" >&2; exit 2 ;;
esac
