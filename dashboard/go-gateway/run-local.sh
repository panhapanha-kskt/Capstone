#!/usr/bin/env bash
# Run the existing Python demo behind the authenticated Go gateway on localhost.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DATA="$ROOT/dashboard/data"
PYTHON="${SOC_PYTHON:-$ROOT/.venv/bin/python}"
GATEWAY="$DATA/soc-gateway"

for path in "$DATA/gateway-internal-token" "$DATA/gateway-password-credentials.json" "$GATEWAY"; do
  if [[ ! -f "$path" ]]; then
    echo "Missing $path; see dashboard/go-gateway/README.md" >&2
    exit 1
  fi
done
if [[ ! -x "$PYTHON" || ! -x "$GATEWAY" ]]; then
  echo "Python or Go gateway is not executable" >&2
  exit 1
fi

export SOC_INTERNAL_TOKEN
SOC_INTERNAL_TOKEN="$(cat "$DATA/gateway-internal-token")"

cleanup() {
  trap - EXIT INT TERM
  kill "$gateway_pid" "$python_pid" 2>/dev/null || true
  wait "$gateway_pid" "$python_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$PYTHON" "$ROOT/dashboard/server.py" --demo --host 127.0.0.1 --port 9002 &
python_pid=$!
"$GATEWAY" --listen 127.0.0.1:9000 --backend http://127.0.0.1:9002 \
  --credentials "$DATA/gateway-password-credentials.json" &
gateway_pid=$!
echo "SOC gateway: http://127.0.0.1:9000/login"
echo "Python backend: 127.0.0.1:9002 (internal token required)"

while kill -0 "$gateway_pid" 2>/dev/null && kill -0 "$python_pid" 2>/dev/null; do
  sleep 1
done
echo "A SOC service stopped; shutting down the stack" >&2
exit 1
