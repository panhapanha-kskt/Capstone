#!/usr/bin/env bash
# setup_pushlogger.sh - one command to (re)install and (re)configure the PushLogger DNS App
# against whatever Technitium server is currently running, on any machine.
#
# Safe to re-run any time:
#   - first time setup on a new computer
#   - after deleting/reinstalling Technitium with a brand new API key
#   - after upgrading (or downgrading) to a different Technitium version
#
# What it does:
#   1. Detects the live server's version via its own API (no hardcoded version).
#   2. Rebuilds the plugin only if that version differs from the last build (cached in
#      infra/technitium-apps/.built_version) - build.sh itself also re-clones its reference
#      source if it was left checked out at a different version.
#   3. Installs the plugin, or updates it in place if already installed.
#   4. Enables query logging - off by default on a fresh Technitium install, and nothing is
#      ever pushed until it's on.
#   5. Configures the plugin to push to this machine's listener via --push-host (default
#      172.20.0.1, this host's docker bridge gateway - the container reaches the listener
#      through that address). Find yours with `ip addr show` (the br-... interface) if it
#      differs, and pass --push-host <that IP>.
#   6. Writes/updates TECHNITIUM_API_KEY in .env so the listener's token matches the new key.
#   7. Restarts scripts/technitium_push_listener.py so it picks up that token.
#
# Usage:
#   ./scripts/setup_pushlogger.sh --api-key <token>
#   ./scripts/setup_pushlogger.sh --api-key <token> --url http://localhost:5380 --push-port 8787
#   ./scripts/setup_pushlogger.sh --api-key <token> --no-restart-listener
#
# Get a token from the Technitium web console: Settings > Sessions > Create Token.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPS_DIR="$HERE/infra/technitium-apps"
LISTENER="$HERE/scripts/technitium_push_listener.py"

URL="http://localhost:5380"
PUSH_HOST="172.20.0.1"
PUSH_PORT="8787"
RESTART_LISTENER=1
API_KEY="${TECHNITIUM_API_KEY:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --api-key) API_KEY="$2"; shift 2 ;;
        --url) URL="$2"; shift 2 ;;
        --push-host) PUSH_HOST="$2"; shift 2 ;;
        --push-port) PUSH_PORT="$2"; shift 2 ;;
        --no-restart-listener) RESTART_LISTENER=0; shift ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$API_KEY" ]; then
    echo "error: no API key given. Pass --api-key <token>, or set TECHNITIUM_API_KEY." >&2
    echo "Get one from the Technitium web console: Settings > Sessions > Create Token." >&2
    exit 1
fi

echo "==> Checking server at $URL ..."
SESSION_JSON="$(curl -sf --max-time 5 "$URL/api/user/session/get?token=$API_KEY")" || {
    echo "error: could not reach $URL, or it rejected the token." >&2
    exit 1
}
VERSION="$(printf '%s' "$SESSION_JSON" | grep -oP '"version"\s*:\s*"\K[^"]+')"
if [ -z "$VERSION" ]; then
    echo "error: could not read server version from response: $SESSION_JSON" >&2
    exit 1
fi
echo "    server version: $VERSION"

BUILT_VERSION_FILE="$APPS_DIR/.built_version"
NEED_BUILD=1
if [ -f "$BUILT_VERSION_FILE" ] && [ -f "$APPS_DIR/PushLogger.zip" ] \
    && [ "$(cat "$BUILT_VERSION_FILE")" = "$VERSION" ]; then
    NEED_BUILD=0
fi

if [ "$NEED_BUILD" = "1" ]; then
    echo "==> Building PushLogger for v$VERSION (not built yet, or version changed) ..."
    DOTNET="${DOTNET:-}"
    PROJECT_SDK="$HERE/infra/technitium-build/dotnet-sdk/dotnet"
    if [ -z "$DOTNET" ]; then
        if [ -x "$PROJECT_SDK" ]; then
            # Prefer this over a system `dotnet` on PATH, which may be an older SDK that
            # doesn't support the TargetFramework the live server needs.
            DOTNET="$PROJECT_SDK"
        elif command -v dotnet >/dev/null 2>&1; then
            DOTNET="dotnet"
        else
            echo "error: no dotnet SDK found. Install one matching this server's TargetFramework," >&2
            echo "kept inside the project rather than system-wide:" >&2
            echo "  curl -sL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 10.0 --install-dir infra/technitium-build/dotnet-sdk" >&2
            echo "then re-run this script - it will find it automatically." >&2
            exit 1
        fi
    fi
    DOTNET="$DOTNET" "$APPS_DIR/build.sh" "$VERSION"
    echo "$VERSION" > "$BUILT_VERSION_FILE"
else
    echo "==> PushLogger already built for v$VERSION, skipping rebuild."
fi

echo "==> Enabling query logging ..."
curl -sf -X POST "$URL/api/settings/set?token=$API_KEY&logQueries=true" >/dev/null

echo "==> Installing/updating the PushLogger app ..."
APPS_JSON="$(curl -sf "$URL/api/apps/list?token=$API_KEY")"
if printf '%s' "$APPS_JSON" | grep -q '"name":"PushLogger"'; then
    curl -sf -X POST "$URL/api/apps/update?name=PushLogger&token=$API_KEY" \
        -F "file=@$APPS_DIR/PushLogger.zip;type=application/zip" >/dev/null
else
    curl -sf -X POST "$URL/api/apps/install?name=PushLogger&token=$API_KEY" \
        -F "file=@$APPS_DIR/PushLogger.zip;type=application/zip" >/dev/null
fi

echo "==> Configuring push target: http://$PUSH_HOST:$PUSH_PORT/push ..."
CONFIG="{\"pushUrl\":\"http://$PUSH_HOST:$PUSH_PORT/push\",\"pushToken\":\"$API_KEY\",\"timeoutMs\":2000,\"maxQueueSize\":10000}"
curl -sf -X POST "$URL/api/apps/config/set?name=PushLogger&token=$API_KEY" \
    --data-urlencode "config=$CONFIG" >/dev/null

echo "==> Updating .env ..."
ENV_FILE="$HERE/.env"
touch "$ENV_FILE"
if grep -q '^TECHNITIUM_API_KEY=' "$ENV_FILE"; then
    sed -i "s/^TECHNITIUM_API_KEY=.*/TECHNITIUM_API_KEY=$API_KEY/" "$ENV_FILE"
else
    echo "TECHNITIUM_API_KEY=$API_KEY" >> "$ENV_FILE"
fi

if [ "$RESTART_LISTENER" = "1" ]; then
    echo "==> Restarting push listener ..."
    pkill -f "technitium_push_listener.py" 2>/dev/null || true
    sleep 0.3
    nohup python3 "$LISTENER" --port "$PUSH_PORT" \
        > "$HERE/scripts/.push_listener.log" 2>&1 &
    disown
    sleep 0.5
    if curl -sf --max-time 2 "http://127.0.0.1:$PUSH_PORT/healthz" >/dev/null; then
        echo "    listener is up on port $PUSH_PORT."
    else
        echo "    warning: listener did not respond on port $PUSH_PORT - check scripts/.push_listener.log" >&2
    fi
else
    echo "==> Skipping listener restart (--no-restart-listener). If its token changed, restart it yourself:"
    echo "    pkill -f technitium_push_listener.py; python3 scripts/technitium_push_listener.py --port $PUSH_PORT"
fi

echo "==> Done. PushLogger v$VERSION is installed, configured, and pushing to http://$PUSH_HOST:$PUSH_PORT/push."
