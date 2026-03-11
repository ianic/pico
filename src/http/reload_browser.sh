#!/usr/bin/env bash
#set -euo pipefail

PORT=9222
TITLE="Pico" # adjust if needed

# 1) Get DevTools targets
json=$(curl -s "http://localhost:${PORT}/json")

# 2) Extract WebSocket URL for the tab with given title
wsUrl=$(echo "$json" | jq -r \
    ".[] | select(.title | startswith(\"${TITLE}\")) | .webSocketDebuggerUrl" | head -n1)

if [ -z "$wsUrl" ] || [ "$wsUrl" = "null" ]; then
    echo "No matching Chromium tab found for title: ${TITLE}" >&2
    exit 1
fi

# 3) Send Page.reload command via DevTools protocol
#    ignoreCache=false => normal reload (like F5)
echo '{"id":1,"method":"Page.reload","params":{"ignoreCache":false}}' |
    websocat -q "$wsUrl" >>/dev/null

exit 0

# start chromium with debugging enabled
chromium --remote-debugging-port=9222 \
    --user-data-dir=/tmp/chrome-debug \
    --no-first-run \
    --disable-default-apps
