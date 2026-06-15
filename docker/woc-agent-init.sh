#!/usr/bin/with-contenv bash
# Start WOC Agent as root so wx-cli can inspect the WeChat process when init is requested.
set -e

if [ ! -x /woc/woc-agent ]; then
    exit 0
fi

mkdir -p /config/.woc-agent
chmod 700 /config/.woc-agent 2>/dev/null || true

if ! pgrep -x woc-agent >/dev/null 2>&1; then
    nohup /woc/woc-agent >/config/.woc-agent/agent.log 2>&1 &
fi
