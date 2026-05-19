#!/bin/bash
set -e

DATA_DIR="${DATA_DIR:-/data}"
WG_CONF_SRC="$DATA_DIR/wg0.conf"
WG_CONF="/etc/wireguard/wg0.conf"

echo "[wg] Umbrel Tunnel WireGuard client starting..."

apply_wg_ingress_guard() {
    # Hardening: limit what a remote WG peer can reach in this namespace.
    # Allow only reverse-proxy ingress on 80/443 over wg0, drop the rest.
    iptables -w -N MINIWEED_WG_GUARD 2>/dev/null || true
    iptables -w -F MINIWEED_WG_GUARD

    iptables -w -A MINIWEED_WG_GUARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -w -A MINIWEED_WG_GUARD -p tcp --dport 80 -j ACCEPT
    iptables -w -A MINIWEED_WG_GUARD -p tcp --dport 443 -j ACCEPT
    iptables -w -A MINIWEED_WG_GUARD -p icmp -j ACCEPT
    iptables -w -A MINIWEED_WG_GUARD -j DROP

    iptables -w -D INPUT -i wg0 -j MINIWEED_WG_GUARD 2>/dev/null || true
    iptables -w -I INPUT 1 -i wg0 -j MINIWEED_WG_GUARD
    echo "[wg] Applied wg0 ingress guard (allow 80/443, drop rest)"
}

# Start API server immediately so keygen works before any config exists
python3 /wg-api.py &
API_PID=$!

cleanup() {
    echo "[wg] Shutting down..."
    wg-quick down wg0 2>/dev/null || true
    kill "$API_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for config to be written by the web container
until [ -f "$WG_CONF_SRC" ] && [ -s "$WG_CONF_SRC" ]; do
    echo "[wg] Waiting for WireGuard config..."
    sleep 3
done

cp "$WG_CONF_SRC" "$WG_CONF"

# Bring up WireGuard
until wg-quick up wg0; do
    echo "[wg] Failed to bring up wg0, retrying in 5s..."
    sleep 5
done
apply_wg_ingress_guard
echo "[wg] Tunnel up"

# Watch config for changes and syncconf (no interface teardown)
PREV_HASH=$(md5sum "$WG_CONF_SRC" | cut -d' ' -f1)
while true; do
    sleep 3
    [ -f "$WG_CONF_SRC" ] || continue
    CURR_HASH=$(md5sum "$WG_CONF_SRC" | cut -d' ' -f1)
    if [ "$CURR_HASH" != "$PREV_HASH" ]; then
        echo "[wg] Config changed, syncing..."
        cp "$WG_CONF_SRC" "$WG_CONF"
        wg syncconf wg0 <(wg-quick strip "$WG_CONF") 2>&1 && echo "[wg] Sync OK" || echo "[wg] Sync failed"
        PREV_HASH="$CURR_HASH"
    fi
done
