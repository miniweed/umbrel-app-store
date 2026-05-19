#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[crowdsec-smoke] must run as root"
  exit 1
fi

echo "[crowdsec-smoke] checking systemd units"
systemctl is-enabled crowdsec >/dev/null
systemctl is-enabled crowdsec-firewall-bouncer >/dev/null
systemctl is-active crowdsec >/dev/null
systemctl is-active crowdsec-firewall-bouncer >/dev/null

echo "[crowdsec-smoke] checking cscli status"
cscli lapi status >/dev/null
cscli bouncers list | grep -q "firewall-bouncer"

echo "[crowdsec-smoke] checking iptables hook"
iptables-save | grep -qi "crowdsec"

echo "[crowdsec-smoke] checking service logs for recent errors"
if journalctl -u crowdsec -u crowdsec-firewall-bouncer -n 80 --no-pager | grep -Eiq "(failed|error|panic|fatal)"; then
  echo "[crowdsec-smoke] detected suspicious log lines"
  exit 1
fi

echo "[crowdsec-smoke] ok"
