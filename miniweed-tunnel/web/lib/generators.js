// Generadores de artefactos (wg0.conf, Caddyfile, script de VPS, kill-switch,
// rotación). Funciones puras extraídas de server.js; reciben el target ya resuelto.
const { safeTunnelIp, isBlockedServiceTarget } = require("./validation");
const { DEFAULT_CONFIG, DEFAULT_CADDYFILE } = require("../config/constants");

function generateWgConf(cfg, active) {
  if (!cfg.privateKey || !active?.pubKey || !active?.ip) return null;
  const clientIp = safeTunnelIp(cfg.tunnelClientIp, DEFAULT_CONFIG.tunnelClientIp);
  const serverIp = safeTunnelIp(cfg.tunnelServerIp, DEFAULT_CONFIG.tunnelServerIp);
  const pskLine = cfg.presharedKey ? `PresharedKey = ${cfg.presharedKey}` : null;
  return [
    '[Interface]',
    `Address = ${clientIp}/32`,
    `PrivateKey = ${cfg.privateKey}`,
    '',
    '[Peer]',
    `PublicKey = ${active.pubKey}`,
    pskLine,
    `Endpoint = ${active.ip}:${active.port}`,
    `AllowedIPs = ${serverIp}/32`,
    'PersistentKeepalive = 25',
    ''
  ].filter(Boolean).join('\n');
}

function generateCaddyfile(cfg) {
  const enabled = (cfg.services || []).filter(s => s.enabled && s.target && !isBlockedServiceTarget(s.target));
  if (!cfg.domain || !cfg.acmeEmail || !enabled.length) return DEFAULT_CADDYFILE;

  const blocks = [`{\n  email ${cfg.acmeEmail}\n  admin off\n}\n`];
  for (const svc of enabled) {
    const host = svc.subdomain ? `${svc.subdomain}.${cfg.domain}` : cfg.domain;
    blocks.push(`${host} {\n  reverse_proxy ${svc.target}\n}\n`);
  }
  return blocks.join('\n');
}

function generateVpsScript(cfg, target, options = {}) {
  const selected = target;
  if (!selected) throw new Error('No hay VPS seleccionado');
  const clientIp = safeTunnelIp(cfg.tunnelClientIp, DEFAULT_CONFIG.tunnelClientIp);
  const serverIp = safeTunnelIp(cfg.tunnelServerIp, DEFAULT_CONFIG.tunnelServerIp);
  const withCrowdsec = Boolean(options.withCrowdsec);
  const pskLine = cfg.presharedKey
    ? `PresharedKey = ${cfg.presharedKey}`
    : '';
  const crowdsecBlock = withCrowdsec
    ? `
# CrowdSec opcional
echo "Instalando CrowdSec..."
if ! command -v curl >/dev/null 2>&1; then
  apt-get -o DPkg::Lock::Timeout=300 install -y -qq curl ca-certificates
fi
if ! command -v cscli >/dev/null 2>&1; then
  curl -fsSL https://install.crowdsec.net | sh
fi
apt-get -o DPkg::Lock::Timeout=300 install -y -qq crowdsec crowdsec-firewall-bouncer-iptables
cscli collections install crowdsecurity/sshd || true
systemctl enable crowdsec crowdsec-firewall-bouncer >/dev/null 2>&1 || true
systemctl restart crowdsec crowdsec-firewall-bouncer >/dev/null 2>&1 || true
for i in 1 2 3 4 5; do
  if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
    break
  fi
  sleep 1
done
if ! systemctl is-active --quiet crowdsec; then
  echo "Advertencia: crowdsec no quedo activo"
fi
if ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
  echo "Advertencia: crowdsec-firewall-bouncer no quedo activo"
fi
cscli lapi status >/dev/null 2>&1 || echo "Advertencia: cscli no pudo validar LAPI"
cscli bouncers list >/dev/null 2>&1 || echo "Advertencia: cscli no pudo listar bouncers"
iptables-save | grep -qi crowdsec || echo "Advertencia: no se detecto hook iptables de CrowdSec"
`
    : '';
  return `#!/bin/bash
# Umbrel Tunnel — VPS Setup
# Ejecutar como root en un VPS Debian/Ubuntu
# VPS dedicado exclusivamente a reverse proxy

set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [ "$(id -u)" -ne 0 ]; then
  echo "Este script debe ejecutarse como root"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

if command -v ufw >/dev/null 2>&1; then
  ufw disable >/dev/null 2>&1 || true
  systemctl disable ufw >/dev/null 2>&1 || true
  systemctl stop ufw >/dev/null 2>&1 || true
fi

apt-get -o DPkg::Lock::Timeout=300 update -qq
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
apt-get -o DPkg::Lock::Timeout=300 install -y -qq wireguard iptables iptables-persistent fail2ban unattended-upgrades

PUBLIC_IF=$(ip route show default | awk '/default/{print $5; exit}')
if [ -z "$PUBLIC_IF" ]; then
  echo "No se pudo detectar la interfaz de red publica"
  exit 1
fi

SSH_PORT=$(/usr/sbin/sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)
if [ -z "$SSH_PORT" ]; then
  SSH_PORT=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
fi
[ -z "$SSH_PORT" ] && SSH_PORT=22

if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)\${SSH_PORT}$"; then
  echo "No se detecta sshd escuchando en el puerto $SSH_PORT. Abortando para evitar lockout."
  exit 1
fi

WG_PORT=${selected.port}
WG_CLIENT_IP=${clientIp}

mkdir -p /root/miniweed-backups
BACKUP_FILE="/root/miniweed-backups/iptables-before-$(date +%s).rules"
iptables-save > "$BACKUP_FILE"

cat > /root/miniweed-rollback-firewall.sh <<'ROLLBACKEOF'
#!/bin/bash
set -euo pipefail
LATEST=$(ls -1t /root/miniweed-backups/iptables-before-*.rules 2>/dev/null | head -1)
if [ -z "$LATEST" ]; then
  echo "No hay backup de firewall para restaurar"
  exit 1
fi
iptables-restore < "$LATEST"
echo "Restaurado firewall desde $LATEST"
ROLLBACKEOF
chmod 700 /root/miniweed-rollback-firewall.sh

ROLLBACK_FLAG=/root/miniweed-firewall-ok
rm -f "$ROLLBACK_FLAG"
( sleep 120; [ -f "$ROLLBACK_FLAG" ] || /root/miniweed-rollback-firewall.sh ) &
ROLLBACK_PID=$!

# Hardening de red del host
cat > /etc/sysctl.d/99-miniweed-tunnel-hardening.conf <<SYSCTLEOF
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_syncookies=1
SYSCTLEOF
sysctl --system >/dev/null

# Firewall estricto para VPS dedicado (sin cortar la sesion SSH activa)
iptables -w -P INPUT ACCEPT
iptables -w -P FORWARD ACCEPT
iptables -w -P OUTPUT ACCEPT
iptables -w -t nat -F
iptables -w -F
iptables -w -X

iptables -w -A INPUT -i lo -j ACCEPT
iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
iptables -w -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -w -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -w -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
iptables -w -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT

iptables -w -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination "$WG_CLIENT_IP:80"
iptables -w -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination "$WG_CLIENT_IP:443"
# Evita retorno asimetrico: SNAT al lado WG para que Umbrel responda por el tunel
iptables -w -t nat -A POSTROUTING -o wg0 -p tcp -d "$WG_CLIENT_IP" --dport 80 -j MASQUERADE
iptables -w -t nat -A POSTROUTING -o wg0 -p tcp -d "$WG_CLIENT_IP" --dport 443 -j MASQUERADE
iptables -w -t nat -A POSTROUTING -o "$PUBLIC_IF" -j MASQUERADE

iptables -w -A FORWARD -p tcp -d "$WG_CLIENT_IP" --dport 80 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -w -A FORWARD -p tcp -d "$WG_CLIENT_IP" --dport 443 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -w -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -w -P INPUT DROP
iptables -w -P FORWARD DROP

iptables-save > /etc/iptables/rules.v4
systemctl enable netfilter-persistent >/dev/null 2>&1 || true
systemctl restart netfilter-persistent >/dev/null 2>&1 || true

# Fail2ban para SSH
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/sshd.local <<FAIL2BANEOF
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
FAIL2BANEOF
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || true

# Actualizaciones de seguridad automáticas
systemctl enable unattended-upgrades >/dev/null 2>&1 || true
systemctl restart unattended-upgrades >/dev/null 2>&1 || true
${crowdsecBlock}

# Endurecer SSH a solo clave publica (sin romper acceso)
SSH_HARDENED="no"
if [ -s /root/.ssh/authorized_keys ]; then
  mkdir -p /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/99-miniweed-tunnel.conf <<SSHEOF
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
SSHEOF

  if /usr/sbin/sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    SSH_HARDENED="yes"
  else
    rm -f /etc/ssh/sshd_config.d/99-miniweed-tunnel.conf
    echo "Advertencia: configuracion SSH invalida, se omite endurecimiento SSH"
  fi
else
  echo "Advertencia: /root/.ssh/authorized_keys no existe o esta vacio; se mantiene acceso por password para evitar lockout"
fi

VPS_PRIV=$(wg genkey)
VPS_PUB=$(echo "$VPS_PRIV" | wg pubkey)

cat > /etc/wireguard/wg0.conf <<WGEOF
[Interface]
Address = ${serverIp}/24
ListenPort = ${selected.port}
PrivateKey = $VPS_PRIV

[Peer]
PublicKey = ${cfg.publicKey}
${pskLine}
AllowedIPs = ${clientIp}/32
WGEOF

chmod 600 /etc/wireguard/wg0.conf

systemctl enable wg-quick@wg0
if systemctl is-active --quiet wg-quick@wg0; then
  systemctl restart wg-quick@wg0
else
  systemctl start wg-quick@wg0
fi

if ! systemctl is-active --quiet wg-quick@wg0; then
  /root/miniweed-rollback-firewall.sh || true
  echo "WireGuard no arrancó correctamente. Firewall restaurado."
  exit 1
fi

ACTIVE_PUB=$(wg show wg0 public-key 2>/dev/null || true)
if [ -z "$ACTIVE_PUB" ]; then
  /root/miniweed-rollback-firewall.sh || true
  echo "No se pudo leer la clave publica activa de wg0 tras aplicar la configuracion."
  exit 1
fi
if [ "$ACTIVE_PUB" != "$VPS_PUB" ]; then
  /root/miniweed-rollback-firewall.sh || true
  echo "La clave activa de wg0 no coincide con la nueva clave generada."
  echo "Esperada: $VPS_PUB"
  echo "Activa:   $ACTIVE_PUB"
  exit 1
fi

touch "$ROLLBACK_FLAG"
kill "$ROLLBACK_PID" 2>/dev/null || true

echo ""
echo "=============================================="
echo " VPS Public Key: $VPS_PUB"
echo "=============================================="
echo " SSH PORT permitido: $SSH_PORT"
if [ "$SSH_HARDENED" = "yes" ]; then
  echo " SSH hardening: PasswordAuthentication no (solo clave publica)"
else
  echo " SSH hardening: OMITIDO para evitar lockout"
fi
echo " IMPORTANTE: en el panel cloud del proveedor abre TCP 80/443 y UDP $WG_PORT"
echo " Backup firewall: $BACKUP_FILE"
echo " Rollback script: /root/miniweed-rollback-firewall.sh"
echo " Pega esta clave en Umbrel Tunnel y listo."
`;
}

function buildKillSwitchScript() {
  return `#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[killswitch] must run as root"
  exit 1
fi

WG_PORT="\${WG_PORT:-51820}"
STATUS_FILE="\${STATUS_FILE:-/var/run/miniweed.status}"

echo "[killswitch] stopping wg0"
systemctl stop wg-quick@wg0 || true

echo "[killswitch] blocking udp/\${WG_PORT}"
iptables -w -C INPUT -p udp --dport "$WG_PORT" -j DROP 2>/dev/null || iptables -w -A INPUT -p udp --dport "$WG_PORT" -j DROP

echo "killed at $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATUS_FILE"
echo "[killswitch] completed"
`;
}

function buildVpsRotateScript(cfg, next, target) {
  const selected = target;
  if (!selected) throw new Error('No hay VPS activo para rotación');
  const clientIp = safeTunnelIp(cfg.tunnelClientIp, DEFAULT_CONFIG.tunnelClientIp);
  const serverIp = safeTunnelIp(cfg.tunnelServerIp, DEFAULT_CONFIG.tunnelServerIp);
  const pskLine = next.presharedKey ? `PresharedKey = ${next.presharedKey}` : '';
  return `#!/usr/bin/env bash
set -euo pipefail

BACKUP="/etc/wireguard/wg0.conf.rotate-$(date +%s).bak"
NEW_CONF_FILE="/tmp/wg0.rotate.new.conf"

rollback() {
  echo "ROTATE_FAIL: restoring $BACKUP"
  cp "$BACKUP" /etc/wireguard/wg0.conf
  wg-quick down wg0 2>/dev/null || true
  wg-quick up wg0
  exit 1
}

trap rollback ERR

cp /etc/wireguard/wg0.conf "$BACKUP"

cat > "$NEW_CONF_FILE" <<'WGEOF'
[Interface]
Address = ${serverIp}/24
ListenPort = ${selected.port}
PrivateKey = __KEEP_EXISTING_VPS_PRIVATE_KEY__

[Peer]
PublicKey = ${next.publicKey}
${pskLine}
AllowedIPs = ${clientIp}/32
WGEOF

if grep -q '^PrivateKey' /etc/wireguard/wg0.conf; then
  VPS_PRIV=$(awk -F' = ' '/^PrivateKey/ {print $2; exit}' /etc/wireguard/wg0.conf)
else
  echo "No se pudo leer PrivateKey actual de /etc/wireguard/wg0.conf"
  exit 1
fi

sed -i "s|__KEEP_EXISTING_VPS_PRIVATE_KEY__|$VPS_PRIV|g" "$NEW_CONF_FILE"
cp "$NEW_CONF_FILE" /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf

wg-quick down wg0 || true
wg-quick up wg0

for i in $(seq 1 30); do
  HS=$(wg show wg0 latest-handshakes | awk '{print $2}' | head -n1)
  if [ -n "$HS" ] && [ "$HS" -gt 0 ] 2>/dev/null; then
    NOW=$(date +%s)
    AGE=$((NOW - HS))
    if [ "$AGE" -lt 90 ]; then
      echo "ROTATE_OK"
      exit 0
    fi
  fi
  sleep 1
done

rollback
`;
}

module.exports = {
  generateWgConf,
  generateCaddyfile,
  generateVpsScript,
  buildKillSwitchScript,
  buildVpsRotateScript
};
