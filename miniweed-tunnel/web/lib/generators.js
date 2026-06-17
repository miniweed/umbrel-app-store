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
    // MTU reducido: evita que paquetes grandes (p. ej. la cadena de cert TLS)
    // se descarten en el túnel detrás de enlaces con MTU < 1500.
    'MTU = 1240',
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

function generateVpsScript(cfg, target) {
  const selected = target;
  if (!selected) throw new Error('No VPS selected');
  const clientIp = safeTunnelIp(cfg.tunnelClientIp, DEFAULT_CONFIG.tunnelClientIp);
  const serverIp = safeTunnelIp(cfg.tunnelServerIp, DEFAULT_CONFIG.tunnelServerIp);
  const pskLine = cfg.presharedKey
    ? `PresharedKey = ${cfg.presharedKey}`
    : '';
  return `#!/bin/bash
# Umbrel Tunnel — VPS Setup
# Run as root on a Debian/Ubuntu VPS
# VPS dedicated exclusively to reverse proxy

set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root"
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
  echo "Could not detect the public network interface"
  exit 1
fi

SSH_PORT=$(/usr/sbin/sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)
if [ -z "$SSH_PORT" ]; then
  SSH_PORT=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
fi
[ -z "$SSH_PORT" ] && SSH_PORT=22

if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)\${SSH_PORT}$"; then
  echo "sshd not detected listening on port $SSH_PORT. Aborting to avoid lockout."
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
  echo "No firewall backup to restore"
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

# MSS clamping: required so the TLS handshake (certificate chain,
# several KB) is not dropped in the WireGuard tunnel behind a link with MTU < 1500.
iptables -w -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200

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

# Automatic security updates
systemctl enable unattended-upgrades >/dev/null 2>&1 || true
systemctl restart unattended-upgrades >/dev/null 2>&1 || true

# Harden SSH to public-key only (without breaking access)
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
    echo "Warning: invalid SSH configuration, skipping SSH hardening"
  fi
else
  echo "Warning: /root/.ssh/authorized_keys does not exist or is empty; keeping password access to avoid lockout"
fi

VPS_PRIV=$(wg genkey)
VPS_PUB=$(echo "$VPS_PRIV" | wg pubkey)

cat > /etc/wireguard/wg0.conf <<WGEOF
[Interface]
Address = ${serverIp}/24
ListenPort = ${selected.port}
PrivateKey = $VPS_PRIV
MTU = 1240

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
  echo "WireGuard did not start correctly. Firewall restored."
  exit 1
fi

ACTIVE_PUB=$(wg show wg0 public-key 2>/dev/null || true)
if [ -z "$ACTIVE_PUB" ]; then
  /root/miniweed-rollback-firewall.sh || true
  echo "Could not read the active wg0 public key after applying the configuration."
  exit 1
fi
if [ "$ACTIVE_PUB" != "$VPS_PUB" ]; then
  /root/miniweed-rollback-firewall.sh || true
  echo "The active wg0 key does not match the newly generated key."
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
echo " SSH PORT allowed: $SSH_PORT"
if [ "$SSH_HARDENED" = "yes" ]; then
  echo " SSH hardening: PasswordAuthentication no (public key only)"
else
  echo " SSH hardening: SKIPPED to avoid lockout"
fi
echo " IMPORTANT: in your cloud provider panel open TCP 80/443 and UDP $WG_PORT"
echo " Backup firewall: $BACKUP_FILE"
echo " Rollback script: /root/miniweed-rollback-firewall.sh"
echo " Paste this key into Umbrel Tunnel and you are done."
`;
}

module.exports = {
  generateWgConf,
  generateCaddyfile,
  generateVpsScript
};
