const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');

const app = express();
const DATA_DIR = process.env.DATA_DIR || '/data';
const WG_API_HOST = process.env.WG_API_HOST || 'wg';
const WG_API_PORT = 8080;

const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const WG_CONF = path.join(DATA_DIR, 'wg0.conf');
const CADDYFILE = path.join(DATA_DIR, 'Caddyfile');

const DEFAULT_CONFIG = {
  privateKey: '',
  publicKey: '',
  vpsIp: '',
  vpsPort: 51820,
  vpsPubKey: '',
  tunnelClientIp: '10.8.0.2',
  tunnelServerIp: '10.8.0.1',
  domain: '',
  acmeEmail: '',
  services: []
};

const DEFAULT_CADDYFILE = ':80 {\n  respond "Umbrel Tunnel — not configured yet"\n}\n';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── helpers ──────────────────────────────────────────────────────────────────

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(CADDYFILE)) {
    fs.writeFileSync(CADDYFILE, DEFAULT_CADDYFILE);
  }
}

function loadConfig() {
  try {
    return { ...DEFAULT_CONFIG, ...JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

function isWireGuardKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) return false;
  try {
    return Buffer.from(value, 'base64').length === 32;
  } catch {
    return false;
  }
}

function isHostname(value) {
  if (typeof value !== 'string' || value.length > 253) return false;
  const labels = value.split('.');
  if (labels.length < 2) return false;
  return labels.every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label));
}

function isSubdomain(value) {
  if (!value) return true;
  return typeof value === 'string' && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(value);
}

function isEmail(value) {
  return !value || (typeof value === 'string' && /^[^\s@{}]+@[^\s@{}]+\.[^\s@{}]+$/.test(value));
}

function isTargetUrl(value) {
  try {
    const url = new URL(value);
    const hasPath = url.pathname && url.pathname !== '/';
    const hasQuery = Boolean(url.search);
    const hasHash = Boolean(url.hash);
    return ['http:', 'https:'].includes(url.protocol)
      && !/[\r\n{}]/.test(value)
      && !hasPath
      && !hasQuery
      && !hasHash;
  } catch {
    return false;
  }
}

function normalizeTargetUrl(value) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    if (!['http:', 'https:'].includes(parsed.protocol)) return '';
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return '';
  }
}

function validateConfig(cfg) {
  const errors = [];

  if (cfg.vpsPort < 1 || cfg.vpsPort > 65535) errors.push('El puerto WireGuard debe estar entre 1 y 65535');
  if (cfg.privateKey && !isWireGuardKey(cfg.privateKey)) errors.push('La clave privada de Umbrel no es válida');
  if (cfg.publicKey && !isWireGuardKey(cfg.publicKey)) errors.push('La clave pública de Umbrel no es válida');
  if (cfg.vpsPubKey && !isWireGuardKey(cfg.vpsPubKey)) errors.push('La clave pública del VPS no es válida');
  if (cfg.domain && !isHostname(cfg.domain)) errors.push('El dominio principal no es válido');
  if (!isEmail(cfg.acmeEmail)) errors.push('El email de Let\'s Encrypt no es válido');

  const seenHosts = new Set();
  for (const [index, svc] of (cfg.services || []).entries()) {
    if (!isSubdomain(svc.subdomain)) errors.push(`El subdominio del servicio ${index + 1} no es válido`);
    if (svc.target && !isTargetUrl(svc.target)) errors.push(`La URL interna del servicio ${index + 1} no es válida`);

    if (cfg.domain && svc.enabled && svc.target) {
      const host = svc.subdomain ? `${svc.subdomain}.${cfg.domain}`.toLowerCase() : cfg.domain.toLowerCase();
      if (seenHosts.has(host)) {
        errors.push(`Hay dos servicios usando el mismo host público (${host})`);
      }
      seenHosts.add(host);
    }
  }

  return errors;
}

function generateWgConf(cfg) {
  if (!cfg.privateKey || !cfg.vpsPubKey || !cfg.vpsIp) return null;
  return [
    '[Interface]',
    `Address = ${cfg.tunnelClientIp}/32`,
    `PrivateKey = ${cfg.privateKey}`,
    '',
    '[Peer]',
    `PublicKey = ${cfg.vpsPubKey}`,
    `Endpoint = ${cfg.vpsIp}:${cfg.vpsPort}`,
    `AllowedIPs = ${cfg.tunnelServerIp}/32`,
    'PersistentKeepalive = 25',
    ''
  ].join('\n');
}

function generateCaddyfile(cfg) {
  const enabled = (cfg.services || []).filter(s => s.enabled && s.target);
  if (!cfg.domain || !cfg.acmeEmail || !enabled.length) return DEFAULT_CADDYFILE;

  const blocks = [`{\n  email ${cfg.acmeEmail}\n  admin localhost:2019\n}\n`];
  for (const svc of enabled) {
    const host = svc.subdomain ? `${svc.subdomain}.${cfg.domain}` : cfg.domain;
    blocks.push(`${host} {\n  reverse_proxy ${svc.target}\n}\n`);
  }
  return blocks.join('\n');
}

function generateVpsScript(cfg) {
  return `#!/bin/bash
# Umbrel Tunnel — VPS Setup
# Ejecutar como root en un VPS Debian/Ubuntu

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Este script debe ejecutarse como root"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard iptables fail2ban unattended-upgrades

# Baseline de hardening de red y kernel
cat > /etc/sysctl.d/99-miniweed-tunnel-hardening.conf <<'SYSCTLEOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_syncookies=1
SYSCTLEOF
sysctl --system >/dev/null

# Fail2ban para SSH
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/sshd.local <<'FAIL2BANEOF'
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

VPS_PRIV=$(wg genkey)
VPS_PUB=$(echo "$VPS_PRIV" | wg pubkey)
ETH=$(ip route show default | awk '/default/{print $5}' | head -1)

cat > /etc/wireguard/wg0.conf <<WGEOF
[Interface]
Address = ${cfg.tunnelServerIp}/24
ListenPort = ${cfg.vpsPort}
PrivateKey = $VPS_PRIV
PostUp   = iptables -w -t nat -A PREROUTING -i $ETH -p tcp --dport 80  -j DNAT --to-destination ${cfg.tunnelClientIp}:80
PostUp   = iptables -w -t nat -A PREROUTING -i $ETH -p tcp --dport 443 -j DNAT --to-destination ${cfg.tunnelClientIp}:443
PostUp   = iptables -w -t nat -A POSTROUTING -o $ETH -j MASQUERADE
PostUp   = iptables -w -A FORWARD -i $ETH -o wg0 -p tcp -d ${cfg.tunnelClientIp} --dport 80 -j ACCEPT
PostUp   = iptables -w -A FORWARD -i $ETH -o wg0 -p tcp -d ${cfg.tunnelClientIp} --dport 443 -j ACCEPT
PostUp   = iptables -w -A FORWARD -i wg0 -o $ETH -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PreDown  = iptables -w -t nat -D PREROUTING -i $ETH -p tcp --dport 80  -j DNAT --to-destination ${cfg.tunnelClientIp}:80
PreDown  = iptables -w -t nat -D PREROUTING -i $ETH -p tcp --dport 443 -j DNAT --to-destination ${cfg.tunnelClientIp}:443
PreDown  = iptables -w -t nat -D POSTROUTING -o $ETH -j MASQUERADE
PreDown  = iptables -w -D FORWARD -i $ETH -o wg0 -p tcp -d ${cfg.tunnelClientIp} --dport 80 -j ACCEPT
PreDown  = iptables -w -D FORWARD -i $ETH -o wg0 -p tcp -d ${cfg.tunnelClientIp} --dport 443 -j ACCEPT
PreDown  = iptables -w -D FORWARD -i wg0 -o $ETH -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

[Peer]
PublicKey = ${cfg.publicKey}
AllowedIPs = ${cfg.tunnelClientIp}/32
WGEOF

chmod 600 /etc/wireguard/wg0.conf

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

echo ""
echo "=============================================="
echo " VPS Public Key: $VPS_PUB"
echo "=============================================="
echo " Pega esta clave en Umbrel Tunnel y listo."
`;
}

function wgApi(urlPath) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: WG_API_HOST, port: WG_API_PORT, path: urlPath, method: 'GET' },
      res => {
        let data = '';
        res.on('data', c => (data += c));
        res.on('end', () => {
          try { resolve(JSON.parse(data)); } catch { resolve(data); }
        });
      }
    );
    req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.end();
  });
}

// ── routes ───────────────────────────────────────────────────────────────────

app.get('/api/config', (req, res) => {
  const cfg = loadConfig();
  // Never expose private key to the frontend
  res.json({ ...cfg, privateKey: cfg.privateKey ? '••••' : '' });
});

app.post('/api/config', (req, res) => {
  const existing = loadConfig();
  const update = req.body;
  if (update.privateKey === '••••') update.privateKey = existing.privateKey;

  const cfg = { ...existing, ...update };
  cfg.vpsPort = parseInt(cfg.vpsPort, 10) || 51820;
  cfg.services = Array.isArray(cfg.services)
    ? cfg.services.map(svc => ({
        name: (svc.name || '').trim(),
        subdomain: (svc.subdomain || '').trim().toLowerCase(),
        target: normalizeTargetUrl(svc.target),
        enabled: Boolean(svc.enabled)
      }))
    : [];

  const errors = validateConfig(cfg);
  if (errors.length) {
    return res.status(400).json({ errors });
  }

  saveConfig(cfg);

  const wgConf = generateWgConf(cfg);
  if (wgConf) fs.writeFileSync(WG_CONF, wgConf);
  fs.writeFileSync(CADDYFILE, generateCaddyfile(cfg));

  res.json({ ok: true });
});

app.get('/api/keygen', async (req, res) => {
  try {
    const keys = await wgApi('/keygen');
    // Save private key immediately, return only public key
    const cfg = loadConfig();
    cfg.privateKey = keys.privateKey;
    cfg.publicKey = keys.publicKey;
    saveConfig(cfg);
    res.json({ publicKey: keys.publicKey });
  } catch (err) {
    res.status(503).json({ error: 'WireGuard no disponible: ' + err.message });
  }
});

app.get('/api/status', async (req, res) => {
  try {
    res.json(await wgApi('/status'));
  } catch {
    res.json({ connected: false, raw: 'WireGuard no disponible' });
  }
});

app.get('/api/vps-setup', (req, res) => {
  const cfg = loadConfig();
  if (!cfg.publicKey || !cfg.vpsIp) {
    return res.status(400).json({ error: 'Configura la IP del VPS y genera las claves primero' });
  }
  res.json({ script: generateVpsScript(cfg) });
});

// ── boot ─────────────────────────────────────────────────────────────────────

ensureDataDir();
const PORT = parseInt(process.env.PORT) || 3000;
app.listen(PORT, () => console.log(`[web] Umbrel Tunnel UI en :${PORT}`));
