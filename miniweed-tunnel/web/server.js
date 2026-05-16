const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { Client } = require('ssh2');

const app = express();
const DATA_DIR = process.env.DATA_DIR || '/data';
const WG_API_HOST = process.env.WG_API_HOST || 'wg';
const WG_API_PORT = 8080;
const API_AUTH_TOKEN = process.env.TUNNEL_API_TOKEN || '';

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

app.use(express.json({ limit: '32kb' }));

const apiRateWindowMs = 60 * 1000;
const apiRateMax = 120;
const apiRateStore = new Map();

function apiRateLimit(req, res, next) {
  const now = Date.now();
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const entry = apiRateStore.get(ip);

  if (!entry || now > entry.resetAt) {
    apiRateStore.set(ip, { count: 1, resetAt: now + apiRateWindowMs });
    return next();
  }

  entry.count += 1;
  if (entry.count > apiRateMax) {
    return res.status(429).json({ error: 'Demasiadas peticiones, prueba de nuevo en un minuto' });
  }

  return next();
}

function requireApiAuth(req, res, next) {
  if (!API_AUTH_TOKEN) return next();
  const token = req.get('x-tunnel-api-token');
  if (token !== API_AUTH_TOKEN) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  return next();
}

app.use('/api', apiRateLimit, requireApiAuth);
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.get(['/', '/index.html'], (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  let html = fs.readFileSync(indexPath, 'utf8');
  html = html.replace('__TUNNEL_API_TOKEN__', JSON.stringify(API_AUTH_TOKEN));
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

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
# VPS dedicado exclusivamente a reverse proxy

set -euo pipefail

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

apt-get update -qq
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
apt-get install -y -qq wireguard iptables iptables-persistent fail2ban unattended-upgrades

PUBLIC_IF=$(ip route show default | awk '/default/{print $5; exit}')
if [ -z "$PUBLIC_IF" ]; then
  echo "No se pudo detectar la interfaz de red publica"
  exit 1
fi

SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')
if [ -z "$SSH_PORT" ]; then
  SSH_PORT=$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
fi
[ -z "$SSH_PORT" ] && SSH_PORT=22

if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)\${SSH_PORT}$"; then
  echo "No se detecta sshd escuchando en el puerto $SSH_PORT. Abortando para evitar lockout."
  exit 1
fi

WG_PORT=${cfg.vpsPort}
WG_CLIENT_IP=${cfg.tunnelClientIp}

mkdir -p /root/miniweed-backups
BACKUP_FILE="/root/miniweed-backups/iptables-before-$(date +%s).rules"
iptables-save > "$BACKUP_FILE"

cat > /root/miniweed-rollback-firewall.sh <<ROLLBACKEOF
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
iptables -w -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
iptables -w -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT

iptables -w -t nat -A PREROUTING -i "$PUBLIC_IF" -p tcp --dport 80 -j DNAT --to-destination "$WG_CLIENT_IP:80"
iptables -w -t nat -A PREROUTING -i "$PUBLIC_IF" -p tcp --dport 443 -j DNAT --to-destination "$WG_CLIENT_IP:443"
iptables -w -t nat -A POSTROUTING -o "$PUBLIC_IF" -j MASQUERADE

iptables -w -A FORWARD -i "$PUBLIC_IF" -o wg0 -p tcp -d "$WG_CLIENT_IP" --dport 80 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -w -A FORWARD -i "$PUBLIC_IF" -o wg0 -p tcp -d "$WG_CLIENT_IP" --dport 443 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -w -A FORWARD -i wg0 -o "$PUBLIC_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

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

VPS_PRIV=$(wg genkey)
VPS_PUB=$(echo "$VPS_PRIV" | wg pubkey)

cat > /etc/wireguard/wg0.conf <<WGEOF
[Interface]
Address = ${cfg.tunnelServerIp}/24
ListenPort = ${cfg.vpsPort}
PrivateKey = $VPS_PRIV

[Peer]
PublicKey = ${cfg.publicKey}
AllowedIPs = ${cfg.tunnelClientIp}/32
WGEOF

chmod 600 /etc/wireguard/wg0.conf

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

if ! systemctl is-active --quiet wg-quick@wg0; then
  /root/miniweed-rollback-firewall.sh || true
  echo "WireGuard no arrancó correctamente. Firewall restaurado."
  exit 1
fi

touch "$ROLLBACK_FLAG"
kill "$ROLLBACK_PID" 2>/dev/null || true

echo ""
echo "=============================================="
echo " VPS Public Key: $VPS_PUB"
echo "=============================================="
echo " SSH PORT permitido: $SSH_PORT"
echo " Backup firewall: $BACKUP_FILE"
echo " Rollback script: /root/miniweed-rollback-firewall.sh"
echo " Pega esta clave en Umbrel Tunnel y listo."
`;
}

function validateSshDeployInput(input) {
  const host = (input.sshHost || '').trim();
  const user = (input.sshUser || 'root').trim();
  const port = parseInt(input.sshPort, 10) || 22;
  const privateKey = input.privateKey || '';
  const passphrase = input.passphrase || '';
  const password = input.password || '';

  if (!host) return { error: 'SSH host requerido' };
  if (!user) return { error: 'SSH user requerido' };
  if (port < 1 || port > 65535) return { error: 'SSH port inválido' };
  if (!privateKey && !password) {
    return { error: 'Debes proporcionar clave privada SSH o password' };
  }

  if (privateKey && (!privateKey.includes('BEGIN') || !privateKey.includes('PRIVATE KEY'))) {
    return { error: 'Clave privada SSH inválida' };
  }

  return {
    host,
    user,
    port,
    privateKey,
    passphrase,
    password
  };
}

function runRemoteCommand(ssh, command, timeoutMs = 20 * 60 * 1000) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';

    ssh.exec(command, (err, stream) => {
      if (err) return reject(err);

      const timer = setTimeout(() => {
        stream.close();
        reject(new Error('Timeout ejecutando comando remoto (20m)'));
      }, timeoutMs);

      stream.on('close', code => {
        clearTimeout(timer);
        resolve({ code, stdout, stderr });
      });

      stream.on('data', data => {
        stdout += data.toString();
      });

      stream.stderr.on('data', data => {
        stderr += data.toString();
      });
    });
  });
}

function deployScriptOverSsh(sshConfig, script) {
  return new Promise((resolve, reject) => {
    const ssh = new Client();
    ssh.on('ready', async () => {
      try {
        const encoded = Buffer.from(script, 'utf8').toString('base64');
        const remotePath = '/root/miniweed-tunnel-vps-setup.sh';
        const cmd = [
          `printf '%s' '${encoded}' | base64 -d > ${remotePath}`,
          `chmod 700 ${remotePath}`,
          `bash -n ${remotePath}`,
          `bash ${remotePath} > /root/miniweed-tunnel-vps-setup.last.log 2>&1 || (cat /root/miniweed-tunnel-vps-setup.last.log && exit 1)`,
          `cat /root/miniweed-tunnel-vps-setup.last.log`
        ].join(' && ');

        const result = await runRemoteCommand(ssh, cmd);
        ssh.end();
        resolve(result);
      } catch (err) {
        ssh.end();
        reject(err);
      }
    });

    ssh.on('error', reject);
    ssh.connect({
      host: sshConfig.host,
      port: sshConfig.port,
      username: sshConfig.user,
      privateKey: sshConfig.privateKey || undefined,
      passphrase: sshConfig.passphrase || undefined,
      password: sshConfig.password || undefined,
      readyTimeout: 20000
    });
  });
}

function extractVpsPublicKey(text) {
  if (!text) return '';
  const match = text.match(/VPS Public Key:\s*([A-Za-z0-9+/]{43}=)/);
  return match ? match[1] : '';
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

app.post('/api/deploy-vps', async (req, res) => {
  const cfg = loadConfig();
  if (!cfg.publicKey || !cfg.vpsIp) {
    return res.status(400).json({ error: 'Configura la IP del VPS y genera las claves primero' });
  }

  const parsed = validateSshDeployInput(req.body || {});
  if (parsed.error) {
    return res.status(400).json({ error: parsed.error });
  }

  const script = generateVpsScript(cfg);

  try {
    const result = await deployScriptOverSsh(parsed, script);
    if (result.code !== 0) {
      return res.status(500).json({
        error: 'Error ejecutando script en VPS',
        stdout: result.stdout,
        stderr: result.stderr,
        code: result.code
      });
    }

    const combinedOutput = `${result.stdout || ''}\n${result.stderr || ''}`;
    const vpsPubKey = extractVpsPublicKey(combinedOutput);
    let autoConfigured = false;

    if (vpsPubKey) {
      cfg.vpsPubKey = vpsPubKey;
      saveConfig(cfg);

      const wgConf = generateWgConf(cfg);
      if (wgConf) {
        fs.writeFileSync(WG_CONF, wgConf);
        autoConfigured = true;
      }
      fs.writeFileSync(CADDYFILE, generateCaddyfile(cfg));
    }

    return res.json({
      ok: true,
      stdout: result.stdout,
      stderr: result.stderr,
      vpsPubKey,
      autoConfigured
    });
  } catch (err) {
    return res.status(500).json({ error: `Fallo SSH: ${err.message}` });
  }
});

// ── boot ─────────────────────────────────────────────────────────────────────

ensureDataDir();
const PORT = parseInt(process.env.PORT) || 3000;
app.listen(PORT, () => console.log(`[web] Umbrel Tunnel UI en :${PORT}`));
