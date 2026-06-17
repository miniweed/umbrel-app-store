const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const zlib = require('zlib');
const crypto = require('crypto');
const dns = require('dns');
const { ConfigSchema } = require('./api-spec/schemas');
const {
  isWireGuardKey,
  keyFingerprint,
  isHostname,
  isSubdomain,
  isEmail,
  isValidIpv4,
  safeTunnelIp,
  isTargetUrl,
  normalizeTargetUrl,
  isDisallowedTargetIp,
  isBlockedServiceTarget
} = require('./lib/validation');
const {
  generateWgConf,
  generateCaddyfile,
  generateVpsScript
} = require('./lib/generators');
const { seal, open, isSealed } = require('./lib/cryptobox');
const audit = require('./lib/audit');

const {
  DATA_DIR,
  WG_API_HOST,
  WG_API_PORT,
  WG_API_TOKEN,
  MAX_SERVICES,
  CONFIG_FILE,
  WG_CONF,
  CADDYFILE,
  APP_SEED_FILE,
  HEALTH_FILE,
  KNOWN_HOSTS_FILE,
  ENCRYPTED_FIELDS,
  DEFAULT_CONFIG,
  DEFAULT_CADDYFILE
} = require('./config/constants');

const app = express();

// In-memory mutable state (config lock).
let configLock = Promise.resolve();

app.use(express.json({ limit: '32kb' }));
app.disable('x-powered-by');

function cspHeaderForPath(pathname) {
  return "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";
}

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  const isHttps = req.secure || req.get('x-forwarded-proto') === 'https';
  if (isHttps) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  res.setHeader('Content-Security-Policy', cspHeaderForPath(req.path));
  next();
});

// realIp: usa el peer TCP (no falsificable vía X-Forwarded-For) para el conteo.
// Imprescindible en endpoints sensibles a fuerza bruta.
const rateBuckets = {
  default: { max: 120, windowMs: 60_000 },
  '/api/keygen': { max: 5, windowMs: 3_600_000, realIp: true },
  '/api/vps-setup-script': { max: 10, windowMs: 600_000 },
  '/api/config': { max: 30, windowMs: 60_000 }
};
const apiRateStore = new Map();
let rateGc = null;
let healthTimer = null;
let runningServers = 0;

app.set('trust proxy', 1);

function withConfigLock(fn) {
  const run = configLock.then(() => fn());
  configLock = run.catch(() => {});
  return run;
}

// Real TCP peer IP (not spoofable via X-Forwarded-For) for rate limiting.
function authClientIp(req) {
  return req.socket?.remoteAddress || req.ip || 'unknown';
}

function cleanupApiRateStore() {
  const now = Date.now();
  for (const [bucketName, bucketStore] of apiRateStore.entries()) {
    for (const [ip, entry] of bucketStore.entries()) {
      if (!entry || now > entry.resetAt) bucketStore.delete(ip);
    }
    if (bucketStore.size === 0) apiRateStore.delete(bucketName);
  }
}

function ensureBackgroundTimers() {
  if (!rateGc) {
    rateGc = setInterval(cleanupApiRateStore, 60 * 1000);
    if (typeof rateGc.unref === 'function') rateGc.unref();
  }
}

function stopBackgroundTimers() {
  if (rateGc) {
    clearInterval(rateGc);
    rateGc = null;
  }
  if (healthTimer) {
    clearInterval(healthTimer);
    healthTimer = null;
  }
}

function apiRateLimit(req, res, next) {
  const bucketName = rateBuckets[req.path] ? req.path : 'default';
  const bucket = rateBuckets[bucketName];
  const store = apiRateStore.get(bucketName) || new Map();
  apiRateStore.set(bucketName, store);
  const now = Date.now();
  const ip = bucket.realIp ? authClientIp(req) : (req.ip || req.socket?.remoteAddress || 'unknown');
  const entry = store.get(ip);

  if (!entry || now > entry.resetAt) {
    store.set(ip, { count: 1, resetAt: now + bucket.windowMs });
    return next();
  }

  entry.count += 1;
  if (entry.count > bucket.max) {
    const retryAfter = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
    res.setHeader('Retry-After', String(retryAfter));
    return res.status(429).json({ error: 'Too many requests, try again in a minute' });
  }

  return next();
}

app.use('/api', apiRateLimit);
app.use((req, res, next) => {
  res.on('finish', () => {
    if (!req.path.startsWith('/api/')) return;
    if (req.method === 'GET' && res.statusCode === 200 && req.path !== '/api/vps-setup-script') return;
    audit.log({
      action: `http.${req.method.toLowerCase()}`,
      path: req.path,
      status: res.statusCode,
      ip: req.ip,
      ua: (req.get('user-agent') || '').slice(0, 120)
    });
  });
  next();
});

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.get(['/', '/index.html'], (req, res, next) => {
  const spaIndex = path.join(__dirname, 'public', 'app', 'index.html');
  if (!fs.existsSync(spaIndex)) return next();
  return res.sendFile(spaIndex);
});

app.get(['/app', '/app/*'], (req, res, next) => {
  const spaIndex = path.join(__dirname, 'public', 'app', 'index.html');
  if (!fs.existsSync(spaIndex)) return next();
  return res.sendFile(spaIndex);
});

// ── helpers ──────────────────────────────────────────────────────────────────

function ensureDataDir() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  } catch (err) {
    console.error(`[warn] could not prepare data dir ${DATA_DIR}: ${err.message}`);
    return;
  }
  if (!fs.existsSync(CADDYFILE)) {
    try {
      fs.writeFileSync(CADDYFILE, DEFAULT_CADDYFILE);
    } catch (err) {
      console.error(`[warn] could not initialize ${CADDYFILE}: ${err.message}`);
    }
  }
}

function encryptConfig(cfg) {
  const out = { ...cfg, _encVersion: 1 };
  for (const f of ENCRYPTED_FIELDS) {
    if (out[f] && !isSealed(out[f])) out[f] = seal(out[f]);
  }
  if (Array.isArray(out.services)) {
    out.services = out.services.map(svc => ({
      ...svc,
      target: svc.target && !isSealed(svc.target) ? seal(svc.target) : svc.target
    }));
  }

  return out;
}

function decryptConfig(cfg) {
  const out = { ...cfg };
  for (const f of ENCRYPTED_FIELDS) {
    if (isSealed(out[f])) out[f] = open(out[f]);
  }
  if (Array.isArray(out.services)) {
    out.services = out.services.map(svc => ({
      ...svc,
      target: isSealed(svc.target) ? open(svc.target) : svc.target
    }));
  }

  return out;
}

function migrateConfigIfNeeded() {
  if (!fs.existsSync(CONFIG_FILE)) return;
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    if (raw && raw._encVersion === 1) return;
    const backup = CONFIG_FILE + '.v0.bak';
    fs.copyFileSync(CONFIG_FILE, backup);
    fs.chmodSync(backup, 0o600);
    saveConfig(raw || {});
    console.log('[migration] config.json encrypted v0 -> v1');
  } catch (err) {
    console.error('[migration] failed to migrate config:', err.message);
  }
}

function loadOrCreateAppSeed() {
  const envSeed = (process.env.APP_SEED || process.env.TUNNEL_API_TOKEN || '').trim();
  if (envSeed.length >= 32) return envSeed;

  if (fs.existsSync(APP_SEED_FILE)) {
    try {
      const stored = String(fs.readFileSync(APP_SEED_FILE, 'utf8') || '').trim();
      if (stored.length >= 32) return stored;
    } catch {
      // Continue to regeneration path.
    }
  }

  const generated = crypto.randomBytes(48).toString('base64url');
  try {
    fs.writeFileSync(APP_SEED_FILE, `${generated}\n`, { mode: 0o600 });
  } catch (err) {
    console.error(`[warn] could not persist app seed: ${err.message}`);
  }
  return generated;
}

function loadConfig() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    const dec = decryptConfig(raw);
    return { ...DEFAULT_CONFIG, ...dec };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

function saveConfig(cfg) {
  fs.mkdirSync(path.dirname(CONFIG_FILE), { recursive: true });
  const tmp = CONFIG_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(encryptConfig(cfg), null, 2), { mode: 0o600 });
  fs.renameSync(tmp, CONFIG_FILE);
}

// Single-VPS target derived from the saved VPS fields.
// Only the IP is required: the VPS public key isn't known until the setup script
// has been run on the VPS, so the script must be generatable with just the IP.
// generateWgConf checks for the pubKey itself before producing wg0.conf.
function getActiveVpsTarget(cfg) {
  if (!cfg.vpsIp) return null;
  return {
    id: 'primary',
    name: 'VPS',
    ip: cfg.vpsIp,
    port: cfg.vpsPort || 51820,
    pubKey: cfg.vpsPubKey || '',
    enabled: true,
    priority: 0
  };
}


// Envuelve handlers async para que un rechazo vaya a next(err) en vez de colgar
// la request (Express 4 no captura rejections de funciones async por sí solo).
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function serviceKey(svc) {
  const subdomain = (svc?.subdomain || '').trim().toLowerCase() || '@root';
  const target = (svc?.target || '').trim().toLowerCase();
  return `${subdomain}|${target}`;
}

function probeServiceTarget(target, timeoutMs = 4000) {
  return new Promise(resolve => {
    let parsed;
    try {
      parsed = new URL(target);
    } catch (err) {
      return resolve({ ok: false, error: 'Invalid URL' });
    }
    const isHttps = parsed.protocol === 'https:';
    if (!isHttps && parsed.protocol !== 'http:') {
      return resolve({ ok: false, error: 'Protocolo no soportado' });
    }

    const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
    // Resuelve el host y rechaza si apunta a loopback/metadata (anti-SSRF + anti-rebinding).
    // No bloquea RFC1918: exponer servicios internos es el propósito de la app.
    dns.lookup(hostname, { all: true }, (err, addresses) => {
      if (err || !addresses || addresses.length === 0) {
        return resolve({ ok: false, error: 'Not resolvable' });
      }
      const blocked = addresses.find(a => isDisallowedTargetIp(a.address));
      if (blocked) {
        return resolve({ ok: false, error: 'Target blocked' });
      }
      const pinned = addresses[0];

      const transport = isHttps ? https : http;
      const req = transport.request(
        {
          protocol: parsed.protocol,
          hostname,
          port: parsed.port || (isHttps ? 443 : 80),
          path: '/',
          method: 'GET',
          timeout: timeoutMs,
          // Fija la IP ya validada: evita que un segundo lookup (rebinding) apunte a otra IP.
          lookup: (_host, _opts, cb) => cb(null, pinned.address, pinned.family),
          servername: hostname,
          // Servicios internos suelen usar certs autofirmados; el probe solo mide alcance.
          rejectUnauthorized: false
        },
        res => {
          res.resume();
          resolve({ ok: true, statusCode: res.statusCode || 0 });
        }
      );

      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', e => resolve({ ok: false, error: e.message }));
      req.end();
    });
  });
}

function probeTcpPort(hostname, port, timeoutMs = 1500) {
  return new Promise(resolve => {
    const started = Date.now();
    const socket = new net.Socket();
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch {}
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      done({ ok: true, latencyMs: Date.now() - started, message: `tcp:${port}` });
    });
    socket.once('timeout', () => done({ ok: false, message: `timeout tcp:${port}` }));
    socket.once('error', err => done({ ok: false, message: err.message }));
    try {
      socket.connect(port, hostname);
    } catch (err) {
      done({ ok: false, message: err.message });
    }
  });
}

async function checkServicesHealth(services) {
  const health = {};
  await Promise.all((services || []).map(async svc => {
    const key = serviceKey(svc);
    if (!svc.enabled || !svc.target) {
      health[key] = { ok: false, checked: false, message: 'Disabled or incomplete' };
      return;
    }

    if (isBlockedServiceTarget(svc.target)) {
      health[key] = { ok: false, checked: false, message: 'Target not allowed' };
      return;
    }

    const result = await probeServiceTarget(svc.target);
    if (result.ok) {
      health[key] = {
        ok: true,
        checked: true,
        statusCode: result.statusCode,
        message: `Connected (${result.statusCode})`
      };
    } else {
      health[key] = {
        ok: false,
        checked: true,
        message: 'No connection'
      };
    }
  }));
  return health;
}

function validateConfig(cfg) {
  const errors = [];

  if ((cfg.services || []).length > MAX_SERVICES) {
    errors.push(`Too many services: max ${MAX_SERVICES}`);
  }

  if (cfg.privateKey && !isWireGuardKey(cfg.privateKey)) errors.push('The Umbrel private key is invalid');
  if (cfg.publicKey && !isWireGuardKey(cfg.publicKey)) errors.push('The Umbrel public key is invalid');

  if (cfg.vpsPort && (cfg.vpsPort < 1 || cfg.vpsPort > 65535)) {
    errors.push('The VPS WireGuard port must be between 1 and 65535');
  }
  if (cfg.vpsPubKey && !isWireGuardKey(cfg.vpsPubKey)) {
    errors.push('The VPS public key is invalid');
  }
  if (cfg.vpsIp && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(cfg.vpsIp) && !isHostname(cfg.vpsIp)) {
    errors.push('The VPS IP/host is invalid');
  }

  if (cfg.domain && !isHostname(cfg.domain)) errors.push('The main domain is invalid');
  if (!isEmail(cfg.acmeEmail)) errors.push('The Let\'s Encrypt email is invalid');

  const seenHosts = new Set();
  for (const [index, svc] of (cfg.services || []).entries()) {
    if (!isSubdomain(svc.subdomain)) errors.push(`The subdomain of service ${index + 1} is invalid`);
    if (svc.target && !isTargetUrl(svc.target)) errors.push(`The internal URL of service ${index + 1} is invalid`);
    if (svc.target && isBlockedServiceTarget(svc.target)) {
      errors.push(`The internal URL of service ${index + 1} points to a reserved or control target`);
    }

    if (cfg.domain && svc.enabled && svc.target) {
      const host = svc.subdomain ? `${svc.subdomain}.${cfg.domain}`.toLowerCase() : cfg.domain.toLowerCase();
      if (seenHosts.has(host)) {
        errors.push(`Two services use the same public host (${host})`);
      }
      seenHosts.add(host);
    }
  }

  return errors;
}


async function computeHealth(cfg) {
  const active = getActiveVpsTarget(cfg);
  const services = cfg?.services || [];
  const out = {};
  await Promise.all(services.map(async svc => {
    const key = serviceKey(svc);
    if (!svc.enabled || !svc.target) {
      out[key] = { ok: false, checked: false, message: 'Disabled or incomplete' };
      return;
    }
    if (isBlockedServiceTarget(svc.target)) {
      out[key] = { ok: false, checked: false, message: 'Target not allowed' };
      return;
    }
    const dnsHost = cfg.domain ? (svc.subdomain ? `${svc.subdomain}.${cfg.domain}` : cfg.domain) : null;
    const item = { checkedAt: new Date().toISOString() };
    if (dnsHost) {
      try {
        const addrs = await dns.promises.resolve4(dnsHost);
        item.dns = { ok: active?.ip ? addrs.includes(active.ip) : false, addrs, expected: active?.ip || '' };
      } catch (err) {
        item.dns = { ok: false, error: err.code || err.message };
      }
    }
    const targetProbe = await probeServiceTarget(svc.target, 5000);
    item.target = targetProbe.ok
      ? { ok: true, statusCode: targetProbe.statusCode }
      : { ok: false, error: targetProbe.error || 'probe_failed' };
    item.ok = Boolean((item.dns ? item.dns.ok : true) && item.target.ok);
    out[key] = item;
  }));
  return out;
}

async function refreshHealthSnapshot() {
  try {
    const cfg = loadConfig();
    const health = await computeHealth(cfg);
    fs.writeFileSync(HEALTH_FILE, JSON.stringify({
      services: health
    }, null, 2));
  } catch {
    // best effort background task
  }
}

function wgApi(urlPath) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: WG_API_HOST,
        port: WG_API_PORT,
        path: urlPath,
        method: 'GET',
        headers: WG_API_TOKEN ? { 'x-wg-api-token': WG_API_TOKEN } : {}
      },
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
  res.json({
    ...cfg,
    vpsIp: cfg.vpsIp || '',
    vpsPort: cfg.vpsPort || 51820,
    vpsPubKey: cfg.vpsPubKey || '',
    privateKey: cfg.privateKey ? '••••' : '',
    vpsPubKeyFingerprint: keyFingerprint(cfg.vpsPubKey || '')
  });
});

app.post('/api/config', async (req, res) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ error: 'validation', issues: [{ path: [], message: 'body must be an object' }] });
  }
  const parsedBody = ConfigSchema.safeParse(req.body);
  if (!parsedBody.success) {
    return res.status(400).json({ error: 'validation', issues: parsedBody.error.issues });
  }
  try {
    const result = await withConfigLock(async () => {
      const existing = loadConfig();
      const update = req.body || {};
      if (update.privateKey === '••••') update.privateKey = existing.privateKey;

      const cfg = { ...existing, ...update };
      cfg.services = Array.isArray(cfg.services)
        ? cfg.services.map(svc => ({
            name: (svc.name || '').trim(),
            subdomain: (svc.subdomain || '').trim().toLowerCase(),
            target: normalizeTargetUrl(svc.target),
            enabled: Boolean(svc.enabled)
          }))
        : [];

      const errors = validateConfig(cfg);
      if (errors.length) return { errors };

      cfg.serviceHealth = await checkServicesHealth(cfg.services);
      saveConfig(cfg);
      refreshHealthSnapshot();
      audit.log({
        action: 'config.update',
        domain: cfg.domain,
        serviceCount: cfg.services.length,
        ip: req.ip
      });

      const wgConf = generateWgConf(cfg, getActiveVpsTarget(cfg));
      if (wgConf) fs.writeFileSync(WG_CONF, wgConf);
      fs.writeFileSync(CADDYFILE, generateCaddyfile(cfg));

      return { ok: true, serviceHealth: cfg.serviceHealth };
    });

    if (result.errors) return res.status(400).json({ errors: result.errors });
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: `Error saving configuration: ${err.message}` });
  }
});



// ── tunnel endpoints ─────────────────────────────────────────────────────────

app.get('/api/keygen', async (req, res) => {
  try {
    const keys = await wgApi('/keygen');
    // Save private key immediately, return only public key
    const cfg = loadConfig();
    cfg.privateKey = keys.privateKey;
    cfg.publicKey = keys.publicKey;
    cfg.presharedKey = keys.presharedKey || '';
    saveConfig(cfg);
    audit.log({ action: 'keygen', ip: req.ip, publicKeyFingerprint: keyFingerprint(keys.publicKey) });
    res.json({ publicKey: keys.publicKey, publicKeyFingerprint: keyFingerprint(keys.publicKey) });
  } catch (err) {
    res.status(503).json({ error: 'WireGuard unavailable: ' + err.message });
  }
});

app.get('/api/status', async (req, res) => {
  try {
    res.json(await wgApi('/status'));
  } catch {
    res.json({ connected: false, raw: 'WireGuard unavailable' });
  }
});

app.get('/api/health', (req, res) => {
  if (!fs.existsSync(HEALTH_FILE)) return res.json({});
  try {
    return res.json(JSON.parse(fs.readFileSync(HEALTH_FILE, 'utf8')));
  } catch {
    return res.json({});
  }
});

app.post('/api/health/refresh', async (req, res) => {
  await refreshHealthSnapshot();
  if (!fs.existsSync(HEALTH_FILE)) return res.json({ ok: false, health: {} });
  try {
    const health = JSON.parse(fs.readFileSync(HEALTH_FILE, 'utf8'));
    return res.json({ ok: true, health });
  } catch {
    return res.json({ ok: false, health: {} });
  }
});


app.get('/api/vps-setup-script', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  const cfg = loadConfig();
  const selected = getActiveVpsTarget(cfg);
  if (!cfg.publicKey || !selected?.ip) {
    return res.status(400).json({ error: 'Configure the VPS IP and generate keys first' });
  }
  const withCrowdsec = String(req.query.withCrowdsec || '').trim() === '1';
  const script = generateVpsScript(cfg, selected, { withCrowdsec });
  const sha256 = crypto.createHash('sha256').update(script).digest('hex');
  if (req.query.format === 'plain') {
    audit.log({ action: 'script.download', format: 'plain', ip: req.ip, vpsId: selected.id, withCrowdsec });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="miniweed-tunnel-vps-setup.sh"');
    return res.send(script);
  }
  audit.log({ action: 'script.download', format: 'json', ip: req.ip, vpsId: selected.id, withCrowdsec });
  return res.json({
    script,
    sha256,
    filename: 'miniweed-tunnel-vps-setup.sh',
    vps: { id: selected.id, name: selected.name, ip: selected.ip, port: selected.port },
    withCrowdsec
  });
});

app.get('/api/audit', (req, res) => {
  const limitRaw = parseInt(req.query.limit, 10);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 1000) : 100;
  const entries = audit.readLatest(limit);
  res.json({ entries, total: entries.length });
});

app.get('/api/audit/verify', (req, res) => {
  res.json(audit.verifyChain());
});

// ── manejo de errores ────────────────────────────────────────────────────────

// Red de seguridad: cualquier throw síncrono o rechazo reenviado vía next(err)
// (handlers envueltos en asyncHandler) responde 500 en vez de colgar la request.
// No expone err.message al cliente para no filtrar contexto sensible.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  console.error(`[error] ${req.method} ${req.path}: ${err && err.message ? err.message : err}`);
  try {
    audit.log({ action: 'request.error', ip: req.ip, path: req.path });
  } catch {}
  return res.status(500).json({ error: 'Internal error' });
});

// ── boot ─────────────────────────────────────────────────────────────────────

function startServer() {
  ensureDataDir();
  ensureBackgroundTimers();
  process.env.APP_SEED = loadOrCreateAppSeed();
  migrateConfigIfNeeded();
  refreshHealthSnapshot();
  if (!healthTimer) {
    healthTimer = setInterval(() => {
      refreshHealthSnapshot();
    }, 5 * 60 * 1000);
    if (typeof healthTimer.unref === 'function') healthTimer.unref();
  }
  const parsedPort = parseInt(process.env.PORT, 10);
  const PORT = Number.isFinite(parsedPort) ? parsedPort : 3000;
  const server = app.listen(PORT, () => {
    const actualPort = server.address() && server.address().port ? server.address().port : PORT;
    console.log(`[web] Umbrel Tunnel UI en :${actualPort}`);
  });
  server.keepAliveTimeout = 0;
  runningServers += 1;
  server.on('close', () => {
    runningServers = Math.max(0, runningServers - 1);
    if (runningServers === 0) {
      stopBackgroundTimers();
    }
  });
  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = {
  app,
  startServer,
  stopBackgroundTimers,
  _internals: {
    keyFingerprint,
    isBlockedServiceTarget,
    isDisallowedTargetIp,
    probeServiceTarget,
    generateVpsScript,
    generateWgConf,
    generateCaddyfile,
    checkServicesHealth,
    loadConfig,
    saveConfig
  }
};
