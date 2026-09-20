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
const { seal, open, isSealed, canOpenWith } = require('./lib/cryptobox');
const audit = require('./lib/audit');

const {
  DATA_DIR,
  WG_API_HOST,
  WG_API_PORT,
  WG_API_TOKEN,
  MAX_SERVICES,
  CONFIG_FILE,
  WG_CONF,
  LEGACY_WG_CONF,
  CADDYFILE,
  APP_SEED_FILE,
  HEALTH_FILE,
  KNOWN_HOSTS_FILE,
  ENCRYPTED_FIELDS,
  DEFAULT_CONFIG,
  DEFAULT_CADDYFILE
} = require('./config/constants');

const app = express();

// In-memory mutable state (config lock + derived admin token).
let configLock = Promise.resolve();
let ADMIN_TOKEN = '';

// ── proxy peer gate ──────────────────────────────────────────────────────────
// Umbrel runs all app containers on a shared Docker network, so web:3016 is
// reachable from other apps' containers. The only legitimate clients are
// Umbrel's app gateway (which enforces the Umbrel session) and loopback
// (processes inside this container). Any other peer gets a 403 before touching
// routes or statics: it never sees the admin token.
//
// Dual umbrelOS 1.x / 2.x compat:
//  - 1.x: the gateway is the app_proxy container → we resolve APP_PROXY_HOST.
//  - 2.x: the app_proxy container no longer exists; umbreld runs the AppGateway
//    in-process on the HOST, so requests arrive from the host IP on the bridge
//    network, which is exactly this container's default gateway.
const APP_PROXY_HOST = process.env.APP_PROXY_HOST || 'miniweed-tunnel_app_proxy_1';
const PROXY_PEER_TTL_MS = 30_000;
const PROXY_PEER_MIN_RESOLVE_GAP_MS = 1_000;
// `ips` is the full admitted set; `gateways` is the subset that came from the
// routing table (host IP), kept apart so the gate can restrict it on 1.x.
let proxyPeers = { ips: new Set(), gateways: new Set(), resolvedAt: 0 };
// Sticky umbrelOS 1.x marker: set the first time APP_PROXY_HOST resolves after
// boot. Only 1.x has that container (2.x's legacy-compat drops it from the
// compose), so once seen this process is on 1.x for its whole lifetime — a
// later app_proxy restart or DNS hiccup must not silently switch the gate to
// 2.x mode, where the host IP is trusted for everything.
let appProxySeen = false;

function normalizePeerIp(addr) {
  const ip = String(addr || '').trim().toLowerCase();
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped ? mapped[1] : ip;
}

function isLoopbackPeer(ip) {
  return ip === '::1' || ip.startsWith('127.');
}

// Default gateway of the container's default interface, read from
// /proc/net/route (destination 00000000, gateway hex little-endian). On
// umbrelOS 2.x that IP is the host's address on umbrel_main_network: legitimate
// requests from the in-process AppGateway and umbreld's server-side widgets
// arrive from there. On 1.x it additionally admits the host IP, which is
// already a trusted domain (the gate exists to block the OTHER containers on
// the shared network).
function readDefaultGatewayIps() {
  const ips = new Set();
  try {
    const lines = fs.readFileSync('/proc/net/route', 'utf8').split('\n').slice(1);
    for (const line of lines) {
      const fields = line.trim().split(/\s+/);
      if (fields.length < 3) continue;
      const destination = fields[1];
      const gatewayHex = fields[2];
      if (destination !== '00000000' || gatewayHex === '00000000') continue;
      const m = gatewayHex.match(/^([0-9A-Fa-f]{8})$/);
      if (!m) continue;
      const raw = Buffer.from(m[1], 'hex');
      ips.add(`${raw[3]}.${raw[2]}.${raw[1]}.${raw[0]}`);
    }
  } catch {
    // No /proc/net/route (tests, non-Linux environments): return the empty set.
  }
  return ips;
}

async function resolveProxyPeers(force = false) {
  const now = Date.now();
  const fresh = now - proxyPeers.resolvedAt < PROXY_PEER_TTL_MS;
  const tooSoon = now - proxyPeers.resolvedAt < PROXY_PEER_MIN_RESOLVE_GAP_MS;
  if ((fresh && !force) || (force && tooSoon)) return proxyPeers.ips;

  // The set is rebuilt from scratch on every resolution: IPs from previous
  // resolutions are never inherited. An IP the app_proxy once held expires with
  // the TTL (30s) — essential because Docker recycles pool IPs to other apps'
  // containers.
  const next = new Set();
  // Host IP on the bridge network: umbreld's in-process AppGateway on 2.x, and
  // umbreld's server-side widget fetch on both 1.x and 2.x.
  const gateways = readDefaultGatewayIps();
  for (const gw of gateways) next.add(gw);
  // umbrelOS 1.x: the app_proxy container. On 2.x the name does not exist and
  // the lookup fails: the set keeps only the gateways (enough on 2.x; on 1.x
  // the gate restricts them to the widget, see proxyPeerGate).
  try {
    const addrs = await dns.promises.lookup(APP_PROXY_HOST, { all: true });
    for (const a of addrs) next.add(normalizePeerIp(a.address));
    if (addrs.length) appProxySeen = true;
  } catch {
    // Fail-closed: without resolution no new peer is admitted via DNS.
  }
  proxyPeers = { ips: next, gateways, resolvedAt: now };
  return proxyPeers.ips;
}

// The only request umbreld itself makes straight to the container (widgets are
// fetched server-side from the host). It is unauthenticated and secret-free.
function isWidgetRequest(req) {
  return (req.method === 'GET' || req.method === 'HEAD') && req.path === '/api/widget';
}

async function proxyPeerGate(req, res, next) {
  const peer = normalizePeerIp(req.socket?.remoteAddress);
  if (isLoopbackPeer(peer)) return next();
  let allowed = await resolveProxyPeers();
  if (!allowed.has(peer)) {
    // The app_proxy may have restarted with a different IP: re-resolve before denying.
    allowed = await resolveProxyPeers(true);
  }
  if (!allowed.has(peer)) return res.status(403).json({ error: 'Forbidden' });
  // On 1.x the UI always arrives via app_proxy, so the host IP is legitimate
  // ONLY for umbreld's widget fetch. Anything else from that IP is another
  // container on the host network (network_mode: host apps share the host's
  // bridge address), which must not receive the admin cookie — same boundary
  // as 1.6.50. On 2.x (app_proxy never seen) the in-process AppGateway is the
  // host IP and has to be trusted for everything.
  if (appProxySeen && proxyPeers.gateways.has(peer) && !isWidgetRequest(req)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  return next();
}

app.use((req, res, next) => { proxyPeerGate(req, res, next).catch(next); });

app.use(express.json({ limit: '32kb' }));
app.disable('x-powered-by');

const CSP_HEADER = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  const isHttps = req.secure || req.get('x-forwarded-proto') === 'https';
  if (isHttps) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  res.setHeader('Content-Security-Policy', CSP_HEADER);
  next();
});

// Counting always uses the real TCP peer (authClientIp), not spoofable via
// X-Forwarded-For: without this a client could reset its bucket (or poison the
// audit log) simply by changing the header on each request.
const rateBuckets = {
  default: { max: 120, windowMs: 60_000 },
  '/api/keygen': { max: 5, windowMs: 3_600_000 },
  '/api/vps-setup-script': { max: 10, windowMs: 600_000 },
  '/api/config': { max: 30, windowMs: 60_000 }
};
const apiRateStore = new Map();
let rateGc = null;
let healthTimer = null;
let runningServers = 0;

function withConfigLock(fn) {
  const run = configLock.then(() => fn());
  configLock = run.catch(() => {});
  return run;
}

// Real TCP peer IP (not spoofable via X-Forwarded-For) for rate limiting and
// audit trails. `trust proxy` is deliberately not used: the only trusted hop
// is the app gateway and its identity is already guaranteed by the peer gate.
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
  const ip = authClientIp(req);
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
      ip: authClientIp(req),
      ua: (req.get('user-agent') || '').slice(0, 120)
    });
  });
  next();
});

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.get(['/', '/index.html', '/app', '/app/*'], (req, res, next) => {
  const spaIndex = path.join(__dirname, 'public', 'app', 'index.html');
  if (!fs.existsSync(spaIndex)) return next();
  if (ADMIN_TOKEN) res.setHeader('Set-Cookie', `_t=${ADMIN_TOKEN}; HttpOnly; SameSite=Strict; Path=/`);
  return res.sendFile(spaIndex);
});

// ── auth ─────────────────────────────────────────────────────────────────────

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const pair of String(header).split(';')) {
    const idx = pair.indexOf('=');
    if (idx < 1) continue;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function requireAuth(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(503).json({ error: 'Server not ready' });
  const expected = Buffer.from(ADMIN_TOKEN);
  const check = (raw) => {
    if (!raw || raw.length !== ADMIN_TOKEN.length) return false;
    try { return crypto.timingSafeEqual(Buffer.from(raw), expected); } catch { return false; }
  };
  if (check(req.headers['x-tunnel-api-token'])) return next();
  if (check(parseCookies(req.headers.cookie || '')._t)) return next();
  return res.status(401).json({ error: 'Not authenticated' });
}

// ── helpers ──────────────────────────────────────────────────────────────────

function ensureDataDir() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.mkdirSync(path.dirname(WG_CONF), { recursive: true });
  } catch (err) {
    console.error(`[warn] could not prepare data dir ${DATA_DIR}: ${err.message}`);
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
    // The backup contains the plaintext private key: keeping it would defeat
    // at-rest encryption. It is only deleted after the encrypted v1 is written
    // successfully; if saveConfig throws, the .bak stays as a safety net and
    // the original remains intact (saveConfig writes tmp + atomic rename).
    fs.unlinkSync(backup);
    console.log('[migration] config.json encrypted v0 -> v1 (plaintext backup removed)');
  } catch (err) {
    console.error('[migration] failed to migrate config:', err.message);
  }
}

// Until 1.6.48 wg0.conf lived at the DATA_DIR root; it now lives in DATA_DIR/wg
// because the wg container only mounts that subdir. Moves the existing conf so
// an update doesn't leave the tunnel waiting for a config that was already written.
function migrateWgConfIfNeeded() {
  try {
    if (!fs.existsSync(LEGACY_WG_CONF)) return;
    if (!fs.existsSync(WG_CONF)) {
      // Copy instead of rename: the new file gets this process's owner, so the
      // wg container (no DAC_OVERRIDE) can read it even if the legacy file had
      // a different owner.
      writePrivateFile(WG_CONF, fs.readFileSync(LEGACY_WG_CONF));
      console.log('[migration] wg0.conf moved to wg/ subdir');
    } else {
      console.log('[migration] stale legacy wg0.conf removed');
    }
    fs.unlinkSync(LEGACY_WG_CONF);
  } catch (err) {
    console.error('[migration] failed to migrate wg0.conf:', err.message);
  }
}

function readStoredAppSeed() {
  try {
    if (!fs.existsSync(APP_SEED_FILE)) return '';
    return String(fs.readFileSync(APP_SEED_FILE, 'utf8') || '').trim();
  } catch {
    return '';
  }
}

function persistAppSeed(seed) {
  try {
    fs.writeFileSync(APP_SEED_FILE, `${seed}\n`, { mode: 0o600 });
  } catch (err) {
    console.error(`[warn] could not persist app seed: ${err.message}`);
  }
}

// Any sealed blob from the stored config, used as a probe to tell which seed the
// config was encrypted with. Returns null when there is no config yet or nothing
// in it is sealed (nothing to lose, so either seed is fine).
function findSealedProbe() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    for (const f of ENCRYPTED_FIELDS) {
      if (isSealed(raw[f])) return raw[f];
    }
    if (Array.isArray(raw.services)) {
      for (const svc of raw.services) {
        if (svc && isSealed(svc.target)) return svc.target;
      }
    }
  } catch {
    // No config, unreadable, or not JSON: no probe available.
  }
  return null;
}

function loadOrCreateAppSeed() {
  const envSeed = (process.env.APP_SEED || process.env.TUNNEL_API_TOKEN || '').trim();
  const stored = readStoredAppSeed();

  if (envSeed.length >= 32) {
    // Persist the effective seed as a backup so the config survives an umbrelOS
    // version that stops exporting APP_SEED altogether (the fallback below then
    // reads it back from disk).
    if (stored === envSeed) return envSeed;
    if (stored.length < 32) {
      persistAppSeed(envSeed);
      return envSeed;
    }

    // env and backup disagree: umbrelOS may have changed the APP_SEED
    // derivation. Overwriting the backup here would destroy the only copy of
    // the seed config.json was encrypted with, so check which one actually
    // opens it before touching the file.
    const probe = findSealedProbe();
    if (probe && !canOpenWith(envSeed, probe) && canOpenWith(stored, probe)) {
      console.error('[warn] APP_SEED changed and does not decrypt config.json; ' +
        'falling back to the persisted seed backup');
      return stored;
    }
    persistAppSeed(envSeed);
    return envSeed;
  }

  if (stored.length >= 32) return stored;

  const generated = crypto.randomBytes(48).toString('base64url');
  persistAppSeed(generated);
  return generated;
}

// After a backup restore the Caddyfile may be missing (caddy/data is in
// backupIgnore) or still hold the placeholder while config.json was restored.
// Regenerate it from the config so Caddy never starts stuck on the placeholder.
function regenerateCaddyfileFromConfig() {
  try {
    const cfg = loadConfig();
    if (cfg && cfg.domain) {
      fs.writeFileSync(CADDYFILE, generateCaddyfile(cfg));
      console.log('[startup] Caddyfile (re)generated from saved config');
    } else if (!fs.existsSync(CADDYFILE)) {
      fs.writeFileSync(CADDYFILE, DEFAULT_CADDYFILE);
    }
  } catch (err) {
    console.error(`[warn] could not regenerate Caddyfile from config: ${err.message}`);
  }
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

// mode only applies when creating the file; chmod covers pre-existing files.
function writePrivateFile(file, data) {
  fs.writeFileSync(file, data, { mode: 0o600 });
  try { fs.chmodSync(file, 0o600); } catch {}
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


// Wraps async handlers so a rejection goes to next(err) instead of hanging
// the request (Express 4 doesn't catch async function rejections by itself).
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
    // Doesn't block RFC1918: exposing internal services is the app's purpose.
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
          // Pins the already-validated IP: prevents a second lookup (rebinding) from pointing elsewhere.
          lookup: (_host, _opts, cb) => cb(null, pinned.address, pinned.family),
          servername: hostname,
          // Internal services often use self-signed certs; the probe only measures reachability.
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
  // Same semantics as the input zod schema: strict IPv4 only.
  if (cfg.vpsIp && !isValidIpv4(cfg.vpsIp)) {
    errors.push('The VPS IP is invalid');
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
    writePrivateFile(HEALTH_FILE, JSON.stringify({
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

// ── widget (umbrelOS 2.x home screen) ────────────────────────────────────────
// Unauthenticated, secret-free endpoint: umbreld fetches it server-side
// straight to the container (http://web:3016/api/widget) and the peer gate
// already protects it from other apps. It runs without auth (but shares the
// default /api rate-limit bucket, with the gateway IP as its only client: UI
// and widget consume the same bucket, with no practical impact) so umbreld
// doesn't need cookies. Returns the umbrelOS `three-stats` shape.
//
// `refresh` is mandatory in the BODY, not just in the manifest: umbreld runs
// `ms(widgetData.refresh)` on the response (1.x and 2.x alike) and `ms(undefined)`
// throws, which makes the home-screen widget render as dashes.
const WIDGET_REFRESH = '30s';
app.get('/api/widget', asyncHandler(async (req, res) => {
  const cfg = loadConfig();
  const services = Array.isArray(cfg.services) ? cfg.services : [];
  const enabled = services.filter(s => s.enabled && s.target);
  const health = cfg.serviceHealth || {};
  const healthy = enabled.filter(s => health[serviceKey(s)] && health[serviceKey(s)].ok).length;

  let wg = { connected: false, lastHandshakeAgeSec: null };
  try { wg = await wgApi('/status'); } catch { /* wg down: widget degrades */ }

  let tunnelText = 'Not connected';
  let tunnelSub = 'no handshake';
  if (wg && wg.connected) {
    tunnelText = 'Connected';
    const age = wg.lastHandshakeAgeSec;
    tunnelSub = (typeof age === 'number' && age >= 0) ? `handshake ${age}s ago` : 'wireguard up';
  }

  res.json({
    type: 'three-stats',
    refresh: WIDGET_REFRESH,
    link: '',
    items: [
      { icon: 'route', text: tunnelText, subtext: tunnelSub },
      { icon: 'server-2', text: `${healthy}/${enabled.length}`, subtext: 'services healthy' },
      { icon: 'world', text: cfg.domain || '—', subtext: cfg.domain ? 'public domain' : 'no domain' }
    ]
  });
}));

// ── routes ───────────────────────────────────────────────────────────────────

app.get('/api/config', requireAuth, (req, res) => {
  const cfg = loadConfig();
  // Never expose the private key or the preshared key to the frontend: both
  // are tunnel secrets, and the UI never needs their values (the VPS script is
  // the only consumer, generated server-side).
  res.json({
    ...cfg,
    vpsIp: cfg.vpsIp || '',
    vpsPort: cfg.vpsPort || 51820,
    vpsPubKey: cfg.vpsPubKey || '',
    privateKey: cfg.privateKey ? '••••' : '',
    presharedKey: cfg.presharedKey ? '••••' : '',
    vpsPubKeyFingerprint: keyFingerprint(cfg.vpsPubKey || '')
  });
});

app.post('/api/config', requireAuth, async (req, res) => {
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
      if (update.presharedKey === '••••') update.presharedKey = existing.presharedKey;

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
        ip: authClientIp(req)
      });

      const wgConf = generateWgConf(cfg, getActiveVpsTarget(cfg));
      if (wgConf) writePrivateFile(WG_CONF, wgConf);
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

app.get('/api/keygen', requireAuth, asyncHandler(async (req, res) => {
  let keys;
  try {
    keys = await wgApi('/keygen');
  } catch (err) {
    return res.status(503).json({ error: 'WireGuard unavailable: ' + err.message });
  }
  // Save private key immediately, return only public key. Under the lock so it
  // doesn't clobber (or get clobbered by) a concurrent POST /api/config.
  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.privateKey = keys.privateKey;
    cfg.publicKey = keys.publicKey;
    cfg.presharedKey = keys.presharedKey || '';
    saveConfig(cfg);
  });
  audit.log({ action: 'keygen', ip: authClientIp(req), publicKeyFingerprint: keyFingerprint(keys.publicKey) });
  res.json({ publicKey: keys.publicKey, publicKeyFingerprint: keyFingerprint(keys.publicKey) });
}));

app.get('/api/status', requireAuth, async (req, res) => {
  try {
    res.json(await wgApi('/status'));
  } catch {
    res.json({ connected: false, raw: 'WireGuard unavailable' });
  }
});

app.get('/api/health', requireAuth, (req, res) => {
  if (!fs.existsSync(HEALTH_FILE)) return res.json({});
  try {
    return res.json(JSON.parse(fs.readFileSync(HEALTH_FILE, 'utf8')));
  } catch {
    return res.json({});
  }
});

app.post('/api/health/refresh', requireAuth, async (req, res) => {
  await refreshHealthSnapshot();
  if (!fs.existsSync(HEALTH_FILE)) return res.json({ ok: false, health: {} });
  try {
    const health = JSON.parse(fs.readFileSync(HEALTH_FILE, 'utf8'));
    return res.json({ ok: true, health });
  } catch {
    return res.json({ ok: false, health: {} });
  }
});


app.get('/api/vps-setup-script', requireAuth, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  const cfg = loadConfig();
  const selected = getActiveVpsTarget(cfg);
  if (!cfg.publicKey || !selected?.ip) {
    return res.status(400).json({ error: 'Configure the VPS IP and generate keys first' });
  }
  const script = generateVpsScript(cfg, selected);
  const sha256 = crypto.createHash('sha256').update(script).digest('hex');
  if (req.query.format === 'plain') {
    audit.log({ action: 'script.download', format: 'plain', ip: authClientIp(req), vpsId: selected.id });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="miniweed-tunnel-vps-setup.sh"');
    return res.send(script);
  }
  audit.log({ action: 'script.download', format: 'json', ip: authClientIp(req), vpsId: selected.id });
  return res.json({
    script,
    sha256,
    filename: 'miniweed-tunnel-vps-setup.sh',
    vps: { id: selected.id, name: selected.name, ip: selected.ip, port: selected.port }
  });
});

app.get('/api/audit', requireAuth, (req, res) => {
  const limitRaw = parseInt(req.query.limit, 10);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 1000) : 100;
  const entries = audit.readLatest(limit);
  res.json({ entries, total: entries.length });
});

app.get('/api/audit/verify', requireAuth, (req, res) => {
  res.json(audit.verifyChain());
});

// ── error handling ───────────────────────────────────────────────────────────

// Safety net: any synchronous throw or rejection forwarded via next(err)
// (handlers wrapped in asyncHandler) answers 500 instead of hanging the request.
// err.message is not exposed to the client to avoid leaking sensitive context.
// Exception: body-parser errors (malformed JSON, body > 32kb) carry err.status
// 4xx — they are client errors, answered as such, and not logged as
// request.error in the audit log.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const clientStatus = Number(err && (err.status || err.statusCode));
  if (clientStatus >= 400 && clientStatus < 500) {
    return res.status(clientStatus).json({
      error: clientStatus === 413 ? 'Payload too large' : 'Bad request'
    });
  }
  console.error(`[error] ${req.method} ${req.path}: ${err && err.message ? err.message : err}`);
  try {
    audit.log({ action: 'request.error', ip: authClientIp(req), path: req.path });
  } catch {}
  return res.status(500).json({ error: 'Internal error' });
});

// ── boot ─────────────────────────────────────────────────────────────────────

function startServer() {
  ensureDataDir();
  ensureBackgroundTimers();
  process.env.APP_SEED = loadOrCreateAppSeed();
  ADMIN_TOKEN = Buffer.from(crypto.hkdfSync(
    'sha256',
    Buffer.from(process.env.APP_SEED, 'utf8'),
    Buffer.from('miniweed-tunnel/v1', 'utf8'),
    Buffer.from('tunnel-api-token-v1', 'utf8'),
    32
  )).toString('base64url');
  migrateConfigIfNeeded();
  migrateWgConfIfNeeded();
  // The Caddyfile is an artifact derived from config.json by design: it is
  // regenerated on EVERY startup (not just after restores). That way a backup
  // restore without caddy/data (backupIgnore) never leaves Caddy stuck on the
  // placeholder, and any manual Caddyfile edit is deliberately discarded —
  // the source of truth is config.json.
  regenerateCaddyfileFromConfig();
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
    console.log(`[web] Umbrel Tunnel UI on :${actualPort}`);
  });
  // keepAliveTimeout > a proxy's typical idle (60s) allows reuse from the app
  // gateway; a finite value (previously 0 = no timeout) avoids piling up idle
  // sockets until descriptors run out. headersTimeout must be strictly greater.
  server.keepAliveTimeout = 75_000;
  server.headersTimeout = 76_000;
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
    proxyPeerGate,
    normalizePeerIp,
    isLoopbackPeer,
    readDefaultGatewayIps,
    resolveProxyPeers,
    __setProxyPeersForTest(ips, resolvedAt = Date.now(), gateways = []) {
      proxyPeers = { ips: new Set([...ips, ...gateways]), gateways: new Set(gateways), resolvedAt };
    },
    __getProxyPeersForTest() {
      return proxyPeers;
    },
    __setAppProxySeenForTest(value) {
      appProxySeen = Boolean(value);
    },
    __getAppProxySeenForTest() {
      return appProxySeen;
    },
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
