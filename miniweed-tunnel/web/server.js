const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const zlib = require('zlib');
const crypto = require('crypto');
const dns = require('dns');
const {
  ConfigSchema,
  RotatePrepareSchema,
  RotateConfirmSchema,
  AuthPasswordSchema,
  AuthLoginSchema
} = require('./api-spec/schemas');
const openApiDoc = require('./api-spec/openapi-runtime');
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
  generateVpsScript,
  buildKillSwitchScript,
  buildVpsRotateScript
} = require('./lib/generators');
const { seal, open, isSealed } = require('./lib/cryptobox');
const audit = require('./lib/audit');

const {
  DATA_DIR,
  WG_API_HOST,
  WG_API_PORT,
  WG_API_TOKEN,
  DISABLE_API_AUTH,
  MAX_SERVICES,
  MAX_VPS_TARGETS,
  FAILOVER_POLICY_DEFAULTS,
  CONFIG_FILE,
  WG_CONF,
  CADDYFILE,
  TOKEN_FILE,
  APP_SEED_FILE,
  HEALTH_FILE,
  KNOWN_HOSTS_FILE,
  ENCRYPTED_FIELDS,
  SESSION_COOKIE,
  SESSION_TTL_MS,
  CHALLENGE_TTL_MS,
  ROTATION_PLAN_TTL_MS,
  DEFAULT_CONFIG,
  DEFAULT_CADDYFILE
} = require('./config/constants');

const app = express();

// Estado mutable en memoria (no constantes): tokens runtime, lock de config,
// y los Maps de control de sesiones/challenges/rotación/failover.
let API_AUTH_TOKEN = '';
let configLock = Promise.resolve();
const loginFailures = new Map();
const authChallenges = new Map();
const rotationPlans = new Map();
const failoverState = new Map();
let failoverLastSwitchAt = 0;

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
  '/api/config': { max: 30, windowMs: 60_000 },
  '/api/auth/login': { max: 10, windowMs: 60_000, realIp: true },
  '/api/auth/password': { max: 5, windowMs: 300_000, realIp: true },
  '/api/auth/verify': { max: 20, windowMs: 60_000, realIp: true },
  '/api/rotate/prepare': { max: 3, windowMs: 300_000, realIp: true },
  '/api/rotate/confirm': { max: 5, windowMs: 300_000, realIp: true }
};
const apiRateStore = new Map();
let rateGc = null;
let challengeGc = null;
let rotationGc = null;
let healthTimer = null;
let runningServers = 0;

app.set('trust proxy', 1);

function parseCookies(req) {
  const cookie = req.headers.cookie || '';
  const out = {};
  for (const part of cookie.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(value);
    } catch {
      out[key] = value;
    }
  }
  return out;
}

function withConfigLock(fn) {
  const run = configLock.then(() => fn());
  configLock = run.catch(() => {});
  return run;
}

function hashPassword(password) {
  const N = 1 << 15;
  const r = 8;
  const p = 1;
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32, { N, r, p, maxmem: 128 * 1024 * 1024 });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

function verifyPassword(password, encoded) {
  if (!encoded || typeof encoded !== 'string') return false;
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = parseInt(parts[1], 10);
  const r = parseInt(parts[2], 10);
  const p = parseInt(parts[3], 10);
  const salt = Buffer.from(parts[4], 'base64');
  const expected = Buffer.from(parts[5], 'base64');
  const actual = crypto.scryptSync(password, salt, expected.length, { N, r, p, maxmem: 128 * 1024 * 1024 });
  return crypto.timingSafeEqual(actual, expected);
}

function authFailureDelayMs(ip) {
  const now = Date.now();
  const entry = loginFailures.get(ip) || { fails: 0, blockUntil: 0 };
  if (entry.blockUntil > now) return entry.blockUntil - now;
  const nextFails = entry.fails + 1;
  const delay = Math.min(16_000, 1000 * (2 ** (nextFails - 1)));
  const blockUntil = nextFails >= 6 ? now + 60 * 60 * 1000 : 0;
  loginFailures.set(ip, { fails: nextFails, blockUntil });
  return delay;
}

function clearAuthFailures(ip) {
  loginFailures.delete(ip);
}

function parseEd25519PublicKey(input) {
  const value = String(input || '').trim();
  if (!value) return null;

  // 1) Raw DER SPKI in base64
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(value, 'base64'),
      format: 'der',
      type: 'spki'
    });
    if (keyObject.asymmetricKeyType === 'ed25519') {
      return keyObject.export({ format: 'der', type: 'spki' }).toString('base64');
    }
  } catch {
    // Try next format.
  }

  // 2) OpenSSH format: ssh-ed25519 AAAA... [comment]
  if (value.startsWith('ssh-ed25519 ')) {
    const parts = value.split(/\s+/).filter(Boolean);
    if (parts.length >= 2) {
      try {
        const blob = Buffer.from(parts[1], 'base64');
        let idx = 0;
        const readStr = () => {
          if (idx + 4 > blob.length) throw new Error('short blob');
          const len = blob.readUInt32BE(idx);
          idx += 4;
          if (idx + len > blob.length) throw new Error('short blob');
          const out = blob.slice(idx, idx + len);
          idx += len;
          return out;
        };
        const type = readStr().toString('utf8');
        const rawKey = readStr();
        if (type !== 'ssh-ed25519' || rawKey.length !== 32) return null;
        const jwk = {
          kty: 'OKP',
          crv: 'Ed25519',
          x: rawKey.toString('base64url')
        };
        const keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' });
        return keyObject.export({ format: 'der', type: 'spki' }).toString('base64');
      } catch {
        return null;
      }
    }
  }

  return null;
}

function cleanupAuthChallenges() {
  const now = Date.now();
  for (const [id, challenge] of authChallenges.entries()) {
    if (!challenge || challenge.expiresAt <= now) authChallenges.delete(id);
  }
}

function cleanupRotationPlans() {
  const now = Date.now();
  for (const [id, plan] of rotationPlans.entries()) {
    if (!plan || plan.expiresAt <= now) rotationPlans.delete(id);
  }
}

function createSession(ip, source = 'web') {
  const now = Date.now();
  return {
    id: crypto.randomBytes(24).toString('base64url'),
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
    ip,
    source
  };
}

// Comparación de strings en tiempo constante (longitud fija) para evitar side-channels.
function timingSafeStrEq(a, b) {
  const bufA = Buffer.from(String(a || '').padEnd(128).slice(0, 128));
  const bufB = Buffer.from(String(b || '').padEnd(128).slice(0, 128));
  return crypto.timingSafeEqual(bufA, bufB);
}

// IP para throttling anti-fuerza-bruta: usa el peer TCP real (no falsificable),
// no req.ip, que deriva de X-Forwarded-For y un cliente puede manipular.
function authClientIp(req) {
  return req.socket?.remoteAddress || req.ip || 'unknown';
}

// ¿La request está autenticada por token de API (header) o por sesión válida?
// Centraliza la lógica usada por requireApiAuth y por cambios de contraseña.
function isAuthenticatedRequest(req, cfg) {
  const headerToken = req.get('x-tunnel-api-token') || '';
  // Un token vacío configurado nunca debe autenticar (evita bypass si API_AUTH_TOKEN no se generó).
  const headerOk = Boolean(API_AUTH_TOKEN) && timingSafeStrEq(headerToken, API_AUTH_TOKEN);
  const cookies = parseCookies(req);
  const sessionToken = cookies[SESSION_COOKIE] || '';
  const now = Date.now();
  const sessions = Array.isArray(cfg?.auth?.sessions) ? cfg.auth.sessions : [];
  const sessionOk = Boolean(
    sessionToken && sessions.some(s => s.expiresAt > now && timingSafeStrEq(s.id, sessionToken))
  );
  return headerOk || sessionOk;
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
  if (!challengeGc) {
    challengeGc = setInterval(cleanupAuthChallenges, 60 * 1000);
    if (typeof challengeGc.unref === 'function') challengeGc.unref();
  }
  if (!rotationGc) {
    rotationGc = setInterval(cleanupRotationPlans, 60 * 1000);
    if (typeof rotationGc.unref === 'function') rotationGc.unref();
  }
}

function stopBackgroundTimers() {
  if (rateGc) {
    clearInterval(rateGc);
    rateGc = null;
  }
  if (challengeGc) {
    clearInterval(challengeGc);
    challengeGc = null;
  }
  if (rotationGc) {
    clearInterval(rotationGc);
    rotationGc = null;
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

function requireApiAuth(req, res, next) {
  if (DISABLE_API_AUTH) return next();
  const publicPaths = [
    '/auth/login', '/api/auth/login',
    '/auth/challenge', '/api/auth/challenge',
    '/auth/verify', '/api/auth/verify',
    // /auth/password se deja pasar aquí pero el handler exige auth para CAMBIOS
    // (solo el primer set, en bootstrap, es libre). Ver app.post('/api/auth/password').
    '/auth/password', '/api/auth/password',
    '/auth/status', '/api/auth/status'
  ];
  if (publicPaths.includes(req.path)) return next();
  const cfg = loadConfig();

  if (!isAuthenticatedRequest(req, cfg)) {
    audit.log({ action: 'auth.fail', ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'Unauthorized' });
  }
  return next();
}

app.use('/api', apiRateLimit, requireApiAuth);
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

  const auth = out.auth && typeof out.auth === 'object' ? { ...out.auth } : {};
  if (auth.passwordHash && !isSealed(auth.passwordHash)) {
    auth.passwordHash = seal(auth.passwordHash);
  }
  if (Array.isArray(auth.sessions) && !isSealed(auth.sessions)) {
    auth.sessions = seal(JSON.stringify(auth.sessions));
  }
  out.auth = auth;

  out.failoverPolicy = normalizeFailoverPolicy(out.failoverPolicy);
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

  const auth = out.auth && typeof out.auth === 'object' ? { ...out.auth } : {};
  if (isSealed(auth.passwordHash)) {
    auth.passwordHash = open(auth.passwordHash) || '';
  }
  if (isSealed(auth.sessions)) {
    try {
      const dec = open(auth.sessions);
      const parsed = dec ? JSON.parse(dec) : [];
      auth.sessions = Array.isArray(parsed) ? parsed : [];
    } catch {
      auth.sessions = [];
    }
  }
  out.auth = auth;

  return out;
}

function normalizeFailoverPolicy(input) {
  const policy = input && typeof input === 'object' ? input : {};
  const activeRaw = parseInt(policy.activeFailuresRequired, 10);
  const candidateRaw = parseInt(policy.candidateSuccessesRequired, 10);
  const cooldownRaw = parseInt(policy.cooldownMs, 10);
  return {
    activeFailuresRequired: Number.isFinite(activeRaw) && activeRaw >= 1 && activeRaw <= 10
      ? activeRaw
      : FAILOVER_POLICY_DEFAULTS.activeFailuresRequired,
    candidateSuccessesRequired: Number.isFinite(candidateRaw) && candidateRaw >= 1 && candidateRaw <= 10
      ? candidateRaw
      : FAILOVER_POLICY_DEFAULTS.candidateSuccessesRequired,
    cooldownMs: Number.isFinite(cooldownRaw) && cooldownRaw >= 0 && cooldownRaw <= 3_600_000
      ? cooldownRaw
      : FAILOVER_POLICY_DEFAULTS.cooldownMs
  };
}

function extractFailoverPolicy(cfg) {
  return normalizeFailoverPolicy(cfg?.failoverPolicy);
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

function loadOrCreateApiToken() {
  const seed = (process.env.APP_SEED || process.env.TUNNEL_API_TOKEN || '').trim();
  if (seed.length >= 32) {
    const tok = crypto.hkdfSync(
      'sha256',
      Buffer.from(seed, 'utf8'),
      Buffer.from('miniweed-tunnel/v1', 'utf8'),
      Buffer.from('tunnel-api-token-v1', 'utf8'),
      32
    );
    return Buffer.from(tok).toString('base64url');
  }

  if (fs.existsSync(TOKEN_FILE)) {
    try {
      const blob = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
      const token = open(blob);
      if (token && token.length >= 32) return token;
    } catch {
      // Continue with failure path.
    }
  }

  const fallback = crypto.randomBytes(32).toString('base64url');
  try {
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(seal(fallback)), { mode: 0o600 });
  } catch (err) {
    console.error(`[warn] could not persist API token: ${err.message}`);
  }
  return fallback;
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
    const cfg = { ...DEFAULT_CONFIG, ...dec };
    cfg.auth = {
      ...DEFAULT_CONFIG.auth,
      ...(cfg.auth || {}),
      sessions: Array.isArray(cfg.auth?.sessions) ? cfg.auth.sessions : []
    };
    cfg.failoverPolicy = normalizeFailoverPolicy(cfg.failoverPolicy);
    ensureVpsTargets(cfg);
    return cfg;
  } catch {
    const cfg = { ...DEFAULT_CONFIG };
    cfg.failoverPolicy = normalizeFailoverPolicy(cfg.failoverPolicy);
    ensureVpsTargets(cfg);
    return cfg;
  }
}

function saveConfig(cfg) {
  fs.mkdirSync(path.dirname(CONFIG_FILE), { recursive: true });
  const tmp = CONFIG_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(encryptConfig(cfg), null, 2), { mode: 0o600 });
  fs.renameSync(tmp, CONFIG_FILE);
}

function normalizeVpsTarget(raw, index = 0) {
  const idRaw = String(raw?.id || '').trim();
  const id = idRaw || crypto.createHash('sha256').update(`${Date.now()}-${Math.random()}-${index}`).digest('hex').slice(0, 16);
  const name = String(raw?.name || '').trim() || `VPS ${index + 1}`;
  const ip = String(raw?.ip || '').trim();
  const portRaw = parseInt(raw?.port, 10);
  const port = Number.isFinite(portRaw) ? portRaw : 51820;
  const pubKey = String(raw?.pubKey || '').trim();
  const enabled = raw?.enabled !== false;
  const priorityRaw = parseInt(raw?.priority, 10);
  const priority = Number.isFinite(priorityRaw) ? priorityRaw : index;
  const lastHealth = raw?.lastHealth && typeof raw.lastHealth === 'object'
    ? {
        ok: Boolean(raw.lastHealth.ok),
        checkedAt: String(raw.lastHealth.checkedAt || ''),
        message: String(raw.lastHealth.message || ''),
        latencyMs: Number.isFinite(raw.lastHealth.latencyMs) ? raw.lastHealth.latencyMs : null
      }
    : null;
  return { id, name, ip, port, pubKey, enabled, priority, lastHealth };
}

function ensureVpsTargets(cfg) {
  const targets = [];
  if (Array.isArray(cfg.vpsTargets)) {
    for (const [i, raw] of cfg.vpsTargets.entries()) {
      const t = normalizeVpsTarget(raw, i);
      if (!t.ip && !t.pubKey) continue;
      targets.push(t);
    }
  }

  if (!targets.length && (cfg.vpsIp || cfg.vpsPubKey)) {
    targets.push(normalizeVpsTarget({
      id: 'primary',
      name: 'VPS principal',
      ip: cfg.vpsIp,
      port: cfg.vpsPort,
      pubKey: cfg.vpsPubKey,
      enabled: true,
      priority: 0
    }, 0));
  }

  cfg.vpsTargets = targets.slice(0, MAX_VPS_TARGETS);
  const preferred = String(cfg.activeVpsId || '').trim();
  const active = cfg.vpsTargets.find(t => t.id === preferred)
    || cfg.vpsTargets.find(t => t.enabled && t.ip)
    || cfg.vpsTargets[0]
    || null;
  cfg.activeVpsId = active ? active.id : '';

  if (active) {
    cfg.vpsIp = active.ip;
    cfg.vpsPort = active.port;
    cfg.vpsPubKey = active.pubKey;
  }
}

function getActiveVpsTarget(cfg) {
  ensureVpsTargets(cfg);
  return cfg.vpsTargets.find(t => t.id === cfg.activeVpsId) || null;
}

function recordVpsProbeResult(targetId, ok) {
  const current = failoverState.get(targetId) || { okStreak: 0, failStreak: 0 };
  const next = ok
    ? { okStreak: current.okStreak + 1, failStreak: 0 }
    : { okStreak: 0, failStreak: current.failStreak + 1 };
  failoverState.set(targetId, next);
  return next;
}

function getVpsProbeState(targetId) {
  return failoverState.get(targetId) || { okStreak: 0, failStreak: 0 };
}

async function validateEmailWithMx(value) {
  if (!value) return { ok: true, reason: 'empty' };
  const match = String(value).match(/^[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})$/);
  if (!match) return { ok: false, reason: 'syntax' };
  try {
    // Timeout para que un resolver lento (o un dominio elegido por el usuario)
    // no bloquee el guardado de config.
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('mx_timeout')), 4000).unref?.());
    const mx = await Promise.race([dns.promises.resolveMx(match[1]), timeout]);
    if (!Array.isArray(mx) || mx.length === 0) return { ok: false, reason: 'mx_empty' };
    return { ok: true, mxCount: mx.length };
  } catch (err) {
    return { ok: false, reason: 'mx_lookup_failed', code: err.code || err.message || 'unknown' };
  }
}


// Envuelve handlers async para que un rechazo vaya a next(err) en vez de colgar
// la request (Express 4 no captura rejections de funciones async por sí solo).
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function validateBody(schema) {
  return (req, res, next) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'validation', issues: parsed.error.issues });
    }
    req.body = parsed.data;
    return next();
  };
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

async function probeVpsTarget(target, timeoutMs = 1500) {
  if (!target || !target.ip) {
    return { ok: false, message: 'sin ip' };
  }
  const wgProbe = await probeTcpPort(target.ip, 22, timeoutMs);
  if (wgProbe.ok) {
    return { ok: true, message: `ssh reachable (${wgProbe.message})`, latencyMs: wgProbe.latencyMs };
  }
  const webProbe = await probeTcpPort(target.ip, 443, timeoutMs);
  if (webProbe.ok) {
    return { ok: true, message: `https reachable (${webProbe.message})`, latencyMs: webProbe.latencyMs };
  }
  return { ok: false, message: `${wgProbe.message}; ${webProbe.message}` };
}

async function computeVpsHealth(targets) {
  const out = {};
  await Promise.all((targets || []).map(async target => {
    if (!target?.id) return;
    if (!target.enabled) {
      out[target.id] = {
        ok: false,
        checked: false,
        checkedAt: new Date().toISOString(),
        message: 'Disabled'
      };
      return;
    }
    const probe = await probeVpsTarget(target);
    const streak = recordVpsProbeResult(target.id, Boolean(probe.ok));
    out[target.id] = {
      ok: Boolean(probe.ok),
      checked: true,
      checkedAt: new Date().toISOString(),
      message: probe.message || (probe.ok ? 'ok' : 'sin respuesta'),
      latencyMs: Number.isFinite(probe.latencyMs) ? probe.latencyMs : null,
      okStreak: streak.okStreak,
      failStreak: streak.failStreak
    };
  }));
  return out;
}

function pickBestFailoverTarget(cfg, vpsHealth, policy) {
  ensureVpsTargets(cfg);
  const candidates = (cfg.vpsTargets || []).filter(t => t.enabled && t.ip && t.pubKey);
  if (!candidates.length) return null;
  const activeId = cfg.activeVpsId;
  const activeHealth = activeId ? vpsHealth[activeId] : null;
  const activeState = activeId ? getVpsProbeState(activeId) : { failStreak: 0 };
  const activeDegraded = Boolean(activeHealth && !activeHealth.ok && activeState.failStreak >= policy.activeFailuresRequired);
  if (!activeDegraded) return null;

  if (Date.now() - failoverLastSwitchAt < policy.cooldownMs) return null;

  const healthy = candidates
    .filter(t => {
      const health = vpsHealth[t.id];
      const state = getVpsProbeState(t.id);
      return Boolean(health?.ok && state.okStreak >= policy.candidateSuccessesRequired);
    })
    .sort((a, b) => (a.priority - b.priority) || a.name.localeCompare(b.name));
  if (!healthy.length) return null;
  const next = healthy[0];
  if (next.id === activeId) return null;
  return next;
}

async function maybeFailover(cfg, reason = 'auto') {
  const policy = extractFailoverPolicy(cfg);
  const vpsHealth = await computeVpsHealth(cfg.vpsTargets || []);
  const next = pickBestFailoverTarget(cfg, vpsHealth, policy);
  let switched = false;

  if (next) {
    cfg.activeVpsId = next.id;
    ensureVpsTargets(cfg);
    saveConfig(cfg);
    const wgConf = generateWgConf(cfg, getActiveVpsTarget(cfg));
    if (wgConf) fs.writeFileSync(WG_CONF, wgConf);
    switched = true;
    failoverLastSwitchAt = Date.now();
    audit.log({
      action: 'vps.failover',
      reason,
      to: next.id,
      toIp: next.ip
    });
  }

  return {
    switched,
    next: next ? { id: next.id, name: next.name, ip: next.ip } : null,
    vpsHealth,
    policy
  };
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
  ensureVpsTargets(cfg);

  if ((cfg.services || []).length > MAX_SERVICES) {
    errors.push(`Too many services: max ${MAX_SERVICES}`);
  }

  if (cfg.privateKey && !isWireGuardKey(cfg.privateKey)) errors.push('The Umbrel private key is invalid');
  if (cfg.publicKey && !isWireGuardKey(cfg.publicKey)) errors.push('The Umbrel public key is invalid');

  if ((cfg.vpsTargets || []).length > MAX_VPS_TARGETS) {
    errors.push(`Too many VPS configured: max ${MAX_VPS_TARGETS}`);
  }

  for (const [index, target] of (cfg.vpsTargets || []).entries()) {
    const label = target.name || `VPS ${index + 1}`;
    if (target.port < 1 || target.port > 65535) {
      errors.push(`El puerto WireGuard de ${label} debe estar entre 1 y 65535`);
    }
    if (target.pubKey && !isWireGuardKey(target.pubKey)) {
      errors.push(`The public key of ${label} is invalid`);
    }
    if (target.ip && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(target.ip) && !isHostname(target.ip)) {
      errors.push(`The IP/host of ${label} is invalid`);
    }
  }

  if (!(cfg.vpsTargets || []).some(t => t.enabled && t.ip)) {
    errors.push('Configura al menos un VPS habilitado con IP/host');
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

function buildBackupPayload(passphrase, includeAudit = true) {
  const chunks = [];
  const pushEntry = (name, value) => {
    const body = Buffer.from(value, 'utf8');
    chunks.push(Buffer.from(`${name}:${body.length}\n`, 'utf8'));
    chunks.push(body);
  };

  if (fs.existsSync(CONFIG_FILE)) pushEntry('config.json', fs.readFileSync(CONFIG_FILE, 'utf8'));
  if (fs.existsSync(KNOWN_HOSTS_FILE)) pushEntry('known_hosts.json', fs.readFileSync(KNOWN_HOSTS_FILE, 'utf8'));
  if (includeAudit) {
    const auditPath = path.join(DATA_DIR, 'audit.log');
    if (fs.existsSync(auditPath)) pushEntry('audit.log', fs.readFileSync(auditPath, 'utf8'));
  }
  pushEntry('meta.json', JSON.stringify({ ts: new Date().toISOString(), version: 1 }));

  const compressed = zlib.gzipSync(Buffer.concat(chunks));
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, salt, 32, { N: 1 << 16, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from('MWBK', 'utf8'), salt, nonce, ciphertext, tag]);
}

function parseBackupEntries(buffer) {
  const out = {};
  let idx = 0;
  while (idx < buffer.length) {
    const nl = buffer.indexOf(10, idx);
    if (nl === -1) break;
    const header = buffer.slice(idx, nl).toString('utf8');
    idx = nl + 1;
    const sep = header.lastIndexOf(':');
    if (sep <= 0) break;
    const name = header.slice(0, sep);
    const len = parseInt(header.slice(sep + 1), 10);
    if (!Number.isFinite(len) || len < 0 || idx + len > buffer.length) break;
    out[name] = buffer.slice(idx, idx + len).toString('utf8');
    idx += len;
  }
  return out;
}

function restoreBackupPayload(payload, passphrase) {
  if (!Buffer.isBuffer(payload) || payload.length < 48) throw new Error('invalid backup payload');
  if (payload.slice(0, 4).toString('utf8') !== 'MWBK') throw new Error('invalid backup magic');
  const salt = payload.slice(4, 20);
  const nonce = payload.slice(20, 32);
  const tag = payload.slice(payload.length - 16);
  const ciphertext = payload.slice(32, payload.length - 16);
  const key = crypto.scryptSync(passphrase, salt, 32, { N: 1 << 16, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  const compressed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const data = zlib.gunzipSync(compressed);
  const entries = parseBackupEntries(data);
  if (!entries['meta.json']) throw new Error('backup sin meta.json');
  return entries;
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
  const active = getActiveVpsTarget(cfg);
  // Never expose private key to the frontend
  res.json({
    ...cfg,
    vpsIp: active?.ip || '',
    vpsPort: active?.port || 51820,
    vpsPubKey: active?.pubKey || '',
    vpsTargets: cfg.vpsTargets || [],
    activeVpsId: cfg.activeVpsId || '',
    privateKey: cfg.privateKey ? '••••' : '',
    vpsPubKeyFingerprint: keyFingerprint(active?.pubKey || ''),
    vpsFingerprints: Object.fromEntries((cfg.vpsTargets || []).map(t => [t.id, keyFingerprint(t.pubKey)]))
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
      const updateTargets = Array.isArray(update.vpsTargets)
        ? update.vpsTargets.map((raw, i) => normalizeVpsTarget(raw, i))
        : null;
      if (updateTargets) {
        cfg.vpsTargets = updateTargets.slice(0, MAX_VPS_TARGETS);
      } else if (update.vpsIp || update.vpsPubKey || update.vpsPort || existing.vpsTargets.length === 0) {
        const preserved = existing.vpsTargets.filter(t => t.id !== (existing.activeVpsId || ''));
        const legacyTarget = normalizeVpsTarget({
          id: existing.activeVpsId || 'primary',
          name: existing.vpsTargets.find(t => t.id === existing.activeVpsId)?.name || 'VPS principal',
          ip: update.vpsIp ?? existing.vpsIp,
          port: update.vpsPort ?? existing.vpsPort,
          pubKey: update.vpsPubKey ?? existing.vpsPubKey,
          enabled: true,
          priority: 0
        }, 0);
        cfg.vpsTargets = [legacyTarget, ...preserved].slice(0, MAX_VPS_TARGETS);
      }
      if (typeof update.activeVpsId === 'string') {
        cfg.activeVpsId = update.activeVpsId.trim();
      }
      ensureVpsTargets(cfg);
      cfg.services = Array.isArray(cfg.services)
        ? cfg.services.map(svc => ({
            name: (svc.name || '').trim(),
            subdomain: (svc.subdomain || '').trim().toLowerCase(),
            target: normalizeTargetUrl(svc.target),
            enabled: Boolean(svc.enabled)
          }))
        : [];

      const errors = validateConfig(cfg);
      const emailCheck = await validateEmailWithMx(cfg.acmeEmail);
      if (!emailCheck.ok) {
        errors.push(`The Let's Encrypt email failed MX validation (${emailCheck.reason})`);
      }
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


// ── auth endpoints ───────────────────────────────────────────────────────────

app.get('/api/auth/status', (req, res) => {
  const cfg = loadConfig();
  const hasPassword = Boolean(cfg.auth?.passwordHash);
  const cookies = parseCookies(req);
  const sessionToken = cookies[SESSION_COOKIE] || '';
  const now = Date.now();
  const sessions = Array.isArray(cfg.auth?.sessions) ? cfg.auth.sessions : [];
  const authenticated = Boolean(sessionToken && sessions.some(s => s.id === sessionToken && s.expiresAt > now));
  return res.json({ hasPassword, authenticated });
});

app.post('/api/auth/password', validateBody(AuthPasswordSchema), async (req, res) => {
  const password = String(req.body?.password || '');
  const currentPassword = String(req.body?.currentPassword || '');
  let denied = false;
  let changed = false;
  try {
    await withConfigLock(async () => {
      const cfg = loadConfig();
      cfg.auth = cfg.auth || {};
      const hasPassword = Boolean(cfg.auth.passwordHash);
      if (hasPassword) {
        // Cambio de contraseña: requiere sesión/token válido o la contraseña actual.
        const authed = isAuthenticatedRequest(req, cfg);
        const currentOk = Boolean(currentPassword) && verifyPassword(currentPassword, cfg.auth.passwordHash);
        if (!authed && !currentOk) {
          denied = true;
          return;
        }
      }
      // Primer set (bootstrap) o cambio autorizado.
      cfg.auth.passwordHash = hashPassword(password);
      cfg.auth.sessions = []; // invalida todas las sesiones existentes
      saveConfig(cfg);
      changed = true;
    });
  } catch (err) {
    audit.log({ action: 'auth.password.error', ip: req.ip });
    return res.status(500).json({ error: 'Error saving password' });
  }
  if (denied) {
    const delay = authFailureDelayMs(authClientIp(req));
    await new Promise(resolve => setTimeout(resolve, delay));
    audit.log({ action: 'auth.password.denied', ip: req.ip });
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (changed) audit.log({ action: 'auth.password.set', ip: req.ip });
  return res.json({ ok: true });
});

app.post('/api/auth/login', validateBody(AuthLoginSchema), asyncHandler(async (req, res) => {
  const password = String(req.body?.password || '');
  const ip = authClientIp(req);

  const cfg = loadConfig();
  const hash = cfg.auth?.passwordHash || '';
  if (!hash) return res.status(400).json({ error: 'password not set' });

  const ok = verifyPassword(password, hash);
  if (!ok) {
    const delay = authFailureDelayMs(ip);
    await new Promise(resolve => setTimeout(resolve, delay));
    audit.log({ action: 'auth.fail', ip, path: '/api/auth/login' });
    return res.status(401).json({ error: 'invalid credentials' });
  }

  clearAuthFailures(ip);
  const now = Date.now();
  const session = createSession(ip, 'web-password');
  await withConfigLock(async () => {
    const current = loadConfig();
    current.auth = current.auth || {};
    const sessions = Array.isArray(current.auth.sessions) ? current.auth.sessions : [];
    current.auth.sessions = sessions
      .filter(s => s.expiresAt > now)
      .concat([session]);
    saveConfig(current);
  });

  const secureAttr = req.secure || req.get('x-forwarded-proto') === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(session.id)}; Path=/; HttpOnly; SameSite=Strict${secureAttr}; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`);
  audit.log({ action: 'auth.success', ip, path: '/api/auth/login' });
  return res.json({ ok: true });
}));

app.get('/api/auth/sessions', (req, res) => {
  const cfg = loadConfig();
  const now = Date.now();
  const sessions = Array.isArray(cfg.auth?.sessions) ? cfg.auth.sessions.filter(s => s.expiresAt > now) : [];
  const cookies = parseCookies(req);
  const currentSessionId = cookies[SESSION_COOKIE] || '';
  return res.json({
    sessions: sessions.map(s => ({
      id: s.id,
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
      ip: s.ip,
      source: s.source || 'unknown',
      current: s.id === currentSessionId
    }))
  });
});

app.delete('/api/auth/sessions/:id', asyncHandler(async (req, res) => {
  const sessionId = String(req.params.id || '').trim();
  if (!sessionId) return res.status(400).json({ error: 'session id required' });
  const now = Date.now();
  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.auth = cfg.auth || {};
    const sessions = Array.isArray(cfg.auth.sessions) ? cfg.auth.sessions : [];
    cfg.auth.sessions = sessions.filter(s => s.expiresAt > now && s.id !== sessionId);
    saveConfig(cfg);
  });
  audit.log({ action: 'auth.session.revoke', ip: req.ip || req.socket?.remoteAddress || 'unknown', sessionId });
  return res.json({ ok: true });
}));

app.post('/api/auth/pubkeys', asyncHandler(async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const inputKey = String(req.body?.publicKey || '').trim();
  if (!name || !inputKey) return res.status(400).json({ error: 'name and publicKey are required' });
  const publicKey = parseEd25519PublicKey(inputKey);
  if (!publicKey) {
    return res.status(400).json({ error: 'invalid publicKey (accepts base64 DER SPKI or ssh-ed25519)' });
  }
  const keyObject = crypto.createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' });
  if (keyObject.asymmetricKeyType !== 'ed25519') {
    return res.status(400).json({ error: 'only ed25519 keys are allowed' });
  }
  const keyId = crypto.createHash('sha256').update(publicKey).digest('hex').slice(0, 16);
  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.auth = cfg.auth || {};
    const pubkeys = Array.isArray(cfg.auth.pubkeys) ? cfg.auth.pubkeys : [];
    const next = pubkeys.filter(p => p.id !== keyId);
    next.push({ id: keyId, name, publicKey, addedAt: Date.now() });
    cfg.auth.pubkeys = next;
    saveConfig(cfg);
  });
  audit.log({ action: 'auth.pubkey.add', ip: req.ip || req.socket?.remoteAddress || 'unknown', keyId, name });
  return res.json({ ok: true, keyId });
}));

app.get('/api/auth/pubkeys', (req, res) => {
  const cfg = loadConfig();
  const pubkeys = Array.isArray(cfg.auth?.pubkeys) ? cfg.auth.pubkeys : [];
  res.json({ pubkeys: pubkeys.map(p => ({ id: p.id, name: p.name, addedAt: p.addedAt })) });
});

app.delete('/api/auth/pubkeys/:id', asyncHandler(async (req, res) => {
  const keyId = String(req.params.id || '').trim();
  if (!keyId) return res.status(400).json({ error: 'key id required' });
  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.auth = cfg.auth || {};
    const pubkeys = Array.isArray(cfg.auth.pubkeys) ? cfg.auth.pubkeys : [];
    cfg.auth.pubkeys = pubkeys.filter(p => p.id !== keyId);
    saveConfig(cfg);
  });
  audit.log({ action: 'auth.pubkey.remove', ip: req.ip || req.socket?.remoteAddress || 'unknown', keyId });
  return res.json({ ok: true });
}));

app.post('/api/auth/challenge', (req, res) => {
  const keyId = String(req.body?.keyId || '').trim();
  if (!keyId) return res.status(400).json({ error: 'keyId required' });
  const cfg = loadConfig();
  const pubkeys = Array.isArray(cfg.auth?.pubkeys) ? cfg.auth.pubkeys : [];
  const key = pubkeys.find(p => p.id === keyId);
  if (!key) return res.status(401).json({ error: 'key not registered' });
  const challengeId = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(32).toString('base64');
  const now = Date.now();
  authChallenges.set(challengeId, {
    keyId,
    nonce,
    createdAt: now,
    expiresAt: now + CHALLENGE_TTL_MS,
    ip: req.ip || req.socket?.remoteAddress || 'unknown'
  });
  return res.json({ challengeId, nonce, expiresInSec: Math.floor(CHALLENGE_TTL_MS / 1000) });
});

app.post('/api/auth/verify', asyncHandler(async (req, res) => {
  const challengeId = String(req.body?.challengeId || '').trim();
  const signatureB64 = String(req.body?.signature || '').trim();
  if (!challengeId || !signatureB64) {
    return res.status(400).json({ error: 'challengeId and signature are required' });
  }
  const challenge = authChallenges.get(challengeId);
  if (!challenge || challenge.expiresAt <= Date.now()) {
    authChallenges.delete(challengeId);
    return res.status(401).json({ error: 'challenge expired or invalid' });
  }
  authChallenges.delete(challengeId);

  const cfg = loadConfig();
  const pubkeys = Array.isArray(cfg.auth?.pubkeys) ? cfg.auth.pubkeys : [];
  const key = pubkeys.find(p => p.id === challenge.keyId);
  if (!key) return res.status(401).json({ error: 'key not found' });

  let verified = false;
  try {
    const publicKey = crypto.createPublicKey({ key: Buffer.from(key.publicKey, 'base64'), format: 'der', type: 'spki' });
    verified = crypto.verify(null, Buffer.from(challenge.nonce, 'base64'), publicKey, Buffer.from(signatureB64, 'base64'));
  } catch {
    verified = false;
  }
  if (!verified) {
    audit.log({ action: 'auth.fail', ip: req.ip || req.socket?.remoteAddress || 'unknown', path: '/api/auth/verify' });
    return res.status(401).json({ error: 'invalid signature' });
  }

  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const session = createSession(ip, `pubkey:${challenge.keyId}`);
  await withConfigLock(async () => {
    const current = loadConfig();
    current.auth = current.auth || {};
    const now = Date.now();
    const sessions = Array.isArray(current.auth.sessions) ? current.auth.sessions : [];
    current.auth.sessions = sessions.filter(s => s.expiresAt > now).concat([session]);
    saveConfig(current);
  });
  audit.log({ action: 'auth.success', ip, path: '/api/auth/verify', keyId: challenge.keyId });
  return res.json({ ok: true, sessionToken: session.id, expiresAt: session.expiresAt });
}));

app.post('/api/auth/logout', asyncHandler(async (req, res) => {
  const cookies = parseCookies(req);
  const sessionId = cookies[SESSION_COOKIE] || '';
  const now = Date.now();
  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.auth = cfg.auth || {};
    const sessions = Array.isArray(cfg.auth.sessions) ? cfg.auth.sessions : [];
    cfg.auth.sessions = sessions.filter(s => s.expiresAt > now && s.id !== sessionId);
    saveConfig(cfg);
  });
  const secureAttr = req.secure || req.get('x-forwarded-proto') === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict${secureAttr}; Max-Age=0`);
  audit.log({ action: 'auth.logout', ip: req.ip || req.socket?.remoteAddress || 'unknown' });
  return res.json({ ok: true });
}));

// ── vps endpoints ────────────────────────────────────────────────────────────

app.post('/api/vps/failover', async (req, res) => {
  const requestedId = String(req.body?.targetId || '').trim();
  const cfg = loadConfig();
  ensureVpsTargets(cfg);
  if (!requestedId) {
    const result = await maybeFailover(cfg, 'manual-auto');
    return res.json({
      ok: true,
      ...result,
      activeVpsId: loadConfig().activeVpsId || '',
      policy: result.policy || extractFailoverPolicy(cfg)
    });
  }
  const target = (cfg.vpsTargets || []).find(t => t.id === requestedId && t.enabled && t.ip && t.pubKey);
  if (!target) {
    return res.status(404).json({ error: 'target VPS not found or incomplete' });
  }
  cfg.activeVpsId = target.id;
  ensureVpsTargets(cfg);
  saveConfig(cfg);
  const wgConf = generateWgConf(cfg, getActiveVpsTarget(cfg));
  if (wgConf) fs.writeFileSync(WG_CONF, wgConf);
  audit.log({ action: 'vps.failover.manual', ip: req.ip, to: target.id, toIp: target.ip });
  return res.json({ ok: true, switched: true, next: { id: target.id, name: target.name, ip: target.ip }, activeVpsId: cfg.activeVpsId });
});

app.get('/api/vps/targets', async (req, res) => {
  const cfg = loadConfig();
  ensureVpsTargets(cfg);
  const vpsHealth = await computeVpsHealth(cfg.vpsTargets || []);
  res.json({
    activeVpsId: cfg.activeVpsId || '',
    targets: (cfg.vpsTargets || []).map(t => ({
      ...t,
      fingerprint: keyFingerprint(t.pubKey),
      health: vpsHealth[t.id] || null
    }))
  });
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


app.post('/api/backup', (req, res) => {
  const passphrase = String(req.body?.passphrase || '');
  const includeAudit = req.body?.includeAudit !== false;
  if (passphrase.length < 12) {
    return res.status(400).json({ error: 'passphrase demasiado corta' });
  }
  try {
    const payload = buildBackupPayload(passphrase, includeAudit);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="miniweed-backup-${Date.now()}.bak"`);
    audit.log({ action: 'backup.create', ip: req.ip, includeAudit: Boolean(includeAudit) });
    return res.send(payload);
  } catch (err) {
    return res.status(500).json({ error: `backup failed: ${err.message}` });
  }
});

app.post('/api/restore', express.raw({ type: 'application/octet-stream', limit: '15mb' }), (req, res) => {
  const passphrase = req.get('x-backup-passphrase') || '';
  if (!passphrase || passphrase.length < 12) {
    return res.status(400).json({ error: 'invalid passphrase' });
  }
  try {
    const entries = restoreBackupPayload(Buffer.from(req.body), passphrase);
    const meta = entries['meta.json'] ? JSON.parse(entries['meta.json']) : null;
    if (!meta || meta.version !== 1) {
      return res.status(400).json({ error: 'invalid meta in backup' });
    }

    if (entries['config.json']) {
      const rawConfig = JSON.parse(entries['config.json']);
      const parsedConfig = ConfigSchema.safeParse(rawConfig);
      if (!parsedConfig.success) {
        audit.log({
          action: 'backup.restore.fail',
          ip: req.ip,
          reason: 'schema_validation',
          issues: parsedConfig.error.issues
        });
        return res.status(400).json({
          error: 'config in backup failed validation',
          issues: parsedConfig.error.issues
        });
      }
    }
    if (entries['known_hosts.json']) JSON.parse(entries['known_hosts.json']);

    const restoreDir = path.join(DATA_DIR, '.restore-staging');
    fs.mkdirSync(restoreDir, { recursive: true });
    if (entries['config.json']) fs.writeFileSync(path.join(restoreDir, 'config.json'), entries['config.json'], { mode: 0o600 });
    if (entries['known_hosts.json']) fs.writeFileSync(path.join(restoreDir, 'known_hosts.json'), entries['known_hosts.json'], { mode: 0o600 });
    if (entries['audit.log']) fs.writeFileSync(path.join(restoreDir, 'audit.log'), entries['audit.log'], { mode: 0o600 });

    if (entries['config.json']) fs.renameSync(path.join(restoreDir, 'config.json'), CONFIG_FILE);
    if (entries['known_hosts.json']) fs.renameSync(path.join(restoreDir, 'known_hosts.json'), KNOWN_HOSTS_FILE);
    if (entries['audit.log']) fs.renameSync(path.join(restoreDir, 'audit.log'), path.join(DATA_DIR, 'audit.log'));

    migrateConfigIfNeeded();
    refreshHealthSnapshot();
    audit.log({ action: 'backup.restore', ip: req.ip });
    return res.json({ ok: true, restored: Object.keys(entries) });
  } catch (err) {
    return res.status(400).json({ error: `restore failed: ${err.message}` });
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

app.get('/api/openapi.json', (req, res) => {
  res.json(openApiDoc);
});

app.get('/api/kill-switch/script', (req, res) => {
  const script = buildKillSwitchScript();
  const sha256 = crypto.createHash('sha256').update(script).digest('hex');
  if (req.query.format === 'plain') {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="miniweed-killswitch.sh"');
    return res.send(script);
  }
  return res.json({ script, sha256, filename: 'miniweed-killswitch.sh' });
});

app.post('/api/rotate/prepare', validateBody(RotatePrepareSchema), async (req, res) => {
  const cfg = loadConfig();
  const active = getActiveVpsTarget(cfg);
  if (!active?.ip || !active?.pubKey || !cfg.publicKey || !cfg.privateKey) {
    return res.status(400).json({ error: 'Incomplete configuration for rotation' });
  }
  try {
    const body = req.body || {};
    let keys = null;
    if (body.nextPrivateKey && body.nextPublicKey) {
      if (!isWireGuardKey(body.nextPrivateKey) || !isWireGuardKey(body.nextPublicKey)) {
        return res.status(400).json({ error: 'invalid nextPrivateKey/nextPublicKey' });
      }
      if (body.nextPresharedKey && !isWireGuardKey(body.nextPresharedKey)) {
        return res.status(400).json({ error: 'invalid nextPresharedKey' });
      }
      keys = {
        privateKey: body.nextPrivateKey,
        publicKey: body.nextPublicKey,
        presharedKey: body.nextPresharedKey || cfg.presharedKey || ''
      };
    } else {
      keys = await wgApi('/keygen');
    }
    const planId = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    const next = {
      privateKey: keys.privateKey,
      publicKey: keys.publicKey,
      presharedKey: keys.presharedKey || cfg.presharedKey || ''
    };
    const script = buildVpsRotateScript(cfg, next, active);
    rotationPlans.set(planId, {
      id: planId,
      createdAt: now,
      expiresAt: now + ROTATION_PLAN_TTL_MS,
      previous: {
        privateKey: cfg.privateKey,
        publicKey: cfg.publicKey,
        presharedKey: cfg.presharedKey || ''
      },
      next,
      script,
      scriptSha256: crypto.createHash('sha256').update(script).digest('hex'),
      target: { id: active.id, name: active.name, ip: active.ip }
    });
    audit.log({ action: 'key.rotate.prepare', ip: req.ip, planId, nextFingerprint: keyFingerprint(next.publicKey) });
    return res.json({
      ok: true,
      planId,
      expiresInSec: Math.floor(ROTATION_PLAN_TTL_MS / 1000),
      nextPublicKey: next.publicKey,
      nextPublicKeyFingerprint: keyFingerprint(next.publicKey),
      script,
      scriptSha256: crypto.createHash('sha256').update(script).digest('hex'),
      target: { id: active.id, name: active.name, ip: active.ip }
    });
  } catch (err) {
    return res.status(503).json({ error: `Could not prepare rotation: ${err.message}` });
  }
});

app.post('/api/rotate/confirm', validateBody(RotateConfirmSchema), async (req, res) => {
  const planId = String(req.body?.planId || '').trim();
  const apply = req.body?.apply !== false;
  const plan = rotationPlans.get(planId);
  if (!plan || plan.expiresAt <= Date.now()) {
    rotationPlans.delete(planId);
    return res.status(404).json({ error: 'Rotation plan not found or expired' });
  }

  if (!apply) {
    rotationPlans.delete(planId);
    audit.log({ action: 'key.rotate.cancel', ip: req.ip, planId });
    return res.json({ ok: true, cancelled: true });
  }

  await withConfigLock(async () => {
    const cfg = loadConfig();
    cfg.privateKey = plan.next.privateKey;
    cfg.publicKey = plan.next.publicKey;
    cfg.presharedKey = plan.next.presharedKey;
    saveConfig(cfg);
    const wgConf = generateWgConf(cfg, getActiveVpsTarget(cfg));
    if (wgConf) fs.writeFileSync(WG_CONF, wgConf);
  });

  rotationPlans.delete(planId);
  audit.log({ action: 'key.rotate.commit', ip: req.ip, planId, publicKeyFingerprint: keyFingerprint(plan.next.publicKey) });
  return res.json({ ok: true, applied: true, nextPublicKey: plan.next.publicKey, nextPublicKeyFingerprint: keyFingerprint(plan.next.publicKey) });
});

app.get('/api/rotate/:planId', (req, res) => {
  const plan = rotationPlans.get(req.params.planId);
  if (!plan || plan.expiresAt <= Date.now()) {
    if (plan) rotationPlans.delete(req.params.planId);
    return res.status(404).json({ error: 'Plan not found or expired' });
  }
  return res.json({
    id: plan.id,
    createdAt: plan.createdAt,
    expiresAt: plan.expiresAt,
    nextPublicKey: plan.next.publicKey,
    nextPublicKeyFingerprint: keyFingerprint(plan.next.publicKey),
    scriptSha256: plan.scriptSha256
  });
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
  API_AUTH_TOKEN = loadOrCreateApiToken();
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
    buildKillSwitchScript,
    buildVpsRotateScript,
    checkServicesHealth,
    validateEmailWithMx,
    buildBackupPayload,
    restoreBackupPayload,
    loadConfig,
    saveConfig
  }
};
