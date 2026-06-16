// Constantes puras (sin estado mutable), extraídas de server.js.
// El estado en memoria (Maps de sesiones/rotación/failover, tokens runtime)
// permanece en server.js.
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || '/data';
const WG_API_HOST = process.env.WG_API_HOST || 'wg';
const WG_API_PORT = 8080;
const WG_API_TOKEN = String(process.env.WG_API_TOKEN || '').trim();
const DISABLE_API_AUTH = /^(1|true|yes)$/i.test(String(process.env.DISABLE_API_AUTH || ''));

const MAX_SERVICES = 64;
const MAX_VPS_TARGETS = 8;
const FAILOVER_POLICY_DEFAULTS = {
  activeFailuresRequired: 2,
  candidateSuccessesRequired: 2,
  cooldownMs: 2 * 60 * 1000
};

const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const WG_CONF = path.join(DATA_DIR, 'wg0.conf');
const CADDYFILE = path.join(DATA_DIR, 'Caddyfile');
const TOKEN_FILE = path.join(DATA_DIR, 'api-token.enc');
const APP_SEED_FILE = path.join(DATA_DIR, 'app-seed');
const HEALTH_FILE = path.join(DATA_DIR, 'health.json');
const KNOWN_HOSTS_FILE = path.join(DATA_DIR, 'known_hosts.json');

const ENCRYPTED_FIELDS = ['privateKey', 'presharedKey'];
const SESSION_COOKIE = 'mw_session';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const ROTATION_PLAN_TTL_MS = 30 * 60 * 1000;

const DEFAULT_CONFIG = {
  privateKey: '',
  publicKey: '',
  presharedKey: '',
  vpsIp: '',
  vpsPort: 51820,
  vpsPubKey: '',
  vpsTargets: [],
  activeVpsId: '',
  tunnelClientIp: '10.8.0.2',
  tunnelServerIp: '10.8.0.1',
  domain: '',
  acmeEmail: '',
  services: [],
  serviceHealth: {},
  auth: {
    passwordHash: '',
    sessions: [],
    pubkeys: []
  },
  failoverPolicy: { ...FAILOVER_POLICY_DEFAULTS }
};

const DEFAULT_CADDYFILE = ':80 {\n  respond "Umbrel Tunnel — not configured yet"\n}\n';

module.exports = {
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
};
