// Pure constants (no mutable state), extracted from server.js.
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || '/data';
const WG_API_HOST = process.env.WG_API_HOST || 'wg';
const WG_API_PORT = 8080;
const WG_API_TOKEN = String(process.env.WG_API_TOKEN || '').trim();

const MAX_SERVICES = 64;

const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
// wg0.conf vive en un subdir propio: el contenedor wg monta solo DATA_DIR/wg
// (read-only), así no ve config.json/app-seed/etc.
const WG_CONF = path.join(DATA_DIR, 'wg', 'wg0.conf');
const LEGACY_WG_CONF = path.join(DATA_DIR, 'wg0.conf');
const CADDYFILE = process.env.CADDYFILE_PATH || path.join(DATA_DIR, 'Caddyfile');
const APP_SEED_FILE = path.join(DATA_DIR, 'app-seed');
const HEALTH_FILE = path.join(DATA_DIR, 'health.json');
const KNOWN_HOSTS_FILE = path.join(DATA_DIR, 'known_hosts.json');

const ENCRYPTED_FIELDS = ['privateKey', 'presharedKey'];

const DEFAULT_CONFIG = {
  privateKey: '',
  publicKey: '',
  presharedKey: '',
  vpsIp: '',
  vpsPort: 51820,
  vpsPubKey: '',
  tunnelClientIp: '10.8.0.2',
  tunnelServerIp: '10.8.0.1',
  domain: '',
  acmeEmail: '',
  services: [],
  serviceHealth: {}
};

const DEFAULT_CADDYFILE = ':80 {\n  respond "Umbrel Tunnel — not configured yet"\n}\n';

module.exports = {
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
};
