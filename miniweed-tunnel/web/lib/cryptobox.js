const crypto = require('crypto');

const SALT = Buffer.from('miniweed-tunnel/v1', 'utf8');
const KDF_PARAMS = { N: 1 << 17, r: 8, p: 1, dkLen: 32 };
const ALG = 'aes-256-gcm';

let cachedKey = null;

function getMasterKey() {
  if (cachedKey) return cachedKey;
  const seed = process.env.APP_SEED || process.env.TUNNEL_API_TOKEN;
  if (!seed || String(seed).length < 32) {
    throw new Error('APP_SEED missing or too short (need >=32 chars)');
  }
  cachedKey = crypto.scryptSync(String(seed), SALT, KDF_PARAMS.dkLen, {
    N: KDF_PARAMS.N,
    r: KDF_PARAMS.r,
    p: KDF_PARAMS.p,
    maxmem: 256 * 1024 * 1024
  });
  return cachedKey;
}

function seal(plaintext) {
  if (plaintext == null || plaintext === '') return null;
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALG, getMasterKey(), nonce);
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  return {
    v: 1,
    n: nonce.toString('base64'),
    c: ct.toString('base64'),
    t: cipher.getAuthTag().toString('base64')
  };
}

function open(blob) {
  if (!blob || typeof blob !== 'object' || blob.v !== 1) return null;
  const nonce = Buffer.from(blob.n, 'base64');
  const ct = Buffer.from(blob.c, 'base64');
  const tag = Buffer.from(blob.t, 'base64');
  const decipher = crypto.createDecipheriv(ALG, getMasterKey(), nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

function isSealed(value) {
  return Boolean(value && typeof value === 'object' && value.v === 1 && value.n && value.c && value.t);
}

function __resetForTest() {
  cachedKey = null;
}

module.exports = { seal, open, isSealed, __resetForTest };
