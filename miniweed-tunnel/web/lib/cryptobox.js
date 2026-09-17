const crypto = require('crypto');

const SALT = Buffer.from('miniweed-tunnel/v1', 'utf8');
const KDF_PARAMS = { N: 1 << 17, r: 8, p: 1, dkLen: 32 };
const ALG = 'aes-256-gcm';

let cachedKey = null;

function deriveKey(seed) {
  return crypto.scryptSync(String(seed), SALT, KDF_PARAMS.dkLen, {
    N: KDF_PARAMS.N,
    r: KDF_PARAMS.r,
    p: KDF_PARAMS.p,
    maxmem: 256 * 1024 * 1024
  });
}

function getMasterKey() {
  if (cachedKey) return cachedKey;
  const seed = process.env.APP_SEED || process.env.TUNNEL_API_TOKEN;
  if (!seed || String(seed).length < 32) {
    throw new Error('APP_SEED missing or too short (need >=32 chars)');
  }
  cachedKey = deriveKey(seed);
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

// Can this specific seed open this blob? Derives a throwaway key (never touches
// the cached master key) so startup can tell which of two candidate seeds the
// stored config was actually encrypted with. Costs one scrypt pass, so it is
// only called on the rare seed-mismatch path.
function canOpenWith(seed, blob) {
  if (!isSealed(blob) || !seed || String(seed).length < 32) return false;
  try {
    const decipher = crypto.createDecipheriv(ALG, deriveKey(seed), Buffer.from(blob.n, 'base64'));
    decipher.setAuthTag(Buffer.from(blob.t, 'base64'));
    Buffer.concat([decipher.update(Buffer.from(blob.c, 'base64')), decipher.final()]);
    return true;
  } catch {
    // Wrong key (GCM tag mismatch) or malformed blob.
    return false;
  }
}

function __resetForTest() {
  cachedKey = null;
}

module.exports = { seal, open, isSealed, canOpenWith, __resetForTest };
