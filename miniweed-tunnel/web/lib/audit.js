const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const AUDIT_PATH = path.join(process.env.DATA_DIR || '/data', 'audit.log');
const MAX_SIZE = 10 * 1024 * 1024;
const MAX_FILES = 5;
let lastHash = '0'.repeat(64);

function init() {
  if (!fs.existsSync(AUDIT_PATH)) return;
  try {
    const lines = fs.readFileSync(AUDIT_PATH, 'utf8').trim().split('\n').filter(Boolean);
    if (!lines.length) return;
    const last = JSON.parse(lines[lines.length - 1]);
    if (last && typeof last.hash === 'string') lastHash = last.hash;
  } catch {
    lastHash = '0'.repeat(64);
  }
}

function rotateIfNeeded() {
  if (!fs.existsSync(AUDIT_PATH)) return;
  const size = fs.statSync(AUDIT_PATH).size;
  if (size < MAX_SIZE) return;
  for (let i = MAX_FILES - 1; i >= 1; i -= 1) {
    const src = `${AUDIT_PATH}.${i}`;
    const dst = `${AUDIT_PATH}.${i + 1}`;
    if (fs.existsSync(src)) fs.renameSync(src, dst);
  }
  fs.renameSync(AUDIT_PATH, `${AUDIT_PATH}.1`);
}

function log(event) {
  try {
    rotateIfNeeded();
    const entry = { ts: new Date().toISOString(), prevHash: lastHash, ...event };
    const serial = JSON.stringify(entry);
    const hash = crypto.createHash('sha256').update(lastHash + serial).digest('hex');
    const final = { ...entry, hash };
    fs.appendFileSync(AUDIT_PATH, JSON.stringify(final) + '\n', { mode: 0o600 });
    lastHash = hash;
  } catch {
    // Non-blocking best effort logging.
  }
}

function readLatest(limit = 100) {
  if (!fs.existsSync(AUDIT_PATH)) return [];
  const lines = fs.readFileSync(AUDIT_PATH, 'utf8').trim().split('\n').filter(Boolean);
  return lines.slice(-limit).map(line => JSON.parse(line));
}

function verifyChain() {
  if (!fs.existsSync(AUDIT_PATH)) return { ok: true, entries: 0 };
  const lines = fs.readFileSync(AUDIT_PATH, 'utf8').trim().split('\n').filter(Boolean);
  let prev = '0'.repeat(64);
  for (let i = 0; i < lines.length; i += 1) {
    let parsed;
    try {
      parsed = JSON.parse(lines[i]);
    } catch {
      return { ok: false, entries: lines.length, brokenAt: i, reason: 'invalid_json' };
    }
    if (parsed.prevHash !== prev) {
      return { ok: false, entries: lines.length, brokenAt: i, reason: 'prev_hash_mismatch' };
    }
    const { hash, ...rest } = parsed;
    const expected = crypto.createHash('sha256').update(prev + JSON.stringify(rest)).digest('hex');
    if (hash !== expected) {
      return { ok: false, entries: lines.length, brokenAt: i, reason: 'hash_mismatch' };
    }
    prev = hash;
  }
  return { ok: true, entries: lines.length };
}

init();

module.exports = { log, readLatest, verifyChain };
