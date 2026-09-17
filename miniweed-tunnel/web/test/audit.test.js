const fs = require('fs');
const os = require('os');
const path = require('path');

// lib/audit pins AUDIT_PATH to DATA_DIR at load time: prepare the dir first.
function freshAudit() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mw-audit-'));
  process.env.DATA_DIR = dir;
  jest.resetModules();
  return { dir, audit: require('../lib/audit') };
}

describe('audit hash chain', () => {
  const prevDataDir = process.env.DATA_DIR;
  afterEach(() => {
    if (prevDataDir === undefined) delete process.env.DATA_DIR;
    else process.env.DATA_DIR = prevDataDir;
  });

  test('valid chain verifies ok', () => {
    const { dir, audit } = freshAudit();
    audit.log({ action: 'a' });
    audit.log({ action: 'b' });
    audit.log({ action: 'c' });
    const result = audit.verifyChain();
    expect(result.ok).toBe(true);
    expect(result.entries).toBe(3);
    expect(audit.readLatest(2).length).toBe(2);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('detects tampering with an entry', () => {
    const { dir, audit } = freshAudit();
    audit.log({ action: 'login', user: 'a' });
    audit.log({ action: 'login', user: 'b' });
    const auditPath = path.join(dir, 'audit.log');
    const lines = fs.readFileSync(auditPath, 'utf8').trim().split('\n');
    const tampered = JSON.parse(lines[0]);
    tampered.user = 'attacker'; // changes the content without recomputing the hash
    lines[0] = JSON.stringify(tampered);
    fs.writeFileSync(auditPath, lines.join('\n') + '\n');

    const result = audit.verifyChain();
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(0);
    expect(result.reason).toBe('hash_mismatch');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('detects deletion of an entry (breaks prevHash)', () => {
    const { dir, audit } = freshAudit();
    audit.log({ action: '1' });
    audit.log({ action: '2' });
    audit.log({ action: '3' });
    const auditPath = path.join(dir, 'audit.log');
    const lines = fs.readFileSync(auditPath, 'utf8').trim().split('\n');
    // Removes the second entry: the third one no longer chains to the first.
    fs.writeFileSync(auditPath, [lines[0], lines[2]].join('\n') + '\n');

    const result = audit.verifyChain();
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('prev_hash_mismatch');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('rotation restarts the chain: verifyChain gives no false positive', () => {
    const { dir, audit } = freshAudit();
    audit.log({ action: 'pre-rotation' });
    const auditPath = path.join(dir, 'audit.log');
    // Inflate the file beyond MAX_SIZE bypassing log() (doesn't touch lastHash).
    fs.appendFileSync(auditPath, 'x'.repeat(11 * 1024 * 1024));
    audit.log({ action: 'post-rotation' }); // triggers the rotation

    expect(fs.existsSync(`${auditPath}.1`)).toBe(true);
    const result = audit.verifyChain();
    expect(result.ok).toBe(true);
    expect(result.entries).toBe(1);
    // The new file starts with a genesis prevHash.
    const first = JSON.parse(fs.readFileSync(auditPath, 'utf8').trim().split('\n')[0]);
    expect(first.prevHash).toBe('0'.repeat(64));
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
