const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const zlib = require('zlib');

jest.mock('dns', () => ({
  lookup: jest.fn((host, opts, cb) => {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    const family = String(host).includes(':') ? 6 : 4;
    // Passthrough de IPs literales (los tests usan IPs como target de servicio).
    if (opts && opts.all) return cb(null, [{ address: host, family }]);
    return cb(null, host, family);
  }),
  promises: {
    resolveMx: jest.fn(async () => [{ exchange: 'mail.example.com', priority: 10 }]),
    resolve4: jest.fn(async () => ['127.0.0.1'])
  }
}));

jest.mock('net', () => {
  const { EventEmitter } = require('events');
  class MockSocket extends EventEmitter {
    setTimeout() {
      return this;
    }

    connect(port, hostname) {
      const key = `${hostname}:${port}`;
      const mock = global.__NET_SOCKET_MOCK__ || {};
      const seq = mock.sequence && mock.sequence[key];
      let outcome = null;
      if (Array.isArray(seq) && seq.length > 0) {
        outcome = seq.shift();
      }
      if (!outcome && mock.rules) {
        outcome = mock.rules[key] || mock.rules[hostname] || null;
      }
      if (!outcome) outcome = 'fail';

      setImmediate(() => {
        if (outcome === 'ok') {
          this.emit('connect');
          return;
        }
        if (outcome === 'timeout') {
          this.emit('timeout');
          return;
        }
        this.emit('error', new Error(`mock-${outcome}`));
      });

      return this;
    }

    destroy() {
      return this;
    }
  }

  return { Socket: MockSocket };
});

const dns = require('dns');

function setNetMock(rules = {}, sequence = {}) {
  global.__NET_SOCKET_MOCK__ = { rules: { ...rules }, sequence: { ...sequence } };
}

async function startAppServer(tempDir) {
  process.env.DATA_DIR = tempDir;
  process.env.APP_SEED = 'a'.repeat(64);
  process.env.PORT = '0';
  jest.resetModules();
  const mod = require('../server');
  const server = mod.startServer();
  await new Promise(resolve => server.on('listening', resolve));
  const port = server.address().port;
  return { server, port, stopBackgroundTimers: mod.stopBackgroundTimers };
}

function req(port, method, pathname, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: '127.0.0.1',
      port,
      path: pathname,
      method,
      agent: false,
      headers: {
        Connection: 'close',
        ...headers
      }
    };
    const client = require('http').request(options, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });
    client.on('error', reject);
    if (body) client.write(body);
    client.end();
  });
}

function buildBackupPayloadForTest(entries, passphrase) {
  const chunks = [];
  for (const [name, value] of Object.entries(entries)) {
    const body = Buffer.from(String(value), 'utf8');
    chunks.push(Buffer.from(`${name}:${body.length}\n`, 'utf8'));
    chunks.push(body);
  }
  const compressed = zlib.gzipSync(Buffer.concat(chunks));
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, salt, 32, { N: 1 << 16, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from('MWBK', 'utf8'), salt, nonce, ciphertext, tag]);
}

describe('api hardening', () => {
  let tmpDir;
  let server;
  let port;
  let token;
  let stopBackgroundTimers;
  let logSpy;

  beforeEach(async () => {
    setNetMock();
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniweed-web-'));
    const started = await startAppServer(tmpDir);
    server = started.server;
    port = started.port;
    stopBackgroundTimers = started.stopBackgroundTimers;
    token = Buffer.from(require('crypto').hkdfSync(
      'sha256',
      Buffer.from(process.env.APP_SEED, 'utf8'),
      Buffer.from('miniweed-tunnel/v1', 'utf8'),
      Buffer.from('tunnel-api-token-v1', 'utf8'),
      32
    )).toString('base64url');
  });

  afterEach(done => {
    server.close(() => {
      if (typeof stopBackgroundTimers === 'function') stopBackgroundTimers();
      if (logSpy) logSpy.mockRestore();
      done();
    });
  });

  test('rejects unauthorized api call', async () => {
    const r = await req(port, 'GET', '/api/config');
    expect(r.status).toBe(401);
  });

  test('does not issue tunnel_api_token cookie on SPA routes', async () => {
    const r = await req(port, 'GET', '/');
    expect(r.status).toBe(200);
    const setCookie = Array.isArray(r.headers['set-cookie'])
      ? r.headers['set-cookie'].join(';')
      : String(r.headers['set-cookie'] || '');
    expect(setCookie).not.toContain('tunnel_api_token=');
  });

  test('bootstraps persistent app seed when env seed is missing', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniweed-web-seed-'));
    const prevSeed = process.env.APP_SEED;
    const prevToken = process.env.TUNNEL_API_TOKEN;
    const prevData = process.env.DATA_DIR;
    const prevPort = process.env.PORT;

    delete process.env.APP_SEED;
    delete process.env.TUNNEL_API_TOKEN;
    process.env.DATA_DIR = tempDir;
    process.env.PORT = '0';

    jest.resetModules();
    const mod = require('../server');
    const s1 = mod.startServer();
    await new Promise(resolve => s1.on('listening', resolve));
    await new Promise(resolve => s1.close(resolve));
    if (typeof mod.stopBackgroundTimers === 'function') mod.stopBackgroundTimers();

    const seedPath = path.join(tempDir, 'app-seed');
    expect(fs.existsSync(seedPath)).toBe(true);
    const firstSeed = String(fs.readFileSync(seedPath, 'utf8')).trim();
    expect(firstSeed.length).toBeGreaterThanOrEqual(32);

    jest.resetModules();
    const mod2 = require('../server');
    const s2 = mod2.startServer();
    await new Promise(resolve => s2.on('listening', resolve));
    await new Promise(resolve => s2.close(resolve));
    if (typeof mod2.stopBackgroundTimers === 'function') mod2.stopBackgroundTimers();

    const secondSeed = String(fs.readFileSync(seedPath, 'utf8')).trim();
    expect(secondSeed).toBe(firstSeed);

    if (prevSeed === undefined) delete process.env.APP_SEED; else process.env.APP_SEED = prevSeed;
    if (prevToken === undefined) delete process.env.TUNNEL_API_TOKEN; else process.env.TUNNEL_API_TOKEN = prevToken;
    if (prevData === undefined) delete process.env.DATA_DIR; else process.env.DATA_DIR = prevData;
    if (prevPort === undefined) delete process.env.PORT; else process.env.PORT = prevPort;

    jest.resetModules();
  });

  test('returns script with sha for authorized call', async () => {
    const payload = JSON.stringify({
      vpsIp: '1.2.3.4',
      vpsPort: 51820,
      vpsPubKey: 'A'.repeat(43) + '=',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      services: []
    });
    await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });

    const r = await req(port, 'GET', '/api/vps-setup-script', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(typeof body.script).toBe('string');
    expect(body.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(body.vps).toBeTruthy();
    expect(body.vps.ip).toBe('1.2.3.4');
  });

  test('supports multi-vps config and manual failover switch', async () => {
    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-a',
          name: 'VPS A',
          ip: '10.10.10.10',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 1
        },
        {
          id: 'vps-b',
          name: 'VPS B',
          ip: '11.11.11.11',
          port: 51821,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 0
        }
      ],
      activeVpsId: 'vps-a',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'C'.repeat(43) + '=',
      publicKey: 'D'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    const switchRes = await req(port, 'POST', '/api/vps/failover', JSON.stringify({ targetId: 'vps-b' }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(switchRes.status).toBe(200);
    const switched = JSON.parse(switchRes.body);
    expect(switched.ok).toBe(true);
    expect(switched.activeVpsId).toBe('vps-b');

    const cfgRes = await req(port, 'GET', '/api/config', null, {
      'x-tunnel-api-token': token
    });
    expect(cfgRes.status).toBe(200);
    const cfgBody = JSON.parse(cfgRes.body);
    expect(Array.isArray(cfgBody.vpsTargets)).toBe(true);
    expect(cfgBody.activeVpsId).toBe('vps-b');
    expect(cfgBody.vpsIp).toBe('11.11.11.11');
  });

  test('returns vps targets with health metadata', async () => {
    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-h1',
          name: 'VPS Health 1',
          ip: '127.0.0.1',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 0
        }
      ],
      activeVpsId: 'vps-h1',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    const r = await req(port, 'GET', '/api/vps/targets', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.activeVpsId).toBe('vps-h1');
    expect(Array.isArray(body.targets)).toBe(true);
    expect(body.targets[0].id).toBe('vps-h1');
    expect(typeof body.targets[0].fingerprint).toBe('string');
    expect(body.targets[0].health).toBeTruthy();
    expect(typeof body.targets[0].health.ok).toBe('boolean');
  });

  test('can request setup script with crowdsec for specific vps', async () => {
    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-c',
          name: 'VPS C',
          ip: '12.12.12.12',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 0
        }
      ],
      activeVpsId: 'vps-c',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    const r = await req(port, 'GET', '/api/vps-setup-script?vpsId=vps-c&withCrowdsec=1', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.withCrowdsec).toBe(true);
    expect(body.script).toContain('Instalando CrowdSec');
    expect(body.script).toContain('apt-get -o DPkg::Lock::Timeout=300 install -y -qq curl ca-certificates');
    expect(body.script).toContain('curl -fsSL https://install.crowdsec.net | sh');
    expect(body.script).toContain('cscli lapi status >/dev/null 2>&1 || echo "Warning: cscli could not validate LAPI"');
    expect(body.script).toContain('iptables-save | grep -qi crowdsec || echo "Warning: CrowdSec iptables hook not detected"');
    expect(body.vps.id).toBe('vps-c');
  });

  test('auto failover respects streaks, cooldown, and recovery after cooldown', async () => {
    const nowSpy = jest.spyOn(Date, 'now');
    let now = 1_000_000;
    nowSpy.mockImplementation(() => now);

    // Keep everyone healthy during initial save/health refresh.
    setNetMock(
      {
        '10.0.0.1:22': 'ok',
        '10.0.0.1:443': 'ok',
        '10.0.0.2:22': 'ok',
        '10.0.0.2:443': 'ok'
      }
    );

    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-a',
          name: 'VPS A',
          ip: '10.0.0.1',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 0
        },
        {
          id: 'vps-b',
          name: 'VPS B',
          ip: '10.0.0.2',
          port: 51820,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 1
        }
      ],
      activeVpsId: 'vps-a',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'C'.repeat(43) + '=',
      publicKey: 'D'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    // Active starts failing, candidate remains healthy.
    setNetMock(
      {
        '10.0.0.1:22': 'fail',
        '10.0.0.1:443': 'fail',
        '10.0.0.2:22': 'ok',
        '10.0.0.2:443': 'ok'
      }
    );

    let auto1 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto1.status).toBe(200);
    expect(JSON.parse(auto1.body).switched).toBe(false);

    now += 1000;
    let auto2 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto2.status).toBe(200);
    const switchedToB = JSON.parse(auto2.body);
    expect(switchedToB.switched).toBe(true);
    expect(switchedToB.activeVpsId).toBe('vps-b');

    setNetMock(
      {
        '10.0.0.1:22': 'ok',
        '10.0.0.1:443': 'ok',
        '10.0.0.2:22': 'fail',
        '10.0.0.2:443': 'fail'
      }
    );

    now += 1000;
    await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });

    now += 1000;
    const cooldownBlocked = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(cooldownBlocked.status).toBe(200);
    const blockedBody = JSON.parse(cooldownBlocked.body);
    expect(blockedBody.switched).toBe(false);
    expect(blockedBody.activeVpsId).toBe('vps-b');

    now += (2 * 60 * 1000) + 1000;
    const recovered = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(recovered.status).toBe(200);
    const recoveredBody = JSON.parse(recovered.body);
    expect(recoveredBody.switched).toBe(true);
    expect(recoveredBody.activeVpsId).toBe('vps-a');

    nowSpy.mockRestore();
  });

  test('auto failover tie-break uses lexical name when priorities equal', async () => {
    // Keep everyone healthy during initial save/health refresh.
    setNetMock(
      {
        '10.1.0.1:22': 'ok',
        '10.1.0.1:443': 'ok',
        '10.1.0.2:22': 'ok',
        '10.1.0.2:443': 'ok',
        '10.1.0.3:22': 'ok',
        '10.1.0.3:443': 'ok'
      }
    );

    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'active',
          name: 'Active-Z',
          ip: '10.1.0.1',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 5
        },
        {
          id: 'alpha',
          name: 'Alpha',
          ip: '10.1.0.2',
          port: 51820,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 1
        },
        {
          id: 'beta',
          name: 'Beta',
          ip: '10.1.0.3',
          port: 51820,
          pubKey: 'C'.repeat(43) + '=',
          enabled: true,
          priority: 1
        }
      ],
      activeVpsId: 'active',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'D'.repeat(43) + '=',
      publicKey: 'E'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    // Active degrades, both candidates healthy with same priority.
    setNetMock(
      {
        '10.1.0.1:22': 'fail',
        '10.1.0.1:443': 'fail',
        '10.1.0.2:22': 'ok',
        '10.1.0.2:443': 'ok',
        '10.1.0.3:22': 'ok',
        '10.1.0.3:443': 'ok'
      }
    );

    await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });

    const auto = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto.status).toBe(200);
    const body = JSON.parse(auto.body);
    expect(body.switched).toBe(true);
    expect(body.activeVpsId).toBe('alpha');
    expect(body.next.name).toBe('Alpha');
  });

  test('manual switch and later auto failover recovery interoperate correctly', async () => {
    setNetMock(
      {
        '10.2.0.1:22': 'ok',
        '10.2.0.1:443': 'ok',
        '10.2.0.2:22': 'ok',
        '10.2.0.2:443': 'ok'
      }
    );

    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-a',
          name: 'VPS A',
          ip: '10.2.0.1',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 0
        },
        {
          id: 'vps-b',
          name: 'VPS B',
          ip: '10.2.0.2',
          port: 51820,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 1
        }
      ],
      activeVpsId: 'vps-a',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'C'.repeat(43) + '=',
      publicKey: 'D'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    const manual = await req(port, 'POST', '/api/vps/failover', JSON.stringify({ targetId: 'vps-b' }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(manual.status).toBe(200);
    const manualBody = JSON.parse(manual.body);
    expect(manualBody.switched).toBe(true);
    expect(manualBody.activeVpsId).toBe('vps-b');

    setNetMock(
      {
        '10.2.0.1:22': 'ok',
        '10.2.0.1:443': 'ok',
        '10.2.0.2:22': 'fail',
        '10.2.0.2:443': 'fail'
      }
    );

    const auto1 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto1.status).toBe(200);
    expect(JSON.parse(auto1.body).switched).toBe(false);

    const auto2 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto2.status).toBe(200);
    const autoBody = JSON.parse(auto2.body);
    expect(autoBody.switched).toBe(true);
    expect(autoBody.activeVpsId).toBe('vps-a');
  });

  test('auto failover recovers when current active target is incomplete', async () => {
    setNetMock(
      {
        '10.3.0.1:22': 'fail',
        '10.3.0.1:443': 'fail',
        '10.3.0.2:22': 'fail',
        '10.3.0.2:443': 'fail'
      }
    );

    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-incomplete',
          name: 'VPS Incomplete',
          ip: '10.3.0.1',
          port: 51820,
          enabled: true,
          priority: 0
        },
        {
          id: 'vps-ok',
          name: 'VPS OK',
          ip: '10.3.0.2',
          port: 51820,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 1
        }
      ],
      activeVpsId: 'vps-incomplete',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'C'.repeat(43) + '=',
      publicKey: 'D'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    setNetMock(
      {
        '10.3.0.1:22': 'fail',
        '10.3.0.1:443': 'fail',
        '10.3.0.2:22': 'ok',
        '10.3.0.2:443': 'ok'
      }
    );

    const auto1 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto1.status).toBe(200);
    expect(JSON.parse(auto1.body).switched).toBe(false);

    const auto2 = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto2.status).toBe(200);
    const body = JSON.parse(auto2.body);
    expect(body.switched).toBe(true);
    expect(body.activeVpsId).toBe('vps-ok');
  });

  test('health refresh endpoint works', async () => {
    const r = await req(port, 'POST', '/api/health/refresh', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.ok).toBe(true);
  });

  test('rejects config service target to loopback wg helper port', async () => {
    const payload = JSON.stringify({
      vpsIp: '1.2.3.4',
      vpsPort: 51820,
      vpsPubKey: 'A'.repeat(43) + '=',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      services: [{ name: 'bad', subdomain: 'bad', target: 'http://127.0.0.1:8080', enabled: true }]
    });
    const r = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(400);
    const body = JSON.parse(r.body);
    expect(Array.isArray(body.errors)).toBe(true);
    expect(body.errors.join(' ')).toContain('reserved or control target');
  });

  test('rejects config service target to localhost caddy admin port', async () => {
    const payload = JSON.stringify({
      vpsIp: '1.2.3.4',
      vpsPort: 51820,
      vpsPubKey: 'A'.repeat(43) + '=',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      services: [{ name: 'bad2', subdomain: 'bad2', target: 'http://localhost:2019', enabled: true }]
    });
    const r = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(400);
    const body = JSON.parse(r.body);
    expect(Array.isArray(body.errors)).toBe(true);
    expect(body.errors.join(' ')).toContain('reserved or control target');
  });

  test('validation rejects malformed email', async () => {
    const payload = JSON.stringify({
      vpsIp: '1.2.3.4',
      vpsPort: 51820,
      domain: 'example.com',
      acmeEmail: 'bad-email',
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      services: []
    });
    const r = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(400);
  });

  test('accepts minimal progressive setup payload and returns validation details for malformed body', async () => {
    const minimal = await req(port, 'POST', '/api/config', JSON.stringify({
      vpsIp: '1.2.3.4',
      domain: 'example.com',
      acmeEmail: 'ops@example.com'
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(minimal.status).toBe(200);

    const malformed = await req(port, 'POST', '/api/config', JSON.stringify([]), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(malformed.status).toBe(400);
    const malformedBody = JSON.parse(malformed.body);
    expect(malformedBody.error).toBe('validation');
    expect(Array.isArray(malformedBody.issues)).toBe(true);
  });

  test('validation rejects malformed vps IPv4 in config update', async () => {
    const malformed = await req(port, 'POST', '/api/config', JSON.stringify({
      vpsIp: '999.999.999.999',
      domain: 'example.com',
      acmeEmail: 'ops@example.com'
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(malformed.status).toBe(400);
    const body = JSON.parse(malformed.body);
    expect(body.error).toBe('validation');
  });

  test('validation rejects malformed vps target IPv4 in config update', async () => {
    const malformed = await req(port, 'POST', '/api/config', JSON.stringify({
      vpsTargets: [{
        id: 'bad-ip',
        name: 'Bad IP',
        ip: 'not-an-ip',
        port: 51820,
        pubKey: 'A'.repeat(43) + '=',
        enabled: true,
        priority: 0
      }],
      activeVpsId: 'bad-ip',
      domain: 'example.com',
      acmeEmail: 'ops@example.com'
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(malformed.status).toBe(400);
    const body = JSON.parse(malformed.body);
    expect(body.error).toBe('validation');
  });

  test('can set and use UI password session login', async () => {
    const setPwd = await req(port, 'POST', '/api/auth/password', JSON.stringify({ password: 'S3gura__pass__123' }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(setPwd.status).toBe(200);

    const login = await req(port, 'POST', '/api/auth/login', JSON.stringify({ password: 'S3gura__pass__123' }), {
      'Content-Type': 'application/json'
    });
    expect(login.status).toBe(200);
    const setCookie = Array.isArray(login.headers['set-cookie']) ? login.headers['set-cookie'][0] : String(login.headers['set-cookie'] || '');
    expect(setCookie).toContain('mw_session=');

    const sessionValue = setCookie.split(';')[0].split('=')[1];
    const bySession = await req(port, 'GET', '/api/config', null, {
      Cookie: `mw_session=${sessionValue}`
    });
    expect(bySession.status).toBe(200);

    const logout = await req(port, 'POST', '/api/auth/logout', null, {
      Cookie: `mw_session=${sessionValue}`
    });
    expect(logout.status).toBe(200);

    const afterLogout = await req(port, 'GET', '/api/config', null, {
      Cookie: `mw_session=${sessionValue}`
    });
    expect(afterLogout.status).toBe(401);
  });

  test('password change requires auth once a password exists (C1)', async () => {
    // Bootstrap: primer set sin auth permitido.
    const first = await req(port, 'POST', '/api/auth/password', JSON.stringify({ password: 'S3gura__pass__123' }), {
      'Content-Type': 'application/json'
    });
    expect(first.status).toBe(200);

    // Intento de cambio SIN auth ni contraseña actual -> rechazado.
    const unauth = await req(port, 'POST', '/api/auth/password', JSON.stringify({ password: 'Otra__pass__9999' }), {
      'Content-Type': 'application/json'
    });
    expect(unauth.status).toBe(401);

    // La contraseña original sigue siendo válida (no fue sobrescrita).
    const stillOriginal = await req(port, 'POST', '/api/auth/login', JSON.stringify({ password: 'S3gura__pass__123' }), {
      'Content-Type': 'application/json'
    });
    expect(stillOriginal.status).toBe(200);

    // Cambio con la contraseña actual -> permitido.
    const withCurrent = await req(port, 'POST', '/api/auth/password', JSON.stringify({
      password: 'Otra__pass__9999',
      currentPassword: 'S3gura__pass__123'
    }), { 'Content-Type': 'application/json' });
    expect(withCurrent.status).toBe(200);

    // Cambio con token de API -> permitido.
    const withToken = await req(port, 'POST', '/api/auth/password', JSON.stringify({ password: 'Tercera__pass__777' }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(withToken.status).toBe(200);
  });

  test('auth endpoints enforce zod validation', async () => {
    const badSetPwd = await req(port, 'POST', '/api/auth/password', JSON.stringify({ password: 'short' }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(badSetPwd.status).toBe(400);
    expect(JSON.parse(badSetPwd.body).error).toBe('validation');

    const badLogin = await req(port, 'POST', '/api/auth/login', JSON.stringify({ password: '' }), {
      'Content-Type': 'application/json'
    });
    expect(badLogin.status).toBe(400);
    expect(JSON.parse(badLogin.body).error).toBe('validation');
  });

  test('stores auth secrets encrypted at rest', async () => {
    const setPwd = await req(port, 'POST', '/api/auth/password', JSON.stringify({ password: 'S3gura__pass__123' }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(setPwd.status).toBe(200);

    const login = await req(port, 'POST', '/api/auth/login', JSON.stringify({ password: 'S3gura__pass__123' }), {
      'Content-Type': 'application/json'
    });
    expect(login.status).toBe(200);

    const raw = JSON.parse(fs.readFileSync(path.join(tmpDir, 'config.json'), 'utf8'));
    expect(raw.auth).toBeTruthy();
    expect(raw.auth.passwordHash).toMatchObject({ v: 1 });
    expect(raw.auth.sessions).toMatchObject({ v: 1 });
  });

  test('supports configurable failover policy via config', async () => {
    const payload = JSON.stringify({
      vpsTargets: [
        {
          id: 'vps-a',
          name: 'VPS A',
          ip: '10.4.0.1',
          port: 51820,
          pubKey: 'A'.repeat(43) + '=',
          enabled: true,
          priority: 0
        },
        {
          id: 'vps-b',
          name: 'VPS B',
          ip: '10.4.0.2',
          port: 51820,
          pubKey: 'B'.repeat(43) + '=',
          enabled: true,
          priority: 1
        }
      ],
      activeVpsId: 'vps-a',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'C'.repeat(43) + '=',
      publicKey: 'D'.repeat(43) + '=',
      failoverPolicy: {
        activeFailuresRequired: 1,
        candidateSuccessesRequired: 1,
        cooldownMs: 0
      },
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    setNetMock(
      {
        '10.4.0.1:22': 'fail',
        '10.4.0.1:443': 'fail',
        '10.4.0.2:22': 'ok',
        '10.4.0.2:443': 'ok'
      }
    );

    const auto = await req(port, 'POST', '/api/vps/failover', JSON.stringify({}), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(auto.status).toBe(200);
    const body = JSON.parse(auto.body);
    expect(body.switched).toBe(true);
    expect(body.policy).toMatchObject({
      activeFailuresRequired: 1,
      candidateSuccessesRequired: 1,
      cooldownMs: 0
    });
  });

  test('applies strict CSP for SPA routes', async () => {
    const appRes = await req(port, 'GET', '/app/index.html');
    expect(appRes.status).toBe(200);
    const appCsp = String(appRes.headers['content-security-policy'] || '');
    expect(appCsp).toContain("script-src 'self'");
    expect(appCsp).not.toContain("script-src 'self' 'unsafe-inline'");
  });

  test('pubkey challenge verify flow creates CLI session', async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicDerB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

    const add = await req(port, 'POST', '/api/auth/pubkeys', JSON.stringify({
      name: 'cli-test',
      publicKey: publicDerB64
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(add.status).toBe(200);
    const addBody = JSON.parse(add.body);
    expect(addBody.keyId).toBeTruthy();

    const challenge = await req(port, 'POST', '/api/auth/challenge', JSON.stringify({ keyId: addBody.keyId }), {
      'Content-Type': 'application/json'
    });
    expect(challenge.status).toBe(200);
    const challengeBody = JSON.parse(challenge.body);
    expect(challengeBody.challengeId).toBeTruthy();
    const signature = crypto.sign(null, Buffer.from(challengeBody.nonce, 'base64'), privateKey).toString('base64');

    const verify = await req(port, 'POST', '/api/auth/verify', JSON.stringify({
      challengeId: challengeBody.challengeId,
      signature
    }), {
      'Content-Type': 'application/json'
    });
    expect(verify.status).toBe(200);
    const verifyBody = JSON.parse(verify.body);
    expect(verifyBody.sessionToken).toBeTruthy();

    const bySession = await req(port, 'GET', '/api/config', null, {
      Cookie: `mw_session=${verifyBody.sessionToken}`
    });
    expect(bySession.status).toBe(200);
  });

  test('accepts OpenSSH ssh-ed25519 public key format', async () => {
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const der = publicKey.export({ format: 'der', type: 'spki' });
    const rawKey = der.slice(-32);
    const type = Buffer.from('ssh-ed25519', 'utf8');
    const blob = Buffer.concat([
      Buffer.from([0, 0, 0, type.length]),
      type,
      Buffer.from([0, 0, 0, rawKey.length]),
      rawKey
    ]);
    const rawOpenSsh = `ssh-ed25519 ${blob.toString('base64')} openssh-cli@test`;
    const add = await req(port, 'POST', '/api/auth/pubkeys', JSON.stringify({
      name: 'openssh-cli',
      publicKey: rawOpenSsh
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(add.status).toBe(200);
    const body = JSON.parse(add.body);
    expect(body.keyId).toBeTruthy();
  });

  test('rotation prepare and commit flow works', async () => {
    const seedPayload = JSON.stringify({
      vpsIp: '1.2.3.4',
      vpsPort: 51820,
      vpsPubKey: 'A'.repeat(43) + '=',
      domain: 'example.com',
      acmeEmail: 'ops@example.com',
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      services: []
    });
    const saved = await req(port, 'POST', '/api/config', seedPayload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    const prep = await req(port, 'POST', '/api/rotate/prepare', JSON.stringify({
      nextPrivateKey: 'C'.repeat(43) + '=',
      nextPublicKey: 'D'.repeat(43) + '=',
      nextPresharedKey: 'E'.repeat(43) + '='
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(prep.status).toBe(200);
    const prepBody = JSON.parse(prep.body);
    expect(prepBody.planId).toBeTruthy();
    expect(prepBody.scriptSha256).toMatch(/^[a-f0-9]{64}$/);

    const confirm = await req(port, 'POST', '/api/rotate/confirm', JSON.stringify({ planId: prepBody.planId, apply: true }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(confirm.status).toBe(200);
    const confirmBody = JSON.parse(confirm.body);
    expect(confirmBody.applied).toBe(true);
    expect(confirmBody.nextPublicKey).toBeTruthy();
  });

  test('restore rejects backup with config schema violations', async () => {
    const payload = buildBackupPayloadForTest({
      'meta.json': JSON.stringify({ ts: new Date().toISOString(), version: 1 }),
      'config.json': JSON.stringify({
        vpsIp: '999.999.999.999',
        acmeEmail: 'ops@example.com',
        domain: 'example.com'
      })
    }, 'StrongPassphrase__123');

    const restoreBad = await req(port, 'POST', '/api/restore', payload, {
      'Content-Type': 'application/octet-stream',
      'x-backup-passphrase': 'StrongPassphrase__123',
      'x-tunnel-api-token': token
    });
    expect(restoreBad.status).toBe(400);
    const body = JSON.parse(restoreBad.body);
    expect(body.error).toContain('config in backup failed validation');
    expect(Array.isArray(body.issues)).toBe(true);
  });

  test('restore rejects malicious tunnel IP (bash injection vector M4)', async () => {
    const payload = buildBackupPayloadForTest({
      'meta.json': JSON.stringify({ ts: new Date().toISOString(), version: 1 }),
      'config.json': JSON.stringify({
        tunnelClientIp: '10.8.0.2 -j ACCEPT\nrm -rf /',
        domain: 'example.com'
      })
    }, 'StrongPassphrase__123');

    const restoreBad = await req(port, 'POST', '/api/restore', payload, {
      'Content-Type': 'application/octet-stream',
      'x-backup-passphrase': 'StrongPassphrase__123',
      'x-tunnel-api-token': token
    });
    expect(restoreBad.status).toBe(400);
    expect(JSON.parse(restoreBad.body).error).toContain('failed validation');
  });

  test('VPS script generator sanitizes invalid tunnel IPs (M4 defense in depth)', () => {
    const mod = require('../server');
    const script = mod._internals.generateVpsScript(
      {
        publicKey: 'A'.repeat(43) + '=',
        tunnelClientIp: 'evil\nrm -rf /',
        tunnelServerIp: '10.8.0.1'
      },
      { id: 'vps-a', name: 'A', ip: '203.0.113.7', port: 51820 },
      {}
    );
    expect(script).not.toContain('rm -rf');
    expect(script).toContain('WG_CLIENT_IP=10.8.0.2'); // cae al default seguro
  });

  test('returns kill switch script with sha', async () => {
    const r = await req(port, 'GET', '/api/kill-switch/script', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.filename).toBe('miniweed-killswitch.sh');
    expect(body.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(body.script).toContain('wg-quick@wg0');
    expect(body.script).toContain('must run as root');
    expect(body.script).toContain('WG_PORT="${WG_PORT:-51820}"');
    expect(body.script).toContain('iptables -w -C INPUT -p udp --dport "$WG_PORT" -j DROP');
    expect(body.script).toContain('STATUS_FILE="${STATUS_FILE:-/var/run/miniweed.status}"');
  });

  test('returns audit chain verification status', async () => {
    const r = await req(port, 'GET', '/api/audit/verify', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(typeof body.ok).toBe('boolean');
    expect(typeof body.entries).toBe('number');
  });

  test('rejects rotate prepare with only one key', async () => {
    const r = await req(port, 'POST', '/api/rotate/prepare', JSON.stringify({
      nextPrivateKey: 'C'.repeat(43) + '='
    }), {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(400);
    const body = JSON.parse(r.body);
    expect(body.error).toBe('validation');
  });

  test('openapi includes rotate and audit schemas', async () => {
    const r = await req(port, 'GET', '/api/openapi.json', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.components.schemas.RotatePrepareRequest).toBeTruthy();
    expect(body.paths['/api/rotate/{planId}']).toBeTruthy();
    expect(body.paths['/api/audit/verify']).toBeTruthy();
    expect(body.paths['/api/vps/failover']).toBeTruthy();
    expect(body.paths['/api/vps/targets']).toBeTruthy();
    expect(body.paths['/api/vps-setup-script']).toBeTruthy();
    expect(body.components.schemas.VpsFailoverResponse).toBeTruthy();
  });

  test('health internals block forbidden service targets', async () => {
    const mod = require('../server');
    expect(mod._internals.isBlockedServiceTarget('http://127.0.0.1:8080')).toBe(true);
    expect(mod._internals.isBlockedServiceTarget('http://localhost:2019')).toBe(true);
    expect(mod._internals.isBlockedServiceTarget('http://10.0.0.5:8081')).toBe(false);

    const health = await mod._internals.checkServicesHealth([
      { enabled: true, subdomain: 'bad', target: 'http://127.0.0.1:8080' },
      { enabled: true, subdomain: 'ok', target: 'http://10.0.0.5:8081' }
    ]);

    expect(health['bad|http://127.0.0.1:8080']).toEqual({
      ok: false,
      checked: false,
      message: 'Target not allowed'
    });
    expect(health['ok|http://10.0.0.5:8081'].ok).toBe(false);
    expect(health['ok|http://10.0.0.5:8081'].message).toBe('No connection');
  });

  test('isDisallowedTargetIp blocks loopback/metadata but allows RFC1918 (A2)', () => {
    const mod = require('../server');
    const { isDisallowedTargetIp } = mod._internals;
    // Bloqueados: loopback, metadata cloud, link-local, multicast, unspecified.
    expect(isDisallowedTargetIp('127.0.0.1')).toBe(true);
    expect(isDisallowedTargetIp('169.254.169.254')).toBe(true);
    expect(isDisallowedTargetIp('0.0.0.0')).toBe(true);
    expect(isDisallowedTargetIp('224.0.0.1')).toBe(true);
    expect(isDisallowedTargetIp('::1')).toBe(true);
    expect(isDisallowedTargetIp('fe80::1')).toBe(true);
    expect(isDisallowedTargetIp('::ffff:127.0.0.1')).toBe(true);
    // Permitidos: servicios internos legítimos (propósito de la app).
    expect(isDisallowedTargetIp('10.0.0.5')).toBe(false);
    expect(isDisallowedTargetIp('172.18.0.3')).toBe(false);
    expect(isDisallowedTargetIp('192.168.1.10')).toBe(false);
    expect(isDisallowedTargetIp('8.8.8.8')).toBe(false);
  });

  test('probeServiceTarget rejects DNS rebinding to metadata (A2)', async () => {
    const mod = require('../server');
    const dnsMock = require('dns');
    // Un host que resuelve a la IP de metadata cloud debe rechazarse en el probe.
    dnsMock.lookup.mockImplementationOnce((host, opts, cb) => {
      if (typeof opts === 'function') { cb = opts; opts = {}; }
      cb(null, [{ address: '169.254.169.254', family: 4 }]);
    });
    const result = await mod._internals.probeServiceTarget('http://rebind.example.com/');
    expect(result.ok).toBe(false);
    expect(result.error).toBe('Target blocked');
  });

  // ── Caracterización de generadores (red de seguridad para el refactor) ──────

  test('generateWgConf output (con y sin PSK)', () => {
    const mod = require('../server');
    const active = { id: 'a', name: 'A', ip: '203.0.113.1', port: 51820, pubKey: crypto.randomBytes(32).toString('base64') };
    const base = {
      privateKey: crypto.randomBytes(32).toString('base64'),
      tunnelClientIp: '10.8.0.2',
      tunnelServerIp: '10.8.0.1'
    };
    const wg = mod._internals.generateWgConf({ ...base }, active);
    expect(wg).toContain('[Interface]');
    expect(wg).toContain('Address = 10.8.0.2/32');
    expect(wg).toContain('Endpoint = 203.0.113.1:51820');
    expect(wg).toContain('AllowedIPs = 10.8.0.1/32');
    expect(wg).toContain('PersistentKeepalive = 25');
    expect(wg).not.toContain('PresharedKey');

    const psk = crypto.randomBytes(32).toString('base64');
    const wgPsk = mod._internals.generateWgConf({ ...base, presharedKey: psk }, active);
    expect(wgPsk).toContain(`PresharedKey = ${psk}`);

    // Sin clave privada no genera config.
    expect(mod._internals.generateWgConf({ ...base, privateKey: '' }, active)).toBeNull();
  });

  test('generateCaddyfile output (default vs servicios)', () => {
    const mod = require('../server');
    // Config incompleta -> Caddyfile por defecto.
    const def = mod._internals.generateCaddyfile({ services: [] });
    expect(def).toContain(':80');

    const full = mod._internals.generateCaddyfile({
      domain: 'home.example.com',
      acmeEmail: 'ops@example.com',
      services: [
        { enabled: true, subdomain: 'nube', target: 'http://10.0.0.5:8096' },
        { enabled: true, subdomain: 'bad', target: 'http://127.0.0.1:9000' }, // bloqueado (loopback)
        { enabled: false, subdomain: 'off', target: 'http://10.0.0.6:9001' }  // deshabilitado
      ]
    });
    expect(full).toContain('email ops@example.com');
    expect(full).toContain('nube.home.example.com {');
    expect(full).toContain('reverse_proxy http://10.0.0.5:8096');
    // El target loopback y el deshabilitado no aparecen.
    expect(full).not.toContain('127.0.0.1');
    expect(full).not.toContain('10.0.0.6');
  });

  test('backup roundtrip: build -> restore preserva entradas', () => {
    const mod = require('../server');
    const pass = 'StrongPassphrase__123';
    // Materializa config.json en disco (no existe hasta el primer guardado).
    mod._internals.saveConfig(mod._internals.loadConfig());
    const payload = mod._internals.buildBackupPayload(pass, true);
    expect(Buffer.isBuffer(payload)).toBe(true);
    expect(payload.slice(0, 4).toString('utf8')).toBe('MWBK');

    const entries = mod._internals.restoreBackupPayload(payload, pass);
    expect(entries['config.json']).toBeTruthy();
    expect(entries['meta.json']).toBeTruthy();
    expect(JSON.parse(entries['meta.json']).version).toBe(1);
    // El config.json restaurado es JSON válido (cifrado at-rest, pero descifrable).
    expect(() => JSON.parse(entries['config.json'])).not.toThrow();
  });

  test('backup restore rechaza passphrase incorrecta y magic inválido', () => {
    const mod = require('../server');
    const payload = mod._internals.buildBackupPayload('StrongPassphrase__123', true);
    expect(() => mod._internals.restoreBackupPayload(payload, 'otra-passphrase-mala')).toThrow();
    const corrupt = Buffer.concat([Buffer.from('XXXX'), payload.slice(4)]);
    expect(() => mod._internals.restoreBackupPayload(corrupt, 'StrongPassphrase__123')).toThrow();
  });
});
