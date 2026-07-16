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

  test('generates the VPS script before the VPS public key is known', async () => {
    // The VPS public key is only obtained after running the script, so the script
    // must be generatable with just the IP + Umbrel keys (no vpsPubKey yet).
    const payload = JSON.stringify({
      vpsIp: '1.2.3.4',
      vpsPort: 51820,
      vpsPubKey: '',
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
    expect(JSON.parse(r.body).script).toContain('#!/bin/bash');
  });

  test('setup script never installs remote code (no crowdsec / curl|sh)', async () => {
    const payload = JSON.stringify({
      vpsIp: '12.12.12.12',
      vpsPort: 51820,
      vpsPubKey: 'A'.repeat(43) + '=',
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

    // The withCrowdsec query param is ignored now; the script must be apt-only.
    const r = await req(port, 'GET', '/api/vps-setup-script?withCrowdsec=1', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.script).not.toMatch(/crowdsec/i);
    expect(body.script).not.toContain('| sh');
    expect(body.script).not.toContain('curl -fsSL');
    expect(body.vps.ip).toBe('12.12.12.12');
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

  test('applies strict CSP for SPA routes', async () => {
    const appRes = await req(port, 'GET', '/app/index.html');
    expect(appRes.status).toBe(200);
    const appCsp = String(appRes.headers['content-security-policy'] || '');
    expect(appCsp).toContain("script-src 'self'");
    expect(appCsp).not.toContain("script-src 'self' 'unsafe-inline'");
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

  test('returns audit chain verification status', async () => {
    const r = await req(port, 'GET', '/api/audit/verify', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(typeof body.ok).toBe('boolean');
    expect(typeof body.entries).toBe('number');
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

  // ── proxy peer gate (fix del bootstrap de cookie reportado por nmfretz) ─────

  test('proxy peer gate rejects direct container peers with 403', async () => {
    const mod = require('../server');
    const { proxyPeerGate, __setProxyPeersForTest } = mod._internals;
    __setProxyPeersForTest([], 0); // caché vacía y expirada: fail-closed
    const res = {
      statusCode: 0,
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; }
    };
    let nexted = false;
    await proxyPeerGate({ socket: { remoteAddress: '::ffff:172.18.0.7' } }, res, () => { nexted = true; });
    expect(nexted).toBe(false);
    expect(res.statusCode).toBe(403);
  });

  test('proxy peer gate allows the app_proxy peer and loopback', async () => {
    const mod = require('../server');
    const { proxyPeerGate, __setProxyPeersForTest } = mod._internals;
    __setProxyPeersForTest(['172.18.0.9']);
    let nexted = 0;
    const res = { status() { return this; }, json() { return this; } };
    await proxyPeerGate({ socket: { remoteAddress: '::ffff:172.18.0.9' } }, res, () => { nexted += 1; });
    await proxyPeerGate({ socket: { remoteAddress: '::1' } }, res, () => { nexted += 1; });
    await proxyPeerGate({ socket: { remoteAddress: '127.0.0.1' } }, res, () => { nexted += 1; });
    expect(nexted).toBe(3);
  });

  test('status and health endpoints require auth', async () => {
    const anonStatus = await req(port, 'GET', '/api/status');
    expect(anonStatus.status).toBe(401);
    const anonHealth = await req(port, 'GET', '/api/health');
    expect(anonHealth.status).toBe(401);
    const authedHealth = await req(port, 'GET', '/api/health', null, {
      'x-tunnel-api-token': token
    });
    expect(authedHealth.status).toBe(200);
  });

  test('audit endpoint tolerates corrupted log lines', async () => {
    const payload = JSON.stringify({
      vpsIp: '1.2.3.4',
      domain: 'example.com',
      acmeEmail: 'ops@example.com'
    });
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);

    fs.appendFileSync(path.join(tmpDir, 'audit.log'), '{corrupted-line\n');
    const r = await req(port, 'GET', '/api/audit', null, {
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(Array.isArray(body.entries)).toBe(true);
    expect(body.entries.length).toBeGreaterThan(0);
  });

  test('wg0.conf is written with 0600 permissions', async () => {
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
    const saved = await req(port, 'POST', '/api/config', payload, {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(saved.status).toBe(200);
    const st = fs.statSync(path.join(tmpDir, 'wg', 'wg0.conf'));
    expect(st.mode & 0o777).toBe(0o600);
    // La raíz de /data ya no debe contener wg0.conf: el contenedor wg solo
    // monta el subdir wg/.
    expect(fs.existsSync(path.join(tmpDir, 'wg0.conf'))).toBe(false);
  });

  test('migrates legacy wg0.conf from DATA_DIR root into wg/ on boot', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniweed-web-wgmig-'));
    const prevData = process.env.DATA_DIR;
    const prevPort = process.env.PORT;

    fs.writeFileSync(path.join(tempDir, 'wg0.conf'), '[Interface]\n', { mode: 0o600 });
    process.env.DATA_DIR = tempDir;
    process.env.PORT = '0';

    jest.resetModules();
    const mod = require('../server');
    const s1 = mod.startServer();
    await new Promise(resolve => s1.on('listening', resolve));
    await new Promise(resolve => s1.close(resolve));
    if (typeof mod.stopBackgroundTimers === 'function') mod.stopBackgroundTimers();

    expect(fs.existsSync(path.join(tempDir, 'wg0.conf'))).toBe(false);
    const migrated = path.join(tempDir, 'wg', 'wg0.conf');
    expect(fs.existsSync(migrated)).toBe(true);
    expect(String(fs.readFileSync(migrated, 'utf8'))).toBe('[Interface]\n');
    expect(fs.statSync(migrated).mode & 0o777).toBe(0o600);

    if (prevData === undefined) delete process.env.DATA_DIR; else process.env.DATA_DIR = prevData;
    if (prevPort === undefined) delete process.env.PORT; else process.env.PORT = prevPort;
  });

  test('removes stale legacy wg0.conf when the new path already exists', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniweed-web-wgmig2-'));
    const prevData = process.env.DATA_DIR;
    const prevPort = process.env.PORT;

    fs.mkdirSync(path.join(tempDir, 'wg'), { recursive: true });
    fs.writeFileSync(path.join(tempDir, 'wg', 'wg0.conf'), '[Interface]\n# new\n', { mode: 0o600 });
    fs.writeFileSync(path.join(tempDir, 'wg0.conf'), '[Interface]\n# old\n', { mode: 0o600 });
    process.env.DATA_DIR = tempDir;
    process.env.PORT = '0';

    jest.resetModules();
    const mod = require('../server');
    const s1 = mod.startServer();
    await new Promise(resolve => s1.on('listening', resolve));
    await new Promise(resolve => s1.close(resolve));
    if (typeof mod.stopBackgroundTimers === 'function') mod.stopBackgroundTimers();

    expect(fs.existsSync(path.join(tempDir, 'wg0.conf'))).toBe(false);
    expect(String(fs.readFileSync(path.join(tempDir, 'wg', 'wg0.conf'), 'utf8'))).toBe('[Interface]\n# new\n');

    if (prevData === undefined) delete process.env.DATA_DIR; else process.env.DATA_DIR = prevData;
    if (prevPort === undefined) delete process.env.PORT; else process.env.PORT = prevPort;
  });

});
