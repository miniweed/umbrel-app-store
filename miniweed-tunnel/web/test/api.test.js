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
    resolve4: jest.fn(async () => ['127.0.0.1']),
    // Proxy peer gate: configurable per test via global.__DNS_LOOKUP_MOCK__.
    // By default the app_proxy hostname does NOT resolve (umbrelOS 2.x scenario,
    // where that container no longer exists) to exercise the gateway-IP branch.
    lookup: jest.fn(async (host, opts) => {
      const mock = global.__DNS_LOOKUP_MOCK__;
      if (mock === 'throw') throw new Error('ENOTFOUND');
      if (Array.isArray(mock)) return mock;
      throw new Error('ENOTFOUND');
    })
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

  test('persists the env seed as a backup and reuses it when APP_SEED disappears', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniweed-web-seedbk-'));
    const prevSeed = process.env.APP_SEED;
    const prevToken = process.env.TUNNEL_API_TOKEN;
    const prevData = process.env.DATA_DIR;
    const prevPort = process.env.PORT;
    const envSeed = 'e'.repeat(64);
    const seedPath = path.join(tempDir, 'app-seed');

    process.env.DATA_DIR = tempDir;
    process.env.PORT = '0';
    delete process.env.TUNNEL_API_TOKEN;

    process.env.APP_SEED = envSeed;
    jest.resetModules();
    const mod = require('../server');
    const s1 = mod.startServer();
    await new Promise(resolve => s1.on('listening', resolve));
    await new Promise(resolve => s1.close(resolve));
    if (typeof mod.stopBackgroundTimers === 'function') mod.stopBackgroundTimers();
    expect(String(fs.readFileSync(seedPath, 'utf8')).trim()).toBe(envSeed);

    // A later umbrelOS stops exporting APP_SEED: the backup keeps the app on
    // the same seed instead of generating a new one (which would make the
    // encrypted config unreadable).
    delete process.env.APP_SEED;
    jest.resetModules();
    const mod2 = require('../server');
    const s2 = mod2.startServer();
    await new Promise(resolve => s2.on('listening', resolve));
    await new Promise(resolve => s2.close(resolve));
    if (typeof mod2.stopBackgroundTimers === 'function') mod2.stopBackgroundTimers();
    expect(process.env.APP_SEED).toBe(envSeed);

    if (prevSeed === undefined) delete process.env.APP_SEED; else process.env.APP_SEED = prevSeed;
    if (prevToken === undefined) delete process.env.TUNNEL_API_TOKEN; else process.env.TUNNEL_API_TOKEN = prevToken;
    if (prevData === undefined) delete process.env.DATA_DIR; else process.env.DATA_DIR = prevData;
    if (prevPort === undefined) delete process.env.PORT; else process.env.PORT = prevPort;
    jest.resetModules();
  });

  test('keeps the backup seed when APP_SEED changes and no longer decrypts the config', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniweed-web-seedrot-'));
    const prevSeed = process.env.APP_SEED;
    const prevToken = process.env.TUNNEL_API_TOKEN;
    const prevData = process.env.DATA_DIR;
    const prevPort = process.env.PORT;
    const oldSeed = 'o'.repeat(64);
    const newSeed = 'n'.repeat(64);
    const seedPath = path.join(tempDir, 'app-seed');
    const configPath = path.join(tempDir, 'config.json');

    process.env.DATA_DIR = tempDir;
    process.env.PORT = '0';
    delete process.env.TUNNEL_API_TOKEN;

    // Config encrypted with the seed in use today, plus the backup 1.7.0 writes.
    process.env.APP_SEED = oldSeed;
    jest.resetModules();
    const box = require('../lib/cryptobox');
    box.__resetForTest();
    fs.writeFileSync(configPath, JSON.stringify({
      _encVersion: 1,
      domain: 'example.com',
      privateKey: box.seal('SECRET-PRIVATE-KEY')
    }));
    fs.writeFileSync(seedPath, `${oldSeed}\n`, { mode: 0o600 });

    // A later umbrelOS exports a differently derived APP_SEED.
    process.env.APP_SEED = newSeed;
    jest.resetModules();
    // The fallback warns on stderr by design; keep the test output clean.
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const mod = require('../server');
    const server = mod.startServer();
    await new Promise(resolve => server.on('listening', resolve));

    // The backup wins and is NOT overwritten, so the config still decrypts.
    expect(process.env.APP_SEED).toBe(oldSeed);
    expect(String(fs.readFileSync(seedPath, 'utf8')).trim()).toBe(oldSeed);
    expect(mod._internals.loadConfig().privateKey).toBe('SECRET-PRIVATE-KEY');

    await new Promise(resolve => server.close(resolve));
    if (typeof mod.stopBackgroundTimers === 'function') mod.stopBackgroundTimers();
    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining('persisted seed backup'));
    errSpy.mockRestore();

    if (prevSeed === undefined) delete process.env.APP_SEED; else process.env.APP_SEED = prevSeed;
    if (prevToken === undefined) delete process.env.TUNNEL_API_TOKEN; else process.env.TUNNEL_API_TOKEN = prevToken;
    if (prevData === undefined) delete process.env.DATA_DIR; else process.env.DATA_DIR = prevData;
    if (prevPort === undefined) delete process.env.PORT; else process.env.PORT = prevPort;
    jest.resetModules();
  }, 60000);

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
    // Allowed: legitimate internal services (the app's purpose).
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

  // ── Generator characterization (safety net for the refactor) ──────────────

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

    // Without a private key it doesn't generate config.
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
    __setProxyPeersForTest([], 0); // empty, expired cache: fail-closed
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

  // ── peer gate dual: umbrelOS 2.x (AppGateway en el host) ───────────────────

  test('readDefaultGatewayIps parses /proc/net/route gateway (hex LE) or returns empty set', () => {
    const mod = require('../server');
    const { readDefaultGatewayIps } = mod._internals;
    const ips = readDefaultGatewayIps();
    expect(ips instanceof Set).toBe(true);
    for (const ip of ips) {
      expect(ip).toMatch(/^\d{1,3}(\.\d{1,3}){3}$/);
    }
  });

  test('proxy peer gate admits the container default gateway (umbrelOS 2.x host gateway)', async () => {
    const mod = require('../server');
    const { proxyPeerGate, __setProxyPeersForTest } = mod._internals;
    // On 2.x the AppGateway runs on the host: requests arrive from the gateway
    // IP. We simulate that resolveProxyPeers already added it to the set.
    __setProxyPeersForTest(['10.21.0.1']);
    const res = {
      statusCode: 0,
      status(code) { this.statusCode = code; return this; },
      json() { return this; }
    };
    let nexted = false;
    await proxyPeerGate({ socket: { remoteAddress: '::ffff:10.21.0.1' } }, res, () => { nexted = true; });
    expect(nexted).toBe(true);
    expect(res.statusCode).not.toBe(403);
  });

  test('proxy peer gate still 403s arbitrary container peers on 2.x', async () => {
    const mod = require('../server');
    const { proxyPeerGate, __setProxyPeersForTest } = mod._internals;
    // Gateway admitted, but another app on the shared network is not.
    __setProxyPeersForTest(['10.21.0.1']);
    const res = {
      statusCode: 0,
      status(code) { this.statusCode = code; return this; },
      json() { return this; }
    };
    let nexted = false;
    await proxyPeerGate({ socket: { remoteAddress: '::ffff:10.21.0.222' } }, res, () => { nexted = true; });
    expect(nexted).toBe(false);
    expect(res.statusCode).toBe(403);
  });

  test('proxy peer gate admits resolved app_proxy IP on 1.x', async () => {
    const mod = require('../server');
    const { proxyPeerGate, __setProxyPeersForTest } = mod._internals;
    __setProxyPeersForTest(['172.18.0.9']);
    const res = {
      statusCode: 0,
      status(code) { this.statusCode = code; return this; },
      json() { return this; }
    };
    let nexted = false;
    await proxyPeerGate({ socket: { remoteAddress: '::ffff:172.18.0.9' } }, res, () => { nexted = true; });
    expect(nexted).toBe(true);
  });

  test('proxy peers resolver unions gateway IPs with DNS results and is fail-closed', async () => {
    const mod = require('../server');
    const { readDefaultGatewayIps, resolveProxyPeers, __setProxyPeersForTest } = mod._internals;
    const gateways = readDefaultGatewayIps();
    // Force expiry and real re-resolution (DNS fails, gateways must come in).
    __setProxyPeersForTest([], 0);
    const peers = await resolveProxyPeers(true);
    // System-read gateways (if any) are part of the valid peers.
    for (const gw of gateways) {
      expect(peers.has(gw)).toBe(true);
    }
  });

  test('proxy peers resolver never inherits stale IPs from previous resolutions', async () => {
    const mod = require('../server');
    const { proxyPeerGate, resolveProxyPeers, __setProxyPeersForTest } = mod._internals;
    // Cache "poisoned" with the app_proxy's old IP (Docker will recycle it to
    // another app). On expiry, re-resolution must NOT inherit it.
    __setProxyPeersForTest(['172.18.0.55'], 0);
    global.__DNS_LOOKUP_MOCK__ = [{ address: '172.18.0.9', family: 4 }];
    const peers = await resolveProxyPeers(true);
    expect(peers.has('172.18.0.55')).toBe(false);
    expect(peers.has('172.18.0.9')).toBe(true);
    // And the gate rejects the recycled IP even though it was once legitimate.
    const res = {
      statusCode: 0,
      status(code) { this.statusCode = code; return this; },
      json() { return this; }
    };
    let nexted = false;
    await proxyPeerGate({ socket: { remoteAddress: '::ffff:172.18.0.55' } }, res, () => { nexted = true; });
    expect(nexted).toBe(false);
    expect(res.statusCode).toBe(403);
    delete global.__DNS_LOOKUP_MOCK__;
  });

  // ── host gateway on umbrelOS 1.x: widget only ──────────────────────────────

  function fakeRes() {
    return {
      statusCode: 0,
      status(code) { this.statusCode = code; return this; },
      json() { return this; }
    };
  }

  test('1.x (app_proxy seen): host gateway may only fetch the widget, never the UI or API', async () => {
    const mod = require('../server');
    const { proxyPeerGate, __setProxyPeersForTest, __setAppProxySeenForTest } = mod._internals;
    __setProxyPeersForTest(['172.18.0.9'], Date.now(), ['10.21.0.1']);
    __setAppProxySeenForTest(true);
    try {
      const fromHost = (method, reqPath) => ({ method, path: reqPath, socket: { remoteAddress: '::ffff:10.21.0.1' } });
      // A network_mode: host container shares the host's bridge IP: it must not
      // get the admin cookie from `/` nor reach the API.
      let res = fakeRes(); let nexted = false;
      await proxyPeerGate(fromHost('GET', '/'), res, () => { nexted = true; });
      expect(nexted).toBe(false); expect(res.statusCode).toBe(403);

      res = fakeRes(); nexted = false;
      await proxyPeerGate(fromHost('POST', '/api/config'), res, () => { nexted = true; });
      expect(nexted).toBe(false); expect(res.statusCode).toBe(403);

      // umbreld's server-side widget fetch is the one legitimate host request.
      res = fakeRes(); nexted = false;
      await proxyPeerGate(fromHost('GET', '/api/widget'), res, () => { nexted = true; });
      expect(nexted).toBe(true); expect(res.statusCode).not.toBe(403);

      // The UI keeps arriving through app_proxy, unaffected.
      res = fakeRes(); nexted = false;
      await proxyPeerGate({ method: 'GET', path: '/', socket: { remoteAddress: '::ffff:172.18.0.9' } }, res, () => { nexted = true; });
      expect(nexted).toBe(true);
    } finally {
      __setAppProxySeenForTest(false);
    }
  });

  test('2.x (app_proxy never seen): host gateway is the AppGateway and is trusted for everything', async () => {
    const mod = require('../server');
    const { proxyPeerGate, __setProxyPeersForTest, __setAppProxySeenForTest } = mod._internals;
    __setProxyPeersForTest([], Date.now(), ['10.21.0.1']);
    __setAppProxySeenForTest(false);
    const res = fakeRes(); let nexted = false;
    await proxyPeerGate({ method: 'GET', path: '/', socket: { remoteAddress: '::ffff:10.21.0.1' } }, res, () => { nexted = true; });
    expect(nexted).toBe(true);
  });

  test('app_proxy marker is sticky: a later DNS failure does not downgrade the gate to 2.x mode', async () => {
    const mod = require('../server');
    const { resolveProxyPeers, __setProxyPeersForTest, __setAppProxySeenForTest, __getAppProxySeenForTest } = mod._internals;
    __setAppProxySeenForTest(false);
    try {
      __setProxyPeersForTest([], 0);
      global.__DNS_LOOKUP_MOCK__ = [{ address: '172.18.0.9', family: 4 }];
      await resolveProxyPeers(true);
      expect(__getAppProxySeenForTest()).toBe(true);
      // app_proxy restarting / transient DNS failure: the marker must survive.
      __setProxyPeersForTest([], 0);
      global.__DNS_LOOKUP_MOCK__ = 'throw';
      const peers = await resolveProxyPeers(true);
      expect(peers.has('172.18.0.9')).toBe(false);
      expect(__getAppProxySeenForTest()).toBe(true);
    } finally {
      delete global.__DNS_LOOKUP_MOCK__;
      __setAppProxySeenForTest(false);
    }
  });

  test('GET /api/config masks the preshared key and "••••" keeps it on POST', async () => {
    const auth = { 'Content-Type': 'application/json', 'x-tunnel-api-token': token };
    const psk = 'C'.repeat(43) + '=';
    await req(port, 'POST', '/api/config', JSON.stringify({
      privateKey: 'A'.repeat(43) + '=',
      publicKey: 'B'.repeat(43) + '=',
      presharedKey: psk,
      services: []
    }), auth);
    let r = await req(port, 'GET', '/api/config', null, auth);
    expect(r.status).toBe(200);
    expect(r.body).not.toContain(psk);
    expect(JSON.parse(r.body).presharedKey).toBe('••••');
    // Round-tripping the masked value must not wipe the stored key.
    await req(port, 'POST', '/api/config', JSON.stringify({ presharedKey: '••••', services: [] }), auth);
    r = await req(port, 'GET', '/api/config', null, auth);
    expect(JSON.parse(r.body).presharedKey).toBe('••••');
    const cfg = JSON.parse(fs.readFileSync(path.join(tmpDir, 'config.json'), 'utf8'));
    expect(typeof cfg.presharedKey).toBe('object'); // sealed blob, still present
  });

  // ── widget (umbrelOS 2.x) ───────────────────────────────────────────────────

  test('widget endpoint is unauthenticated and never leaks secrets', async () => {
    const r = await req(port, 'GET', '/api/widget');
    expect(r.status).toBe(200);
    const body = JSON.parse(r.body);
    expect(body.type).toBe('three-stats');
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items.length).toBe(3);
    // No secretos ni material sensible en el widget.
    const raw = r.body;
    expect(raw).not.toContain('privateKey');
    expect(raw).not.toContain('presharedKey');
    expect(raw).not.toContain(token);
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
    // The /data root must no longer contain wg0.conf: the wg container only
    // mounts the wg/ subdir.
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

  // ── Security-audit regressions ────────────────────────────────────────────

  test('v0->v1 migration encrypts and removes the plaintext backup (M1)', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniweed-web-cfgmig-'));
    const prevData = process.env.DATA_DIR;
    const prevPort = process.env.PORT;

    const plainKey = 'A'.repeat(43) + '=';
    fs.writeFileSync(path.join(tempDir, 'config.json'), JSON.stringify({
      privateKey: plainKey,
      domain: 'example.com',
      acmeEmail: 'ops@example.com'
    }), { mode: 0o600 });
    process.env.DATA_DIR = tempDir;
    process.env.PORT = '0';

    jest.resetModules();
    const mod = require('../server');
    const s1 = mod.startServer();
    await new Promise(resolve => s1.on('listening', resolve));
    await new Promise(resolve => s1.close(resolve));
    if (typeof mod.stopBackgroundTimers === 'function') mod.stopBackgroundTimers();

    // No plaintext backup left and config migrated to encrypted v1.
    expect(fs.existsSync(path.join(tempDir, 'config.json.v0.bak'))).toBe(false);
    const migrated = JSON.parse(fs.readFileSync(path.join(tempDir, 'config.json'), 'utf8'));
    expect(migrated._encVersion).toBe(1);
    expect(typeof migrated.privateKey).toBe('object'); // sealed {v,n,c,t}
    expect(JSON.stringify(migrated)).not.toContain(plainKey);

    if (prevData === undefined) delete process.env.DATA_DIR; else process.env.DATA_DIR = prevData;
    if (prevPort === undefined) delete process.env.PORT; else process.env.PORT = prevPort;
    jest.resetModules();
  });

  test('audit log registra la IP de socket real, no X-Forwarded-For (M3)', async () => {
    const r = await req(port, 'GET', '/api/config', null, { 'X-Forwarded-For': '6.6.6.6' });
    expect(r.status).toBe(401); // 401 != 200: queda registrado en audit
    const lines = fs.readFileSync(path.join(tmpDir, 'audit.log'), 'utf8').trim().split('\n').map(JSON.parse);
    const entry = lines.find(e => e.path === '/api/config' && e.status === 401);
    expect(entry).toBeTruthy();
    expect(entry.ip).not.toBe('6.6.6.6');
    expect(['127.0.0.1', '::1', '::ffff:127.0.0.1']).toContain(entry.ip);
  });

  test('GET /index.html sirve la SPA: la UI legacy fue eliminada (B1)', async () => {
    const r = await req(port, 'GET', '/index.html');
    expect(r.status).toBe(200);
    expect(r.body).toContain('id="app"');
    expect(r.body).not.toContain('__TUNNEL_API_TOKEN__');
  });

  test('generators sanitize invalid WireGuard keys (B2 defense in depth)', () => {
    const mod = require('../server');
    const valid = 'A'.repeat(43) + '=';
    const target = { id: 'vps-a', name: 'A', ip: '203.0.113.7', port: 51820 };

    // Invalid PSK -> omitted; never interpolated into the bash run as root.
    const script = mod._internals.generateVpsScript(
      { publicKey: valid, presharedKey: 'evil\nrm -rf /', tunnelClientIp: '10.8.0.2', tunnelServerIp: '10.8.0.1' },
      target
    );
    expect(script).not.toContain('rm -rf');
    expect(script).not.toContain('PresharedKey = evil');

    // Invalid public key -> fail-closed (no broken script is generated).
    expect(() => mod._internals.generateVpsScript({ publicKey: 'evil; rm -rf /' }, target)).toThrow();

    // wg0.conf: invalid keys -> null; invalid PSK -> line omitted.
    const active = { ...target, pubKey: valid };
    expect(mod._internals.generateWgConf(
      { privateKey: 'evil\nrm -rf /', tunnelClientIp: '10.8.0.2', tunnelServerIp: '10.8.0.1' },
      active
    )).toBeNull();
    expect(mod._internals.generateWgConf(
      { privateKey: valid, tunnelClientIp: '10.8.0.2', tunnelServerIp: '10.8.0.1' },
      { ...active, pubKey: 'evil; rm -rf /' }
    )).toBeNull();
    const conf = mod._internals.generateWgConf(
      { privateKey: valid, presharedKey: 'evil;rm -rf /', tunnelClientIp: '10.8.0.2', tunnelServerIp: '10.8.0.1' },
      active
    );
    expect(conf).not.toBeNull();
    expect(conf).not.toContain('PresharedKey');
  });

  test('keepAliveTimeout es finito y headersTimeout lo supera (B3)', () => {
    expect(server.keepAliveTimeout).toBe(75_000);
    expect(server.headersTimeout).toBeGreaterThan(server.keepAliveTimeout);
  });

  test('JSON malformado responde 400, no 500 (B4)', async () => {
    const r = await req(port, 'POST', '/api/config', '{not-json', {
      'Content-Type': 'application/json',
      'x-tunnel-api-token': token
    });
    expect(r.status).toBe(400);
    expect(JSON.parse(r.body).error).toBe('Bad request');
  });

});
