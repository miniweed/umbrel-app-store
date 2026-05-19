#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

async function httpGetJson(port, pathname, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: pathname,
        method: 'GET',
        headers
      },
      res => {
        let body = '';
        res.on('data', chunk => {
          body += chunk;
        });
        res.on('end', () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(new Error(`GET ${pathname} failed with ${res.statusCode}: ${body}`));
          }
          try {
            resolve(JSON.parse(body));
          } catch (err) {
            reject(new Error(`Invalid JSON from ${pathname}: ${err.message}`));
          }
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

function deriveToken(seed) {
  const token = crypto.hkdfSync(
    'sha256',
    Buffer.from(seed, 'utf8'),
    Buffer.from('miniweed-tunnel/v1', 'utf8'),
    Buffer.from('tunnel-api-token-v1', 'utf8'),
    32
  );
  return Buffer.from(token).toString('base64url');
}

async function main() {
  const rootDir = path.resolve(__dirname, '..');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'miniweed-openapi-'));

  process.env.DATA_DIR = dataDir;
  process.env.APP_SEED = process.env.APP_SEED || 'a'.repeat(64);
  process.env.PORT = '0';

  const token = deriveToken(process.env.APP_SEED);
  const { startServer } = require(path.join(rootDir, 'server.js'));
  const server = startServer();

  await new Promise(resolve => server.on('listening', resolve));
  const port = server.address().port;

  try {
    const spec = await httpGetJson(port, '/api/openapi.json', {
      'x-tunnel-api-token': token
    });
    const outPath = path.join(rootDir, 'api-spec', 'openapi.json');
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, `${JSON.stringify(spec, null, 2)}\n`, 'utf8');
    process.stdout.write(`OpenAPI generated at ${outPath}\n`);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

main().catch(err => {
  process.stderr.write(`${err.message}\n`);
  process.exit(1);
});
