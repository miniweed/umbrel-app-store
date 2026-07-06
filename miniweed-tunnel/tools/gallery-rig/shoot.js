// Captura la galería (1440×900) contra la app corriendo en 127.0.0.1:3125.
// Fase A (estado fresco, "No tunnel"): 02-configuration.
// Fase B (config sembrada + wg "Connected"): 01-instructions, 03-vps-setup, 04-services.
const { chromium } = require('playwright');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const BASE = 'http://127.0.0.1:3125';
const OUT = path.join(__dirname, 'out');
const FLAG = path.join(__dirname, 'wg-connected');
const APP_SEED = process.env.APP_SEED;

const TOKEN = Buffer.from(crypto.hkdfSync(
  'sha256',
  Buffer.from(APP_SEED, 'utf8'),
  Buffer.from('miniweed-tunnel/v1', 'utf8'),
  Buffer.from('tunnel-api-token-v1', 'utf8'),
  32
)).toString('base64url');

function vpsKey() {
  const { publicKey } = crypto.generateKeyPairSync('x25519');
  return publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
}

async function api(method, p, body) {
  const res = await fetch(BASE + p, {
    method,
    headers: { 'Content-Type': 'application/json', 'x-tunnel-api-token': TOKEN },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!res.ok) throw new Error(`${method} ${p} -> ${res.status}: ${await res.text()}`);
  return res.json();
}

async function openTab(page, label) {
  await page.getByRole('tab', { name: label, exact: true }).click();
  await page.waitForTimeout(600);
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });

  // ── Fase A: estado fresco, sin túnel ──
  await page.goto(BASE + '/', { waitUntil: 'networkidle' });
  await page.waitForSelector('.status-badge');
  await openTab(page, 'Configuration');
  await page.screenshot({ path: path.join(OUT, '02-configuration.png') });
  console.log('02-configuration OK');

  // ── Sembrar config vía API (sin toasts en la UI) ──
  const keys = await api('GET', '/api/keygen');
  console.log('keygen pub:', keys.publicKey);
  const saved = await api('POST', '/api/config', {
    vpsIp: '203.0.113.7',
    vpsPort: 51820,
    vpsPubKey: vpsKey(),
    domain: 'mydomain.com',
    acmeEmail: 'you@mydomain.com',
    services: [
      { name: 'Jellyfin', subdomain: 'jellyfin', target: `http://${process.env.LAN_IP}:8096`, enabled: true },
      { name: 'Home Assistant', subdomain: 'home', target: `http://${process.env.LAN_IP}:8123`, enabled: true }
    ]
  });
  console.log('config saved, health:', JSON.stringify(saved.serviceHealth));

  // Túnel "conectado"
  fs.writeFileSync(FLAG, '1');

  // ── Fase B: recarga limpia con estado completo ──
  await page.goto(BASE + '/', { waitUntil: 'networkidle' });
  await page.waitForSelector('.status-badge.connected', { timeout: 15000 });

  await openTab(page, 'Instructions');
  await page.screenshot({ path: path.join(OUT, '01-instructions.png') });
  console.log('01-instructions OK');

  await openTab(page, 'VPS Setup');
  await page.waitForSelector('pre.code-box', { timeout: 15000 });
  await page.screenshot({ path: path.join(OUT, '03-vps-setup.png') });
  console.log('03-vps-setup OK');

  await openTab(page, 'Services');
  await page.waitForSelector('.health-pill.ok', { timeout: 15000 });
  await page.screenshot({ path: path.join(OUT, '04-services.png') });
  console.log('04-services OK');

  await browser.close();
})().catch(err => { console.error(err); process.exit(1); });
