// wg-api simulado para capturas: /keygen devuelve claves X25519 válidas,
// /status es conmutable con el archivo ./wg-connected (existe => connected).
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const FLAG = path.join(__dirname, 'wg-connected');

function rawKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  const priv = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64');
  return { pub, priv };
}

const fixed = rawKeyPair();

http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  if (req.url === '/keygen') {
    const psk = crypto.randomBytes(32).toString('base64');
    res.end(JSON.stringify({ privateKey: fixed.priv, publicKey: fixed.pub, presharedKey: psk }));
    return;
  }
  if (req.url === '/status') {
    const connected = fs.existsSync(FLAG);
    const fp = crypto.createHash('sha256').update(Buffer.from(fixed.pub, 'base64')).digest().subarray(0, 16);
    const fingerprint = [...fp].map(b => b.toString(16).padStart(2, '0')).join(':');
    if (connected) {
      res.end(JSON.stringify({
        connected: true,
        raw: `interface: wg0\n  public key: ${fixed.pub}\n  listening port: 51820\n\npeer: 8Kp2mVYt7cQwJvN4xR1sD6bZgHfL3nWqPuT9aEiC5kM=\n  endpoint: 203.0.113.7:51820\n  allowed ips: 10.8.0.1/32\n  latest handshake: 42 seconds ago\n  transfer: 1.24 GiB received, 3.87 GiB sent\n  persistent keepalive: every 25 seconds`,
        peerCount: 1,
        handshakedPeers: 1,
        lastHandshakeAgeSec: 42,
        publicKey: fixed.pub,
        publicKeyFingerprint: fingerprint
      }));
    } else {
      res.end(JSON.stringify({ connected: false, raw: 'interface wg0 not up yet', peerCount: 0, handshakedPeers: 0, lastHandshakeAgeSec: null, publicKey: '', publicKeyFingerprint: '' }));
    }
    return;
  }
  res.statusCode = 404;
  res.end(JSON.stringify({ error: 'not found' }));
}).listen(8080, '127.0.0.1', () => console.log('[fake-wg] :8080, pub=' + fixed.pub));
