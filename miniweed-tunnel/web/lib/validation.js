// Helpers de validación puros, extraídos de server.js para reducir el monolito.
// Sin estado ni I/O (salvo crypto para huellas). validateEmailWithMx permanece en
// server.js por su dependencia de DNS.
const crypto = require('crypto');

function isWireGuardKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) return false;
  try {
    return Buffer.from(value, 'base64').length === 32;
  } catch {
    return false;
  }
}

function keyFingerprint(key) {
  if (!isWireGuardKey(key)) return '';
  const raw = Buffer.from(key, 'base64');
  const hash = crypto.createHash('sha256').update(raw).digest();
  return hash.slice(0, 16).toString('hex').match(/.{2}/g).join(':');
}

function isHostname(value) {
  if (typeof value !== 'string' || value.length > 253) return false;
  const labels = value.split('.');
  if (labels.length < 2) return false;
  return labels.every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label));
}

function isSubdomain(value) {
  if (!value) return true;
  return typeof value === 'string' && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(value);
}

function isEmail(value) {
  return !value || (typeof value === 'string' && /^[^\s@{}]+@[^\s@{}]+\.[^\s@{}]+$/.test(value));
}

function isValidIpv4(value) {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return false;
  }
  return true;
}

// Saneador defensivo: estas IPs se interpolan en bash/iptables/wg0.conf que corre
// como root en el VPS. Si el valor no es IPv4 estricta (p. ej. inyectado vía restore),
// se cae al valor por defecto seguro en lugar de propagar la cadena.
function safeTunnelIp(value, fallback) {
  return isValidIpv4(value) ? value : fallback;
}

function isTargetUrl(value) {
  try {
    const url = new URL(value);
    const hasPath = url.pathname && url.pathname !== '/';
    const hasQuery = Boolean(url.search);
    const hasHash = Boolean(url.hash);
    return ['http:', 'https:'].includes(url.protocol)
      && !/[\r\n{}]/.test(value)
      && !hasPath
      && !hasQuery
      && !hasHash;
  } catch {
    return false;
  }
}

function normalizeTargetUrl(value) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    if (!['http:', 'https:'].includes(parsed.protocol)) return '';
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return '';
  }
}

// ¿IP (v4/v6) que NO debe sondearse aunque la app exponga servicios internos?
// Bloquea loopback, unspecified, link-local / metadata cloud (169.254.x, incl.
// 169.254.169.254) y multicast. PERMITE rangos RFC1918 (10/172.16/192.168) y
// ULA IPv6, porque exponer servicios internos de la red es el propósito de la app.
function isDisallowedTargetIp(ip) {
  if (typeof ip !== 'string' || !ip) return true; // ante la duda, bloquear
  let addr = ip.trim().toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];

  // IPv6 con IPv4 mapeada (::ffff:1.2.3.4) -> validar la parte IPv4
  const mapped = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) addr = mapped[1];

  if (addr.includes(':')) {
    if (addr === '::' || addr === '::1') return true;   // unspecified / loopback
    if (/^fe[89ab]/.test(addr)) return true;            // link-local fe80::/10
    if (addr.startsWith('ff')) return true;             // multicast
    return false;
  }

  const parts = addr.split('.');
  if (parts.length !== 4) return true;
  const o = parts.map(p => Number(p));
  if (o.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = o;
  if (a === 0) return true;                  // 0.0.0.0/8
  if (a === 127) return true;                // loopback
  if (a === 169 && b === 254) return true;   // link-local + metadata cloud
  if (a >= 224) return true;                 // multicast / reservado
  return false;
}

function isBlockedServiceTarget(value) {
  try {
    const parsed = new URL(value);
    const host = parsed.hostname.toLowerCase();
    const port = Number.parseInt(parsed.port || (parsed.protocol === 'https:' ? '443' : '80'), 10);

    if (host === 'localhost') return true;
    // Si el host es una IP literal, bloquear loopback/link-local/metadata.
    const literal = host.replace(/^\[|\]$/g, '');
    if (/^[0-9.]+$/.test(literal) || literal.includes(':')) {
      if (isDisallowedTargetIp(literal)) return true;
    }

    const blockedPorts = new Set([2019, 8080, 2375, 2376]);
    if (blockedPorts.has(port)) return true;

    return false;
  } catch {
    return true;
  }
}

module.exports = {
  isWireGuardKey,
  keyFingerprint,
  isHostname,
  isSubdomain,
  isEmail,
  isValidIpv4,
  safeTunnelIp,
  isTargetUrl,
  normalizeTargetUrl,
  isDisallowedTargetIp,
  isBlockedServiceTarget
};
