const DEFAULT_TIMEOUT_MS = 10_000;

export async function apiFetch(pathname, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
  try {
    const response = await fetch(pathname, {
      credentials: 'same-origin',
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {})
      }
    });
    return response;
  } finally {
    clearTimeout(timeout);
  }
}

async function parseJson(response) {
  const payload = await response.json().catch(() => ({}));
  return payload;
}

export async function requestJson(pathname, options = {}) {
  const response = await apiFetch(pathname, options);
  const payload = await parseJson(response);
  if (!response.ok) {
    const message = payload.error || payload.message || `Request failed (${response.status})`;
    const error = new Error(message);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

export function getJson(pathname) {
  return requestJson(pathname, { method: 'GET' });
}

export function getConfig() {
  return getJson('/api/config');
}

export function saveConfig(payload) {
  return requestJson('/api/config', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

export function getStatus() {
  return getJson('/api/status');
}

export function keygen() {
  return getJson('/api/keygen');
}

export function getVpsTargets() {
  return getJson('/api/vps/targets');
}

export function triggerFailover(targetId = '') {
  return requestJson('/api/vps/failover', {
    method: 'POST',
    body: JSON.stringify(targetId ? { targetId } : {})
  });
}

export function getVpsSetupScript({ vpsId = '', withCrowdsec = false } = {}) {
  const qs = new URLSearchParams();
  if (vpsId) qs.set('vpsId', vpsId);
  if (withCrowdsec) qs.set('withCrowdsec', '1');
  const suffix = qs.toString();
  return getJson(`/api/vps-setup-script${suffix ? `?${suffix}` : ''}`);
}

export function setUiPassword(password) {
  return requestJson('/api/auth/password', {
    method: 'POST',
    body: JSON.stringify({ password })
  });
}

export function login(password) {
  return requestJson('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ password })
  });
}

export function logout() {
  return requestJson('/api/auth/logout', { method: 'POST' });
}

export function getAuthPubkeys() {
  return getJson('/api/auth/pubkeys');
}

export function addAuthPubkey(name, publicKey) {
  return requestJson('/api/auth/pubkeys', {
    method: 'POST',
    body: JSON.stringify({ name, publicKey })
  });
}

export function removeAuthPubkey(id) {
  return requestJson(`/api/auth/pubkeys/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export function getAuthSessions() {
  return getJson('/api/auth/sessions');
}

export function revokeAuthSession(id) {
  return requestJson(`/api/auth/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' });
}
