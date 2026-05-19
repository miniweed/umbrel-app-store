const DEFAULT_TIMEOUT_MS = 10_000;

/** @typedef {import('../../api-spec/openapi').components['schemas']['VpsFailoverRequest']} VpsFailoverRequest */
/** @typedef {import('../../api-spec/openapi').components['schemas']['VpsFailoverResponse']} VpsFailoverResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['VpsSetupScriptResponse']} VpsSetupScriptResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['VpsTargetsResponse']} VpsTargetsResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['ConfigResponse']} ConfigResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['ConfigUpdateRequest']} ConfigUpdateRequest */
/** @typedef {import('../../api-spec/openapi').components['schemas']['ConfigUpdateResponse']} ConfigUpdateResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['StatusResponse']} StatusResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['KeygenResponse']} KeygenResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['PasswordRequest']} PasswordRequest */
/** @typedef {import('../../api-spec/openapi').components['schemas']['LoginRequest']} LoginRequest */
/** @typedef {import('../../api-spec/openapi').components['schemas']['AuthOkResponse']} AuthOkResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['AuthPubkeysResponse']} AuthPubkeysResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['AuthPubkeyAddResponse']} AuthPubkeyAddResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['AuthSessionsResponse']} AuthSessionsResponse */

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

/**
 * @template T
 * @param {string} pathname
 * @param {RequestInit} [options]
 * @returns {Promise<T>}
 */
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
  return /** @type {T} */ (payload);
}

/**
 * @template T
 * @param {string} pathname
 * @returns {Promise<T>}
 */
export function getJson(pathname) {
  return requestJson(pathname, { method: 'GET' });
}

/** @returns {Promise<ConfigResponse>} */
export function getConfig() {
  return getJson('/api/config');
}

/** @param {ConfigUpdateRequest} payload */
export function saveConfig(payload) {
  return requestJson('/api/config', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

/** @returns {Promise<StatusResponse>} */
export function getStatus() {
  return getJson('/api/status');
}

/** @returns {Promise<KeygenResponse>} */
export function keygen() {
  return getJson('/api/keygen');
}

/** @returns {Promise<VpsTargetsResponse>} */
export function getVpsTargets() {
  return getJson('/api/vps/targets');
}

/**
 * @param {string} [targetId]
 * @returns {Promise<VpsFailoverResponse>}
 */
export function triggerFailover(targetId = '') {
  /** @type {VpsFailoverRequest} */
  const payload = targetId ? { targetId } : {};
  return requestJson('/api/vps/failover', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

/**
 * @param {{ vpsId?: string, withCrowdsec?: boolean }} [options]
 * @returns {Promise<VpsSetupScriptResponse>}
 */
export function getVpsSetupScript({ vpsId = '', withCrowdsec = false } = {}) {
  const qs = new URLSearchParams();
  if (vpsId) qs.set('vpsId', vpsId);
  if (withCrowdsec) qs.set('withCrowdsec', '1');
  const suffix = qs.toString();
  return getJson(`/api/vps-setup-script${suffix ? `?${suffix}` : ''}`);
}

/**
 * @param {string} password
 * @returns {Promise<AuthOkResponse>}
 */
export function setUiPassword(password) {
  /** @type {PasswordRequest} */
  const payload = { password };
  return requestJson('/api/auth/password', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

/**
 * @param {string} password
 * @returns {Promise<AuthOkResponse>}
 */
export function login(password) {
  /** @type {LoginRequest} */
  const payload = { password };
  return requestJson('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

/** @returns {Promise<AuthOkResponse>} */
export function logout() {
  return requestJson('/api/auth/logout', { method: 'POST' });
}

/** @returns {Promise<AuthPubkeysResponse>} */
export function getAuthPubkeys() {
  return getJson('/api/auth/pubkeys');
}

/**
 * @param {string} name
 * @param {string} publicKey
 * @returns {Promise<AuthPubkeyAddResponse>}
 */
export function addAuthPubkey(name, publicKey) {
  return requestJson('/api/auth/pubkeys', {
    method: 'POST',
    body: JSON.stringify({ name, publicKey })
  });
}

/** @returns {Promise<AuthOkResponse>} */
export function removeAuthPubkey(id) {
  return requestJson(`/api/auth/pubkeys/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

/** @returns {Promise<AuthSessionsResponse>} */
export function getAuthSessions() {
  return getJson('/api/auth/sessions');
}

/** @returns {Promise<AuthOkResponse>} */
export function revokeAuthSession(id) {
  return requestJson(`/api/auth/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' });
}
