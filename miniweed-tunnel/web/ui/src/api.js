const DEFAULT_TIMEOUT_MS = 10_000;

/** @typedef {import('../../api-spec/openapi').components['schemas']['VpsSetupScriptResponse']} VpsSetupScriptResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['ConfigResponse']} ConfigResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['ConfigUpdateRequest']} ConfigUpdateRequest */
/** @typedef {import('../../api-spec/openapi').components['schemas']['ConfigUpdateResponse']} ConfigUpdateResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['StatusResponse']} StatusResponse */
/** @typedef {import('../../api-spec/openapi').components['schemas']['KeygenResponse']} KeygenResponse */

export async function apiFetch(pathname, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
  try {
    const response = await fetch(pathname, {
      credentials: 'same-origin',
      cache: 'no-store',
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {})
      }
    });
    return response;
  } catch (err) {
    if (err && err.name === 'AbortError') {
      const timeoutErr = new Error('The request took too long (timeout). Check your connection.');
      timeoutErr.status = 0;
      throw timeoutErr;
    }
    throw err;
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

/**
 * @param {{ withCrowdsec?: boolean }} [options]
 * @returns {Promise<VpsSetupScriptResponse>}
 */
export function getVpsSetupScript({ withCrowdsec = false } = {}) {
  const qs = new URLSearchParams();
  if (withCrowdsec) qs.set('withCrowdsec', '1');
  qs.set('_ts', String(Date.now()));
  const suffix = qs.toString();
  return getJson(`/api/vps-setup-script${suffix ? `?${suffix}` : ''}`);
}

/** Lista de VPS candidatos con su salud y el activo actual. */
export function getVpsTargets() {
  return getJson(`/api/vps/targets?_ts=${Date.now()}`);
}

/**
 * Failover manual (pasa targetId) o automático (sin targetId).
 * @param {string} [targetId]
 */
export function triggerFailover(targetId = '') {
  return requestJson('/api/vps/failover', {
    method: 'POST',
    body: JSON.stringify(targetId ? { targetId } : {})
  });
}

/** Fuerza un recálculo del estado de salud de los servicios. */
export function refreshHealth() {
  return requestJson('/api/health/refresh', { method: 'POST' });
}

// ── auth ──────────────────────────────────────────────────────────────────────

/** @returns {Promise<{ hasPassword: boolean, authenticated: boolean }>} */
export function getAuthStatus() {
  return getJson(`/api/auth/status?_ts=${Date.now()}`);
}

/** @param {string} password */
export function login(password) {
  return requestJson('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ password })
  });
}

export function logout() {
  return requestJson('/api/auth/logout', { method: 'POST' });
}

/**
 * Fija o cambia la contraseña. currentPassword es necesaria para cambios
 * cuando ya existe contraseña y no hay sesión.
 * @param {string} password
 * @param {string} [currentPassword]
 */
export function setPassword(password, currentPassword) {
  const body = currentPassword ? { password, currentPassword } : { password };
  return requestJson('/api/auth/password', {
    method: 'POST',
    body: JSON.stringify(body)
  });
}

export function getSessions() {
  return getJson(`/api/auth/sessions?_ts=${Date.now()}`);
}

/** @param {string} id */
export function revokeSession(id) {
  return requestJson(`/api/auth/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

// ── rotación de claves ──────────────────────────────────────────────────────

/** Prepara un plan de rotación; devuelve script de VPS + SHA + plan. */
export function rotatePrepare() {
  return requestJson('/api/rotate/prepare', {
    method: 'POST',
    body: JSON.stringify({})
  });
}

/**
 * Confirma (apply=true) o cancela (apply=false) un plan de rotación.
 * @param {string} planId
 * @param {boolean} apply
 */
export function rotateConfirm(planId, apply) {
  return requestJson('/api/rotate/confirm', {
    method: 'POST',
    body: JSON.stringify({ planId, apply })
  });
}

// ── kill-switch ─────────────────────────────────────────────────────────────

/** @returns {Promise<{ script: string, sha256: string, filename: string }>} */
export function getKillSwitchScript() {
  return getJson(`/api/kill-switch/script?_ts=${Date.now()}`);
}

// ── claves públicas (acceso CLI) ────────────────────────────────────────────

export function getPubkeys() {
  return getJson(`/api/auth/pubkeys?_ts=${Date.now()}`);
}

/** @param {string} name @param {string} publicKey */
export function addPubkey(name, publicKey) {
  return requestJson('/api/auth/pubkeys', {
    method: 'POST',
    body: JSON.stringify({ name, publicKey })
  });
}

/** @param {string} id */
export function removePubkey(id) {
  return requestJson(`/api/auth/pubkeys/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

// ── backup / restore (binario cifrado) ──────────────────────────────────────

/**
 * Descarga un backup cifrado. Devuelve el Blob para guardarlo.
 * @param {string} passphrase
 * @param {boolean} includeAudit
 * @returns {Promise<Blob>}
 */
export async function createBackup(passphrase, includeAudit = true) {
  const response = await apiFetch('/api/backup', {
    method: 'POST',
    body: JSON.stringify({ passphrase, includeAudit })
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const error = new Error(payload.error || `Backup failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return response.blob();
}

/**
 * Restaura desde un archivo de backup cifrado.
 * @param {ArrayBuffer} buffer
 * @param {string} passphrase
 */
export async function restoreBackup(buffer, passphrase) {
  const response = await apiFetch('/api/restore', {
    method: 'POST',
    body: buffer,
    headers: {
      'Content-Type': 'application/octet-stream',
      'x-backup-passphrase': passphrase
    }
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || `Restore failed (${response.status})`);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}
