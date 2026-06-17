const DEFAULT_TIMEOUT_MS = 10_000;

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

/** Forces a recompute of the services' health status. */
export function refreshHealth() {
  return requestJson('/api/health/refresh', { method: 'POST' });
}
