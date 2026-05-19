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

export async function getJson(pathname) {
  const response = await apiFetch(pathname, { method: 'GET' });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = payload.error || payload.message || `Request failed (${response.status})`;
    throw new Error(message);
  }
  return payload;
}
