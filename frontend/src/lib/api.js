export const API_URL = (import.meta.env.VITE_API_URL || 'https://ai-appsec-reviewer.onrender.com').replace(/\/+$/, '');

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function describeError(status, detail) {
  if (Array.isArray(detail)) {
    // FastAPI validation errors: [{loc, msg}, ...]
    return detail.map((d) => d.msg?.replace(/^Value error, /, '')).filter(Boolean).join('; ');
  }
  if (typeof detail === 'string') return detail;
  if (status === 429) return 'Rate limit reached. Please wait a minute before running another scan.';
  return `Request failed with HTTP ${status}`;
}

export async function analyze(payload, { signal } = {}) {
  let response;
  try {
    response = await fetch(`${API_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal,
    });
  } catch (err) {
    if (err.name === 'AbortError') throw err;
    throw new ApiError('Cannot reach the analysis server. It may be waking up, try again in a few seconds.', 0);
  }

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new ApiError(describeError(response.status, body?.detail ?? body?.error), response.status);
  }
  return response.json();
}

export async function checkHealth({ signal } = {}) {
  const response = await fetch(`${API_URL}/health`, { signal });
  if (!response.ok) throw new ApiError('Health check failed', response.status);
  return response.json();
}
