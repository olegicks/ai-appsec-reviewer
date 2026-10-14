import { describe, expect, it, vi } from 'vitest';
import { analyze, API_URL, ApiError } from './api';

function mockFetch(status, body) {
  return vi.spyOn(globalThis, 'fetch').mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

describe('analyze', () => {
  it('posts the payload to /analyze and returns JSON', async () => {
    const spy = mockFetch(200, { vulnerabilities: [] });
    const payload = { mode: 'snippet', code: 'print(1)', language: 'python' };

    await expect(analyze(payload)).resolves.toEqual({ vulnerabilities: [] });
    expect(spy).toHaveBeenCalledWith(
      `${API_URL}/analyze`,
      expect.objectContaining({ method: 'POST', body: JSON.stringify(payload) }),
    );
  });

  it('surfaces the server detail message', async () => {
    mockFetch(400, { detail: 'Failed to clone repository.' });
    await expect(analyze({})).rejects.toMatchObject({ message: 'Failed to clone repository.', status: 400 });
  });

  it('flattens FastAPI validation errors', async () => {
    mockFetch(422, { detail: [{ msg: 'Value error, Only public https://github.com/owner/repo URLs are allowed' }] });
    await expect(analyze({})).rejects.toThrow('Only public https://github.com/owner/repo URLs are allowed');
  });

  it('explains rate limiting', async () => {
    mockFetch(429, { error: { code: 429 } });
    await expect(analyze({})).rejects.toThrow(/Rate limit/);
  });

  it('wraps network failures in a friendly error', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'));
    const err = await analyze({}).catch((e) => e);

    expect(err).toBeInstanceOf(ApiError);
    expect(err.message).toMatch(/Cannot reach the analysis server/);
  });

  it('passes abort errors through untouched', async () => {
    const abort = new DOMException('aborted', 'AbortError');
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(abort);
    await expect(analyze({})).rejects.toBe(abort);
  });
});
