/* The fetch wrapper: how an API failure becomes a message a page can show.
 *
 * Every page now renders `error` straight from these hooks, so whatever
 * request() puts in the Error is what the operator reads. A wrong API key
 * producing "[object Object]" would be worse than the silent catch it
 * replaced.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, errorMessage, getApiKey, setApiKey } from '../api.js';

function mockFetch(status, body, { json = true } = {}) {
  const text = json ? JSON.stringify(body) : String(body);
  globalThis.fetch = vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    text: async () => text,
  }));
  return globalThis.fetch;
}

afterEach(() => { setApiKey(''); });

describe('request()', () => {
  it('returns the parsed body on success', async () => {
    mockFetch(200, { items: [1, 2] });
    await expect(api.engagements.list()).resolves.toEqual({ items: [1, 2] });
  });

  it("surfaces FastAPI's detail field as the message", async () => {
    mockFetch(403, { detail: "engagement is 'draft', not 'authorized'" });
    await expect(api.engagements.run('e1')).rejects.toThrow(/not 'authorized'/);
  });

  it('falls back to the raw body when there is no detail', async () => {
    mockFetch(500, 'Internal Server Error', { json: false });
    await expect(api.dashboard()).rejects.toThrow(/Internal Server Error/);
  });

  it('renders a FastAPI 422 as readable text, not [object Object]', async () => {
    // FastAPI returns `detail` as a string for an HTTPException but as an
    // ARRAY OF OBJECTS for a validation error. The array used to be handed
    // straight to new Error(), so every 422 reached the operator as the
    // literal "[object Object]".
    mockFetch(422, {
      detail: [
        { loc: ['body', 'target_url'], msg: 'field required' },
        { loc: ['body', 'scope_hosts', 0], msg: 'not a valid hostname' },
      ],
    });
    await expect(api.dashboard()).rejects.toThrow(
      'target_url: field required; scope_hosts.0: not a valid hostname');
  });

  it('never produces [object Object] for any error body shape', async () => {
    const shapes = [
      { detail: [{ loc: ['body'], msg: 'bad' }] },
      { detail: { nested: 'object' } },
      { detail: [] },
      { error: { code: 7 } },
      {},
    ];
    for (const body of shapes) {
      mockFetch(400, body);
      // eslint-disable-next-line no-await-in-loop
      const err = await api.dashboard().catch((e) => e);
      expect(err.message).not.toContain('[object Object]');
      expect(err.message.length).toBeGreaterThan(0);
    }
  });

  it('reports the status when the body is empty', async () => {
    mockFetch(502, '', { json: false });
    await expect(api.dashboard()).rejects.toThrow(/502/);
  });

  it('tolerates a non-JSON 200 instead of crashing the page', async () => {
    mockFetch(200, 'plain text', { json: false });
    await expect(api.dashboard()).resolves.toBe('plain text');
  });
});

describe('API key', () => {
  it('is not sent when unset, so a loopback install needs no config', async () => {
    const f = mockFetch(200, {});
    await api.dashboard();
    expect(f.mock.calls[0][1]?.headers?.['X-API-Key']).toBeUndefined();
  });

  it('rides on every request once set', async () => {
    setApiKey('secret-key');
    const f = mockFetch(200, {});
    await api.dashboard();
    expect(f.mock.calls[0][1].headers['X-API-Key']).toBe('secret-key');
    expect(getApiKey()).toBe('secret-key');
  });

  it('is cleared by setting an empty key', () => {
    setApiKey('x');
    setApiKey('');
    expect(getApiKey()).toBe('');
  });
});

describe('endpoint shapes', () => {
  it('scopes the usage call to one engagement', async () => {
    const f = mockFetch(200, {});
    await api.engagements.usage('eng-7');
    expect(f.mock.calls[0][0]).toBe('/api/engagements/eng-7/usage');
  });

  it('passes the comparison target as a query parameter', async () => {
    const f = mockFetch(200, {});
    await api.engagements.diff('new-id', 'old-id');
    expect(f.mock.calls[0][0]).toBe('/api/engagements/new-id/diff?against=old-id');
  });

  it('no longer exposes the client methods that had no caller', () => {
    // engagements.get was a subset of state(); verify is the ownership proof
    // that has no UI by choice. Both endpoints remain, the dead wrappers do not.
    expect(api.engagements.get).toBeUndefined();
    expect(api.engagements.verify).toBeUndefined();
  });
});


describe('errorMessage()', () => {
  it('prefers a plain string detail', () => {
    expect(errorMessage({ detail: 'no active run' }, '', 404)).toBe('no active run');
  });

  it('drops the request part from a validation location', () => {
    // loc is ["body", "field"]; "body" is noise to the reader.
    expect(errorMessage({ detail: [{ loc: ['body', 'rate'], msg: 'too high' }] }, '', 422))
      .toBe('rate: too high');
  });

  it('falls back to the raw text, then to the status', () => {
    expect(errorMessage(null, 'gateway down', 502)).toBe('gateway down');
    expect(errorMessage(null, '   ', 502)).toBe('HTTP 502');
    expect(errorMessage(null, null, 0)).toBe('HTTP 0');
  });
});
