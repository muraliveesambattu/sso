/**
 * getEntraClaimsApi — POST /auth/sso/entra-claims through the SSO gateway (DLM-100021).
 *
 * Kept in its own file so it doesn't clash with the existing ssoApi.test.js.
 * fetch and the Firebase user are mocked.
 */

import { getEntraClaimsApi } from './ssoApi';
import { auth } from '../auth/FirebaseAuth';

jest.mock('../constants/SsoConstants', () => ({
  API_BASE: 'https://sso.example.test',
  API_BASE_GATEWAY: 'https://gateway.example.test',
}));

jest.mock('../auth/FirebaseAuth', () => ({ auth: { currentUser: null } }));

const PAYLOAD = {
  company_id: 'company-1',
  protocol: 'oidc',
  tenant_id: '11111111-2222-3333-4444-555555555555',
  client_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
};

const response = (status, body) => ({
  ok: status >= 200 && status < 300,
  status,
  json: () => Promise.resolve(body),
});

beforeEach(() => {
  auth.currentUser = { getIdToken: jest.fn().mockResolvedValue('id-token-1') };
  global.fetch = jest.fn();
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  delete global.fetch;
  console.error.mockRestore();
  console.warn.mockRestore();
});

describe('getEntraClaimsApi', () => {
  test('POSTs the payload to the gateway with the Firebase ID token', async () => {
    global.fetch.mockResolvedValue(response(200, { success: true, data: { claimNames: ['roles'] } }));

    const result = await getEntraClaimsApi(PAYLOAD);

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [url, options] = global.fetch.mock.calls[0];
    expect(url).toBe('https://gateway.example.test/auth/sso/entra-claims');
    expect(options.method).toBe('POST');
    expect(options.headers).toEqual({ 'Content-Type': 'application/json', Authorization: 'Bearer id-token-1' });
    expect(JSON.parse(options.body)).toEqual(PAYLOAD);
    expect(options.signal).toBeDefined();
    expect(result).toEqual({ ok: true, status: 200, data: { success: true, data: { claimNames: ['roles'] } } });
  });

  test('never sends an admin API key from the browser', async () => {
    global.fetch.mockResolvedValue(response(200, { success: true }));
    await getEntraClaimsApi(PAYLOAD);
    const { headers } = global.fetch.mock.calls[0][1];
    expect(Object.keys(headers).map((h) => h.toLowerCase())).not.toContain('x-admin-api-key');
  });

  test('returns the error body as-is so the caller can read error.code', async () => {
    const body = { success: false, error: { code: 'ENTRA_CONNECTOR_NOT_CONSENTED', message: 'Grant admin consent first.' } };
    global.fetch.mockResolvedValue(response(403, body));

    await expect(getEntraClaimsApi(PAYLOAD)).resolves.toEqual({ ok: false, status: 403, data: body });
  });

  test('does not retry a 503 (the hook has its own Retry button)', async () => {
    global.fetch.mockResolvedValue(response(503, { success: false }));

    const result = await getEntraClaimsApi(PAYLOAD);

    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(result).toMatchObject({ ok: false, status: 503 });
  });

  test('returns an empty body when the response is not JSON', async () => {
    global.fetch.mockResolvedValue({ ok: false, status: 502, json: () => Promise.reject(new SyntaxError('bad json')) });
    await expect(getEntraClaimsApi(PAYLOAD)).resolves.toEqual({ ok: false, status: 502, data: {} });
  });

  test('rejects with NETWORK_ERROR once, without retrying', async () => {
    global.fetch.mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(getEntraClaimsApi(PAYLOAD)).rejects.toMatchObject({ code: 'NETWORK_ERROR', message: 'Failed to fetch' });
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('rejects with TIMEOUT when the request is aborted', async () => {
    const abort = new Error('aborted');
    abort.name = 'AbortError';
    global.fetch.mockRejectedValue(abort);

    await expect(getEntraClaimsApi(PAYLOAD)).rejects.toMatchObject({ code: 'TIMEOUT', message: 'Request timed out.' });
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('rejects without calling fetch when nobody is signed in', async () => {
    auth.currentUser = null;
    await expect(getEntraClaimsApi(PAYLOAD)).rejects.toThrow('Not authenticated');
    expect(global.fetch).not.toHaveBeenCalled();
  });
});
