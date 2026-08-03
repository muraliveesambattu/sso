/**
 * ssoApi — auth headers, timeout, retry/backoff, and response unwrapping.
 * No DOM needed; fetch and the Firebase auth module are mocked.
 */

jest.mock('../constants/SsoConstants', () => ({
  API_BASE: 'https://sso.example.com',
  API_BASE_GATEWAY: 'https://gateway.example.com',
}));

jest.mock('../auth/FirebaseAuth', () => ({
  auth: { currentUser: { getIdToken: jest.fn().mockResolvedValue('fake-id-token') } },
}));

import { auth } from '../auth/FirebaseAuth';
import {
  saveConfigApi, getSsoConfig, activateSso, deactivateSso,
  deleteSsoConfig, listRolesApi, testConnectionCallbackApi,
} from './ssoApi';

const jsonResponse = (body, { ok = true, status = 200 } = {}) => ({
  ok, status, json: async () => body,
});

beforeEach(() => {
  jest.clearAllMocks();
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
  auth.currentUser = { getIdToken: jest.fn().mockResolvedValue('fake-id-token') };
  global.fetch = jest.fn();
});

afterEach(() => jest.restoreAllMocks());

const lastCall = () => global.fetch.mock.calls[global.fetch.mock.calls.length - 1];

describe('auth headers', () => {
  test('attaches the Firebase ID token as a Bearer header and never an admin key', async () => {
    global.fetch.mockResolvedValue(jsonResponse({ success: true }));
    await saveConfigApi({ protocol: 'oidc' });

    const [, options] = lastCall();
    expect(options.headers.Authorization).toBe('Bearer fake-id-token');
    expect(options.headers['Content-Type']).toBe('application/json');
    expect(options.headers['X-Admin-Api-Key']).toBeUndefined();
  });

  test('throws before any network call when nobody is signed in', async () => {
    auth.currentUser = null;
    await expect(saveConfigApi({})).rejects.toThrow('Not authenticated');
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

describe('endpoints and verbs', () => {
  beforeEach(() => global.fetch.mockResolvedValue(jsonResponse({ success: true, data: {} })));

  test('getSsoConfig prefers company_id and URL-encodes it', async () => {
    await getSsoConfig({ companyId: 'zdna gmail/local' });
    expect(lastCall()[0]).toBe(
      'https://gateway.example.com/auth/sso/config?company_id=zdna%20gmail%2Flocal'
    );
  });

  test('getSsoConfig falls back to domain when no company_id is given', async () => {
    await getSsoConfig({ domain: 'contoso.com' });
    expect(lastCall()[0]).toContain('?domain=contoso.com');
  });

  test('getSsoConfig unwraps body.data', async () => {
    global.fetch.mockResolvedValue(jsonResponse({ success: true, data: { integration: { company_id: 'c1' } } }));
    await expect(getSsoConfig({ companyId: 'c1' })).resolves.toEqual({ integration: { company_id: 'c1' } });
  });

  test('activate and deactivate PATCH the status endpoint with the right body', async () => {
    await activateSso('company-1');
    let [url, options] = lastCall();
    expect(url).toBe('https://gateway.example.com/auth/sso/config/company-1/status');
    expect(options.method).toBe('PATCH');
    expect(JSON.parse(options.body)).toEqual({ status: 'active' });

    await deactivateSso('company-1');
    [, options] = lastCall();
    expect(JSON.parse(options.body)).toEqual({ status: 'inactive' });
  });

  test('deleteSsoConfig issues a DELETE', async () => {
    await deleteSsoConfig('company-1');
    const [url, options] = lastCall();
    expect(url).toBe('https://gateway.example.com/auth/sso/config/company-1');
    expect(options.method).toBe('DELETE');
  });

  test('listRolesApi unwraps the roles array', async () => {
    global.fetch.mockResolvedValue(jsonResponse({ success: true, data: [{ role_id: 'r1' }] }));
    await expect(listRolesApi()).resolves.toEqual([{ role_id: 'r1' }]);
  });

  test('the OIDC test callback bypasses the gateway and sends no Authorization header', async () => {
    await testConnectionCallbackApi({ code: 'c', state: 's' });
    const [url, options] = lastCall();
    expect(url).toBe('https://sso.example.com/auth/test-connection/oidc/callback');
    expect(options.credentials).toBe('include');
    expect(options.headers.Authorization).toBeUndefined();
  });
});

describe('companyId validation', () => {
  test.each([undefined, null, '', '   ', 123])('activateSso rejects %p without calling fetch', async (bad) => {
    await expect(activateSso(bad)).rejects.toThrow(/companyId is required/);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('rejects an over-long companyId', async () => {
    await expect(deleteSsoConfig('x'.repeat(129))).rejects.toThrow('companyId is too long');
  });

  // NOTE: deactivateSso does NOT call validateCompanyId, unlike activate/delete.
  test('deactivateSso currently skips validation and calls fetch', async () => {
    global.fetch.mockResolvedValue(jsonResponse({ success: true }));
    await deactivateSso('');
    expect(global.fetch).toHaveBeenCalled();
  });
});

describe('retry and error handling', () => {
  test('retries a retryable 503 and succeeds on the next attempt', async () => {
    global.fetch
      .mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 503 }))
      .mockResolvedValueOnce(jsonResponse({ success: true, data: [] }));

    await expect(listRolesApi()).resolves.toEqual([]);
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  test('does not retry a non-retryable 404', async () => {
    global.fetch.mockResolvedValue(jsonResponse({ error: { message: 'Not found' } }, { ok: false, status: 404 }));
    await expect(listRolesApi()).rejects.toThrow('Not found');
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('gives up after MAX_RETRIES on persistent 500s', async () => {
    global.fetch.mockResolvedValue(jsonResponse({ error: { message: 'boom' } }, { ok: false, status: 500 }));
    await expect(listRolesApi()).rejects.toThrow('boom');
    expect(global.fetch).toHaveBeenCalledTimes(4); // initial + 3 retries
  });

  test('surfaces success:false even on HTTP 200', async () => {
    global.fetch.mockResolvedValue(jsonResponse({ success: false, message: 'Domain already configured' }));
    await expect(listRolesApi()).rejects.toThrow('Domain already configured');
  });

  test('tolerates a non-JSON body by treating it as an empty object', async () => {
    global.fetch.mockResolvedValue({
      ok: false, status: 404, json: async () => { throw new SyntaxError('Unexpected token <'); },
    });
    await expect(listRolesApi()).rejects.toThrow('Request failed');
  });

  test('tags an aborted request with code TIMEOUT', async () => {
    const abortErr = new Error('The operation was aborted');
    abortErr.name = 'AbortError';
    global.fetch.mockRejectedValue(abortErr);

    await expect(listRolesApi()).rejects.toMatchObject({ code: 'TIMEOUT', message: 'Request timed out.' });
    expect(global.fetch).toHaveBeenCalledTimes(4); // TIMEOUT is retryable
  });

  test('tags a transport failure with code NETWORK_ERROR', async () => {
    global.fetch.mockRejectedValue(new TypeError('Failed to fetch'));
    await expect(listRolesApi()).rejects.toMatchObject({ code: 'NETWORK_ERROR' });
  });

  test('passes an AbortSignal so the timeout can fire', async () => {
    global.fetch.mockResolvedValue(jsonResponse({ success: true, data: [] }));
    await listRolesApi();
    expect(lastCall()[1].signal).toBeDefined();
  });
});
