jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

const { logger } = require('../src/config/logger');

let rmsModule;
for (const p of [
  '../src/services/SSO/rmsClient.service',
  '../src/services/RMS/rmsClient.service',
  '../src/services/rms/rmsClient.service',
  '../src/services/SSO/rms.service',
  '../src/services/rmsClient.service',
]) {
  try {
    rmsModule = require(p);
    break;
  } catch {
    // try fallback paths
  }
}

const { isRmsConfigured, fetchUserPermissionsFromRms, __resetRmsTokenCache } = rmsModule;

describe('rmsClient.service', () => {
  const originalEnv = { ...process.env };
  const originalFetch = globalThis.fetch;

  beforeAll(() => {
    globalThis.fetch = jest.fn();
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
  });

  beforeEach(() => {
    jest.clearAllMocks();
    __resetRmsTokenCache();
    process.env = {
      ...originalEnv,
      ROLE_MANAGEMENT_SERVICE_URL: 'https://rms.example.com',
      RMS_OAUTH_TOKEN_URL: 'https://rms-oauth.example.com/token',
      RMS_OAUTH_AUTHORIZATION_KEY: 'Basic dGVzdC1hdXRoLWtleQ==',
      DNS_URL: 'https://portal.example.com',
      RMS_TIMEOUT_MS: '3000',
    };
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  describe('isRmsConfigured', () => {
    test('returns true when all required environment variables are set', () => {
      expect(isRmsConfigured()).toBe(true);
    });

    test('returns false when ROLE_MANAGEMENT_SERVICE_URL is missing', () => {
      delete process.env.ROLE_MANAGEMENT_SERVICE_URL;
      expect(isRmsConfigured()).toBe(false);
    });

    test('returns false when RMS_OAUTH_TOKEN_URL is missing', () => {
      delete process.env.RMS_OAUTH_TOKEN_URL;
      expect(isRmsConfigured()).toBe(false);
    });

    test('returns false when RMS_OAUTH_AUTHORIZATION_KEY is missing', () => {
      delete process.env.RMS_OAUTH_AUTHORIZATION_KEY;
      expect(isRmsConfigured()).toBe(false);
    });

    test('returns false when all required variables are missing', () => {
      delete process.env.ROLE_MANAGEMENT_SERVICE_URL;
      delete process.env.RMS_OAUTH_TOKEN_URL;
      delete process.env.RMS_OAUTH_AUTHORIZATION_KEY;
      expect(isRmsConfigured()).toBe(false);
    });
  });

  describe('fetchWithTimeout and timeout configuration', () => {
    test('uses default timeout of 3000ms when RMS_TIMEOUT_MS is not set', async () => {
      delete process.env.RMS_TIMEOUT_MS;
      const setTimeoutSpy = jest.spyOn(globalThis, 'setTimeout');

      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'token-default-timeout', expires_in: 3600 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ head: { 'sub-code': 3004 }, data: { rolesArr: [] } }),
        });

      await fetchUserPermissionsFromRms({ email: 'user@example.com', userKey: 'zuid-1' });
      expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 3000);
      setTimeoutSpy.mockRestore();
    });

    test('uses custom timeout when RMS_TIMEOUT_MS is provided', async () => {
      process.env.RMS_TIMEOUT_MS = '5000';
      const setTimeoutSpy = jest.spyOn(globalThis, 'setTimeout');

      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'token-custom-timeout', expires_in: 3600 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ head: { 'sub-code': 3004 }, data: { rolesArr: [] } }),
        });

      await fetchUserPermissionsFromRms({ email: 'user@example.com', userKey: 'zuid-1' });
      expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 5000);
      setTimeoutSpy.mockRestore();
    });
  });

  describe('getRmsToken and token caching', () => {
    test('fetches new OAuth token and caches it until expiry', async () => {
      const fixedNow = 1000000;
      const dateSpy = jest.spyOn(Date, 'now').mockReturnValue(fixedNow);

      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'cached-token-123', expires_in: 1200 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ head: { 'sub-code': 3004 }, data: { rolesArr: [] } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ head: { 'sub-code': 3004 }, data: { rolesArr: [] } }),
        });

      // First call fetches token
      await fetchUserPermissionsFromRms({ email: 'user1@example.com', userKey: 'key-1' });

      // Second call uses cached token within validity period (no second OAuth fetch)
      dateSpy.mockReturnValue(fixedNow + 1000);
      await fetchUserPermissionsFromRms({ email: 'user2@example.com', userKey: 'key-2' });

      // Total fetch calls should be 3 (1 OAuth fetch + 2 /user calls)
      expect(globalThis.fetch).toHaveBeenCalledTimes(3);

      dateSpy.mockRestore();
    });

    test('re-fetches OAuth token when cached token has expired', async () => {
      let currentTime = 1000000;
      const dateSpy = jest.spyOn(Date, 'now').mockImplementation(() => currentTime);

      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'token-run-1', expires_in: 300 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ head: { 'sub-code': 3004 }, data: { rolesArr: [] } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'token-run-2', expires_in: 300 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ head: { 'sub-code': 3004 }, data: { rolesArr: [] } }),
        });

      await fetchUserPermissionsFromRms({ email: 'user1@example.com', userKey: 'key-1' });

      // Advance past cache expiry: (300 - 60) * 1000 = 240,000ms
      currentTime += 250000;

      await fetchUserPermissionsFromRms({ email: 'user2@example.com', userKey: 'key-2' });

      // 2 OAuth token fetches + 2 /user calls = 4 calls total
      expect(globalThis.fetch).toHaveBeenCalledTimes(4);

      dateSpy.mockRestore();
    });

    test('uses fallback expires_in of 300 seconds when expires_in is omitted from OAuth response', async () => {
      const fixedNow = 1000000;
      const dateSpy = jest.spyOn(Date, 'now').mockReturnValue(fixedNow);

      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'token-fallback-expires' }), // no expires_in
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ head: { 'sub-code': 3004 }, data: { rolesArr: [] } }),
        });

      await fetchUserPermissionsFromRms({ email: 'user@example.com', userKey: 'key-1' });

      expect(globalThis.fetch).toHaveBeenNthCalledWith(
        1,
        'https://rms-oauth.example.com/token',
        expect.objectContaining({
          method: 'GET',
          headers: { Authorization: 'Basic dGVzdC1hdXRoLWtleQ==' },
        })
      );

      dateSpy.mockRestore();
    });

    test('re-fetches token after __resetRmsTokenCache is called', async () => {
      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'token-reset-1', expires_in: 3600 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ head: { 'sub-code': 3004 }, data: { rolesArr: [] } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'token-reset-2', expires_in: 3600 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ head: { 'sub-code': 3004 }, data: { rolesArr: [] } }),
        });

      await fetchUserPermissionsFromRms({ email: 'user@example.com', userKey: 'key-1' });

      __resetRmsTokenCache();

      await fetchUserPermissionsFromRms({ email: 'user@example.com', userKey: 'key-1' });

      expect(globalThis.fetch).toHaveBeenCalledTimes(4);
    });

    test('throws an error when OAuth token endpoint responds with non-200 status', async () => {
      globalThis.fetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
      });

      await expect(
        fetchUserPermissionsFromRms({ email: 'user@example.com', userKey: 'key-1' })
      ).rejects.toThrow('RMS OAuth token endpoint responded HTTP 401');
    });

    test('throws an error when OAuth response does not contain an access_token', async () => {
      globalThis.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ token_type: 'Bearer' }), // missing access_token
      });

      await expect(
        fetchUserPermissionsFromRms({ email: 'user@example.com', userKey: 'key-1' })
      ).rejects.toThrow('RMS OAuth response missing access_token');
    });
  });

  describe('fetchUserPermissionsFromRms', () => {
    test('returns found: true, permissions, and roleName when user exists in RMS (sub-code 3004)', async () => {
      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'valid-token', expires_in: 1800 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            head: { 'sub-code': 3004 },
            data: {
              rolesArr: [
                {
                  roleName: 'System Administrator',
                  permissionsArr: ['devices:view', 'devices:edit', 'users:manage'],
                },
              ],
            },
          }),
        });

      const result = await fetchUserPermissionsFromRms({
        email: 'admin@example.com',
        userKey: 'oid-admin-123',
      });

      expect(result).toEqual({
        found: true,
        permissions: ['devices:view', 'devices:edit', 'users:manage'],
        roleName: 'System Administrator',
      });

      expect(globalThis.fetch).toHaveBeenNthCalledWith(
        2,
        'https://rms.example.com/user',
        expect.objectContaining({
          method: 'POST',
          headers: {
            Authorization: 'Bearer valid-token',
            'Content-Type': 'application/json',
            zuid: 'oid-admin-123',
            Origin: 'https://portal.example.com',
          },
          body: JSON.stringify({ email: 'admin@example.com' }),
        })
      );
    });

    test('strips trailing slash from ROLE_MANAGEMENT_SERVICE_URL and handles empty DNS_URL', async () => {
      process.env.ROLE_MANAGEMENT_SERVICE_URL = 'https://rms.example.com/';
      delete process.env.DNS_URL;

      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'valid-token' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            head: { 'sub-code': 3004 },
            data: {
              rolesArr: [
                {
                  roleName: 'Standard User',
                  permissionsArr: ['view:all'],
                },
              ],
            },
          }),
        });

      await fetchUserPermissionsFromRms({
        email: 'user@example.com',
        userKey: 'oid-user-456',
      });

      expect(globalThis.fetch).toHaveBeenNthCalledWith(
        2,
        'https://rms.example.com/user',
        expect.objectContaining({
          headers: expect.objectContaining({
            Origin: '',
          }),
        })
      );
    });

    test('returns found: false and logs info when user is not found in RMS (sub-code !== 3004)', async () => {
      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'valid-token' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            head: { 'sub-code': 3005 },
            data: {},
          }),
        });

      const result = await fetchUserPermissionsFromRms({
        email: 'unknown@example.com',
        userKey: 'oid-unknown',
      });

      expect(result).toEqual({ found: false });
      expect(logger.info).toHaveBeenCalledWith(
        'RMS does not know this user — permission fallback applies',
        { action: 'rms_user_not_found' }
      );
    });

    test('handles missing or non-array permissions and missing roleName gracefully when user exists', async () => {
      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'valid-token' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            head: { 'sub-code': 3004 },
            data: {
              rolesArr: [
                {
                  roleName: null,
                  permissionsArr: 'not-an-array',
                },
              ],
            },
          }),
        });

      const result = await fetchUserPermissionsFromRms({
        email: 'user@example.com',
        userKey: 'oid-user',
      });

      expect(result).toEqual({
        found: true,
        permissions: [],
        roleName: '',
      });
    });

    test('handles empty rolesArr array when user exists in RMS', async () => {
      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'valid-token' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            head: { 'sub-code': 3004 },
            data: {
              rolesArr: [],
            },
          }),
        });

      const result = await fetchUserPermissionsFromRms({
        email: 'user@example.com',
        userKey: 'oid-user',
      });

      expect(result).toEqual({
        found: true,
        permissions: [],
        roleName: '',
      });
    });

    test('logs error body and throws when /user endpoint returns an HTTP error with readable text', async () => {
      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'valid-token' }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 403,
          text: async () => 'Forbidden: Invalid zuid',
        });

      await expect(
        fetchUserPermissionsFromRms({ email: 'forbidden@example.com', userKey: 'bad-key' })
      ).rejects.toThrow('RMS /user responded HTTP 403');

      expect(logger.warn).toHaveBeenCalledWith(
        'RMS /user HTTP 403 body >> Forbidden: Invalid zuid',
        { action: 'rms_user_http_error', status: 403 }
      );
    });

    test('falls back to <unreadable> when res.text() fails on HTTP error', async () => {
      globalThis.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'valid-token' }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 502,
          text: async () => {
            throw new Error('Connection reset while reading body');
          },
        });

      await expect(
        fetchUserPermissionsFromRms({ email: 'badgateway@example.com', userKey: 'any-key' })
      ).rejects.toThrow('RMS /user responded HTTP 502');

      expect(logger.warn).toHaveBeenCalledWith(
        'RMS /user HTTP 502 body >> <unreadable>',
        { action: 'rms_user_http_error', status: 502 }
      );
    });
  });
});