jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

const { resolvePermissions } = require('../src/services/SSO/permissionResolver.service');
const { __resetRmsTokenCache } = require('../src/services/SSO/rmsClient.service');
const { logger } = require('../src/config/logger');

const ROLES = [
  { role_id: 'role-admin',   role_name: 'Administrator', permissions: ['read', 'write', 'delete', 'manage_users'] },
  { role_id: 'role-analyst', role_name: 'Analyst',       permissions: '["read","write"]' }, // JSON-store string shape
];

const USER = { user_id: 'uuid-1', email: 'user@example.com', oid: 'oid-123' };

const rmsTokenResponse = { ok: true, json: async () => ({ access_token: 'rms-token', expires_in: 3600 }) };
const rmsUserFound = {
  ok: true,
  json: async () => ({
    head: { 'sub-code': 3004 },
    data: { rolesArr: [{ roleName: 'Custom Analyst', permissionsArr: ['console:dashboard', 'console:reports:noaccess'] }] },
  }),
};
const rmsUserMissing = { ok: true, json: async () => ({ head: { 'sub-code': 3001 } }) };

const configureRms = () => {
  process.env.ROLE_MANAGEMENT_SERVICE_URL = 'http://rms.local/api';
  process.env.RMS_OAUTH_TOKEN_URL         = 'http://oauth.local/token';
  process.env.RMS_OAUTH_AUTHORIZATION_KEY = 'Basic svc-key';
  process.env.DNS_URL                     = 'https://console.local';
};

describe('permissionResolver.service (RMS user-centric)', () => {
  const OLD_ENV = process.env;
  let fetchSpy;

  beforeEach(() => {
    jest.clearAllMocks();
    __resetRmsTokenCache();
    process.env = { ...OLD_ENV };
    delete process.env.ROLE_MANAGEMENT_SERVICE_URL;
    delete process.env.RMS_OAUTH_TOKEN_URL;
    delete process.env.RMS_OAUTH_AUTHORIZATION_KEY;
    fetchSpy = jest.spyOn(global, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  afterAll(() => {
    process.env = OLD_ENV;
  });

  test('without RMS config, unions zdna_roles permissions (parsing string shapes)', async () => {
    const result = await resolvePermissions(ROLES, USER);

    expect(result.source).toBe('zdna_roles');
    expect(result.permissions.sort()).toEqual(['delete', 'manage_users', 'read', 'write']);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('without a user (no email), stays local even when RMS is configured', async () => {
    configureRms();

    const result = await resolvePermissions(ROLES, null);

    expect(result.source).toBe('zdna_roles');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('fetches OAuth token then the RMS user, mirroring the zdna-functions contract', async () => {
    configureRms();
    fetchSpy.mockResolvedValueOnce(rmsTokenResponse).mockResolvedValueOnce(rmsUserFound);

    const result = await resolvePermissions(ROLES, USER);

    expect(result).toEqual({
      permissions: ['console:dashboard', 'console:reports:noaccess'],
      source: 'rms',
      roleName: 'Custom Analyst',
    });

    // Call 1 — token endpoint with the static Authorization key
    expect(fetchSpy).toHaveBeenNthCalledWith(1, 'http://oauth.local/token', expect.objectContaining({
      method: 'GET',
      headers: { Authorization: 'Basic svc-key' },
    }));
    // Call 2 — RMS /user with Bearer + zuid + Origin, body { email }
    expect(fetchSpy).toHaveBeenNthCalledWith(2, 'http://rms.local/api/user', expect.objectContaining({
      method: 'POST',
      headers: expect.objectContaining({
        Authorization: 'Bearer rms-token',
        zuid:          'oid-123',
        Origin:        'https://console.local',
      }),
      body: JSON.stringify({ email: 'user@example.com' }),
    }));
  });

  test('caches the OAuth token across calls', async () => {
    configureRms();
    fetchSpy
      .mockResolvedValueOnce(rmsTokenResponse)
      .mockResolvedValueOnce(rmsUserFound)
      .mockResolvedValueOnce(rmsUserFound);   // second resolve — no token call

    await resolvePermissions(ROLES, USER);
    await resolvePermissions(ROLES, USER);

    const tokenCalls = fetchSpy.mock.calls.filter(([url]) => url === 'http://oauth.local/token');
    expect(tokenCalls).toHaveLength(1);
  });

  test('falls back to zdna_roles when RMS does not know the user', async () => {
    configureRms();
    fetchSpy.mockResolvedValueOnce(rmsTokenResponse).mockResolvedValueOnce(rmsUserMissing);

    const result = await resolvePermissions(ROLES, USER);

    expect(result.source).toBe('zdna_roles');
    expect(result.permissions.sort()).toEqual(['delete', 'manage_users', 'read', 'write']);
  });

  test('falls back to zdna_roles on any RMS failure (login must not block)', async () => {
    configureRms();
    fetchSpy.mockRejectedValue(new Error('ECONNREFUSED'));

    const result = await resolvePermissions(ROLES, USER);

    expect(result.source).toBe('zdna_roles');
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('falling back'),
      expect.objectContaining({ action: 'rms_fallback' }),
    );
  });

  test('falls back on non-200 RMS responses', async () => {
    configureRms();
    fetchSpy.mockResolvedValueOnce(rmsTokenResponse).mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({}) });

    expect((await resolvePermissions(ROLES, USER)).source).toBe('zdna_roles');
  });
});
