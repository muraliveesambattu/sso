jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

const { resolvePermissions } = require('../src/services/SSO/permissionResolver.service');
const { logger } = require('../src/config/logger');

const ROLES = [
  { role_id: 'role-admin',   role_name: 'Administrator', permissions: ['read', 'write', 'delete', 'manage_users'] },
  { role_id: 'role-analyst', role_name: 'Analyst',       permissions: '["read","write"]' }, // JSON-store string shape
];

describe('permissionResolver.service', () => {
  const OLD_ENV = process.env;
  let fetchSpy;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...OLD_ENV };
    delete process.env.ROLE_MGMT_URL;
    delete process.env.ROLE_MGMT_API_KEY;
    fetchSpy = jest.spyOn(global, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({ permissions: ['console:dashboard', 'console:reports'] }),
    });
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  afterAll(() => {
    process.env = OLD_ENV;
  });

  test('without ROLE_MGMT_URL, unions zdna_roles permissions (parsing string shapes)', async () => {
    const result = await resolvePermissions(ROLES);

    expect(result.source).toBe('zdna_roles');
    expect(result.permissions.sort()).toEqual(['delete', 'manage_users', 'read', 'write']);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('with ROLE_MGMT_URL, fetches from the role-management service', async () => {
    process.env.ROLE_MGMT_URL = 'http://role-mgmt.local/api/';
    process.env.ROLE_MGMT_API_KEY = 'svc-key';

    const result = await resolvePermissions(ROLES);

    expect(result).toEqual({ permissions: ['console:dashboard', 'console:reports'], source: 'role_mgmt' });
    expect(fetchSpy).toHaveBeenCalledWith(
      'http://role-mgmt.local/api/permissions/resolve',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ 'X-Api-Key': 'svc-key' }),
        body: JSON.stringify({ role_ids: ['role-admin', 'role-analyst'] }),
      }),
    );
  });

  test('falls back to zdna_roles when the role-management call fails (login must not block)', async () => {
    process.env.ROLE_MGMT_URL = 'http://role-mgmt.local';
    fetchSpy.mockRejectedValue(new Error('ECONNREFUSED'));

    const result = await resolvePermissions(ROLES);

    expect(result.source).toBe('zdna_roles');
    expect(result.permissions.sort()).toEqual(['delete', 'manage_users', 'read', 'write']);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('falling back'),
      expect.objectContaining({ action: 'role_mgmt_fallback' }),
    );
  });

  test('falls back on non-200 and on malformed responses', async () => {
    process.env.ROLE_MGMT_URL = 'http://role-mgmt.local';

    fetchSpy.mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({}) });
    expect((await resolvePermissions(ROLES)).source).toBe('zdna_roles');

    fetchSpy.mockResolvedValueOnce({ ok: true, json: async () => ({ nope: true }) });
    expect((await resolvePermissions(ROLES)).source).toBe('zdna_roles');
  });

  test('returns empty permissions for empty roles without calling anything', async () => {
    process.env.ROLE_MGMT_URL = 'http://role-mgmt.local';

    expect(await resolvePermissions([])).toEqual({ permissions: [], source: 'zdna_roles' });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
