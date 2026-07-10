jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/services/featureFlag.service', () => ({
  isEnabled: jest.fn(),
}));

jest.mock('../src/services/db/ssoDataService', () => ({
  getSsoIntegrationByCompanyId: jest.fn(),
  getJitMappings: jest.fn(),
  getRolesByIds: jest.fn(),
  findUserByOid: jest.fn(),
  findUserByEmail: jest.fn(),
  createUser: jest.fn(),
  updateUser: jest.fn(),
}));

const crypto = require('crypto');
const { resolveUser } = require('../src/services/SSO/userResolution.service');
const { isEnabled } = require('../src/services/featureFlag.service');
const {
  getSsoIntegrationByCompanyId,
  getJitMappings,
  getRolesByIds,
  findUserByOid,
  findUserByEmail,
  createUser,
  updateUser,
} = require('../src/services/db/ssoDataService');

describe('userResolution.service', () => {
  let randomUuidSpy;

  beforeEach(() => {
    jest.clearAllMocks();
    randomUuidSpy = jest.spyOn(crypto, 'randomUUID').mockReturnValue('uuid-123');
    isEnabled.mockResolvedValue(true);
  });

  afterEach(() => {
    randomUuidSpy.mockRestore();
  });

  test('throws 404 when the company integration does not exist', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue(null);

    await expect(resolveUser('company-1', { email: 'user@example.com', oid: 'oid-1' }, 'oidc')).rejects.toMatchObject({
      statusCode: 404,
      code: 'INTEGRATION_NOT_FOUND',
    });
  });

  test('throws 400 when required identity fields are missing', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_enabled: true });

    await expect(resolveUser('company-1', { name: 'User Only' }, 'oidc')).rejects.toMatchObject({
      statusCode: 400,
      code: 'MISSING_IDENTITY_CLAIMS',
    });
  });

  test('extracts SAML identity fields and single group values during JIT provisioning', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-saml', jit_enabled: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'group', mapping_value: 'zdna-saml-admins', role_id: 'role-admin', priority: 1 },
      { mapping_source: 'default', mapping_value: null, role_id: 'role-viewer', priority: 99 },
    ]);
    getRolesByIds.mockResolvedValue([{ role_id: 'role-admin', role_name: 'Administrator' }]);
    findUserByOid.mockResolvedValue(null);
    createUser.mockResolvedValue({ user_id: 'saml-user-1', email: 'saml.user@example.com' });

    const result = await resolveUser('company-saml', {
      emailaddress: 'saml.user@example.com',
      objectidentifier: 'oid-saml-1',
      displayname: 'SAML User',
      groups: 'zdna-saml-admins',
    }, 'saml');

    expect(createUser).toHaveBeenCalledWith(expect.objectContaining({
      email: 'saml.user@example.com',
      oid: 'oid-saml-1',
      display_name: 'SAML User',
      roles: ['role-admin'],
    }));
    expect(result.action).toBe('created');
  });

  test('creates a JIT user on first login and assigns matching group roles', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_enabled: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'default', mapping_value: null, role_id: 'role-viewer', priority: 99 },
      { mapping_source: 'group', mapping_value: 'zdna-admins', role_id: 'role-admin', priority: 1 },
    ]);
    getRolesByIds.mockResolvedValue([{ role_id: 'role-admin', role_name: 'Administrator' }]);
    findUserByOid.mockResolvedValue(null);
    createUser.mockResolvedValue({ user_id: 'user-1', email: 'user@example.com' });

    const result = await resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-1',
      name: 'User One',
      groups: ['zdna-admins'],
    }, 'oidc');

    expect(createUser).toHaveBeenCalledWith(expect.objectContaining({
      user_id: 'uuid-123',
      company_id: 'company-1',
      email: 'user@example.com',
      oid: 'oid-1',
      display_name: 'User One',
      roles: ['role-admin'],
      jit_provisioned: true,
      login_method: 'sso',
      last_login: expect.any(String),
    }));
    expect(result).toEqual({
      user: { user_id: 'user-1', email: 'user@example.com' },
      roles: [{ role_id: 'role-admin', role_name: 'Administrator' }],
      action: 'created',
    });
  });

  test('matches department, jobtitle, and app-role mapping sources during JIT provisioning', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_enabled: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'department', mapping_value: 'IT',        role_id: 'role-admin',   priority: 1 },
      { mapping_source: 'jobtitle',   mapping_value: 'engineer',  role_id: 'role-analyst', priority: 2 },
      { mapping_source: 'role',       mapping_value: 'Zdna.Admin', role_id: 'role-admin',  priority: 3 },
      { mapping_source: 'default',    mapping_value: null,        role_id: 'role-viewer',  priority: 99 },
    ]);
    getRolesByIds.mockImplementation(async (ids) =>
      ids.map(id => ({ role_id: id, role_name: id })));
    findUserByOid.mockResolvedValue(null);
    createUser.mockImplementation(async (u) => u);

    // department matches case-insensitively ('it' vs 'IT'); jobtitle matches;
    // no app roles → 'role' mapping skipped; default NOT applied (others matched)
    await resolveUser('company-1', {
      email: 'dept@example.com',
      oid: 'oid-dept',
      department: 'it',
      jobTitle: 'Engineer',
      groups: [],
    }, 'oidc');

    expect(getRolesByIds).toHaveBeenCalledWith(['role-admin', 'role-analyst']);
  });

  test('falls back to the default mapping when no attribute matches', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_enabled: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'department', mapping_value: 'IT', role_id: 'role-admin',  priority: 1 },
      { mapping_source: 'default',    mapping_value: null, role_id: 'role-viewer', priority: 99 },
    ]);
    getRolesByIds.mockResolvedValue([{ role_id: 'role-viewer', role_name: 'Viewer' }]);
    findUserByOid.mockResolvedValue(null);
    createUser.mockImplementation(async (u) => u);

    await resolveUser('company-1', {
      email: 'sales@example.com',
      oid: 'oid-sales',
      department: 'Sales',
      groups: [],
    }, 'oidc');

    expect(getRolesByIds).toHaveBeenCalledWith(['role-viewer']);
  });

  test('updates an existing JIT user on re-login', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_enabled: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'default', mapping_value: null, role_id: 'role-analyst', priority: 99 },
    ]);
    getRolesByIds.mockResolvedValue([{ role_id: 'role-analyst', role_name: 'Analyst' }]);
    findUserByOid.mockResolvedValue({
      user_id: 'user-2',
      display_name: 'Old Name',
    });

    const result = await resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-2',
      preferred_username: 'user@example.com',
      name: 'New Name',
      groups: [],
    }, 'oidc');

    expect(updateUser).toHaveBeenCalledWith('user-2', expect.objectContaining({
      roles: ['role-analyst'],
      display_name: 'New Name',
      last_login: expect.any(String),
    }));
    expect(result.action).toBe('updated');
  });

  test('falls back to non-JIT mode when the jit_enabled flag is turned off', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_enabled: true });
    isEnabled.mockResolvedValue(false);
    findUserByOid.mockResolvedValue(null);
    findUserByEmail.mockResolvedValue({
      user_id: 'user-3',
      email: 'user@example.com',
      login_method: 'password',
      roles: ['role-viewer'],
    });

    await expect(resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-3',
      name: 'User Three',
      groups: [],
    }, 'oidc')).rejects.toMatchObject({
      statusCode: 403,
      code: 'LOGIN_METHOD_NOT_ALLOWED',
    });
  });

  test('rejects non-JIT logins for users who are not provisioned by oid or email', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-2', jit_enabled: false });
    findUserByOid.mockResolvedValue(null);
    findUserByEmail.mockResolvedValue(null);

    await expect(resolveUser('company-2', {
      email: 'missing@example.com',
      oid: 'missing-oid',
      name: 'Missing User',
      groups: [],
    }, 'oidc')).rejects.toMatchObject({
      statusCode: 403,
      code: 'USER_NOT_PROVISIONED',
    });
  });

  test('allows non-JIT logins for pre-provisioned SSO users and updates last_login', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_enabled: false });
    findUserByOid.mockResolvedValue({
      user_id: 'user-4',
      email: 'user@example.com',
      oid: 'oid-4',
      login_method: 'sso',
      roles: ['role-analyst'],
    });
    getRolesByIds.mockResolvedValue([{ role_id: 'role-analyst', role_name: 'Analyst' }]);

    const result = await resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-4',
      name: 'User Four',
      groups: [],
    }, 'oidc');

    expect(updateUser).toHaveBeenCalledWith('user-4', { last_login: expect.any(String) });
    expect(result).toEqual({
      user: {
        user_id: 'user-4',
        email: 'user@example.com',
        oid: 'oid-4',
        login_method: 'sso',
        roles: ['role-analyst'],
      },
      roles: [{ role_id: 'role-analyst', role_name: 'Analyst' }],
      action: 'login',
    });
  });

  test('backfills a pending oid placeholder on first non-JIT login', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_enabled: false });
    // Pre-provisioned via POST /sso/users — real Entra oid unknown at creation
    findUserByOid.mockResolvedValue(null);
    findUserByEmail.mockResolvedValue({
      user_id: 'user-5',
      email: 'user5@example.com',
      oid: 'pending:placeholder-uuid',
      login_method: 'sso',
      roles: ['role-viewer'],
    });
    getRolesByIds.mockResolvedValue([{ role_id: 'role-viewer', role_name: 'Viewer' }]);

    await resolveUser('company-1', {
      email: 'user5@example.com',
      oid: 'real-oid-5',
      groups: [],
    }, 'oidc');

    expect(updateUser).toHaveBeenCalledWith('user-5', {
      last_login: expect.any(String),
      oid: 'real-oid-5',
    });
  });

  test('falls back to preferred_username as display name when name is absent during JIT updates', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-3', jit_enabled: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'default', mapping_value: null, role_id: 'role-analyst', priority: 99 },
    ]);
    getRolesByIds.mockResolvedValue([{ role_id: 'role-analyst', role_name: 'Analyst' }]);
    findUserByOid.mockResolvedValue({
      id: 'user-5',
      display_name: 'Old Display',
    });

    await resolveUser('company-3', {
      preferred_username: 'preferred@example.com',
      sub: 'sub-123',
      groups: [],
    }, 'oidc');

    expect(updateUser).toHaveBeenCalledWith('user-5', expect.objectContaining({
      display_name: 'preferred@example.com',
      roles: ['role-analyst'],
    }));
  });
});
