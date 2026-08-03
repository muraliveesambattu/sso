jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/services/featureFlag.service', () => ({
  isEnabled: jest.fn(),
}));

jest.mock('../src/services/db/ssoDataService', () => ({
  getSsoIntegrationByCompanyId: jest.fn(),
  getJitMappings: jest.fn(),
  findUserByOid: jest.fn(),
  findUserByEmail: jest.fn(),
  createUser: jest.fn(),
  updateUser: jest.fn(),
}));

const crypto = require('node:crypto');
const { resolveUser } = require('../src/services/SSO/userResolution.service');
const { logger } = require('../src/config/logger');
const { isEnabled } = require('../src/services/featureFlag.service');
const {
  getSsoIntegrationByCompanyId,
  getJitMappings,
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
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });

    await expect(resolveUser('company-1', { name: 'User Only' }, 'oidc')).rejects.toMatchObject({
      statusCode: 400,
      code: 'MISSING_IDENTITY_CLAIMS',
    });
  });

  test('extracts SAML identity fields and single group values during JIT provisioning', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-saml', jit_status: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'group', mapping_value: 'zdna-saml-admins', role_id: 'role-admin', priority: 1 },
      { mapping_source: 'default', mapping_value: null, role_id: 'role-temporary', priority: 99 },
    ]);
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
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'default', mapping_value: null, role_id: 'role-temporary', role_name: 'Temporary', priority: 99 },
      { mapping_source: 'group', mapping_value: 'zdna-admins', role_id: 'role-admin', role_name: 'Admin', priority: 1 },
    ]);
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
      roles: [{ role_id: 'role-admin', role_name: 'Admin', permissions: [] }],
      action: 'created',
    });
  });

  test('matches department, jobtitle, and app-role mapping sources during JIT provisioning', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'department', mapping_value: 'IT',        role_id: 'role-admin',   role_name: 'Admin',     priority: 1 },
      { mapping_source: 'jobtitle',   mapping_value: 'engineer',  role_id: 'role-manager', role_name: 'Manager',   priority: 2 },
      { mapping_source: 'role',       mapping_value: 'Zdna.Admin', role_id: 'role-admin',  role_name: 'Admin',     priority: 3 },
      { mapping_source: 'default',    mapping_value: null,        role_id: 'role-temporary', role_name: 'Temporary', priority: 99 },
    ]);
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

    // role_name resolved from the mapping (no zdna_roles JOIN in the JIT flow)
    expect(createUser).toHaveBeenCalledWith(expect.objectContaining({ roles: ['role-admin', 'role-manager'] }));
  });

  test('matches an arbitrary Entra claim name against the raw token/assertion', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'employeetype', mapping_value: 'contractor', role_id: 'role-temporary', role_name: 'Temporary', priority: 1 },
    ]);
    findUserByOid.mockResolvedValue(null);
    createUser.mockImplementation(async (u) => u);

    await resolveUser('company-1', {
      email: 'contractor@example.com',
      oid: 'oid-contractor',
      groups: [],
      employeeType: 'Contractor', // custom Entra claim, not one of the 4 named fields
    }, 'oidc');

    expect(createUser).toHaveBeenCalledWith(expect.objectContaining({ roles: ['role-temporary'] }));
    expect(logger.warn).not.toHaveBeenCalled();
  });

  test('logs a warning (and does not match) when a custom claim name is absent from the token', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'costCenter', mapping_value: 'CC-100', role_id: 'role-admin', role_name: 'Admin', priority: 1 },
      { mapping_source: 'default',    mapping_value: null,    role_id: 'role-temporary', role_name: 'Temporary', priority: 99 },
    ]);
    findUserByOid.mockResolvedValue(null);
    createUser.mockImplementation(async (u) => u);

    await resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-nocc',
      groups: [],
      // no costCenter claim present at all — likely a typo'd/misconfigured claim name
    }, 'oidc');

    expect(createUser).toHaveBeenCalledWith(expect.objectContaining({ roles: ['role-temporary'] })); // falls back to default
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('not present in the token'),
      expect.objectContaining({ action: 'jit_unknown_claim', mapping_source: 'costCenter' })
    );
  });

  test('falls back to the default mapping when no attribute matches', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'department', mapping_value: 'IT', role_id: 'role-admin',  role_name: 'Admin', priority: 1 },
      { mapping_source: 'default',    mapping_value: null, role_id: 'role-temporary', role_name: 'Temporary', priority: 99 },
    ]);
    findUserByOid.mockResolvedValue(null);
    createUser.mockImplementation(async (u) => u);

    await resolveUser('company-1', {
      email: 'sales@example.com',
      oid: 'oid-sales',
      department: 'Sales',
      groups: [],
    }, 'oidc');

    expect(createUser).toHaveBeenCalledWith(expect.objectContaining({ roles: ['role-temporary'] }));
  });

  test('falls back to the role id as role_name when the mapping stores no name', async () => {
    // A mapping may store only the role id (RMS roles are per-tenant). When the
    // mapping has no role_name, resolveRoles surfaces the role with role_name =
    // role_id (and empty permissions — real permissions come from RMS/roleConfig).
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'department', mapping_value: 'IT', role_id: 'Field Technician', priority: 1 },
    ]);
    findUserByOid.mockResolvedValue(null);
    createUser.mockImplementation(async (u) => u);

    const { roles } = await resolveUser('company-1', {
      email: 'tech@example.com',
      oid: 'oid-tech',
      department: 'IT',
      groups: [],
    }, 'oidc');

    expect(roles).toEqual([
      { role_id: 'Field Technician', role_name: 'Field Technician', permissions: [] },
    ]);
  });

  test('denies a JIT login when no mapping matches and no default mapping exists', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'group', mapping_value: 'zdna-admins', role_id: 'role-admin', role_name: 'Admin', priority: 1 },
    ]);
    findUserByOid.mockResolvedValue(null);

    await expect(resolveUser('company-1', {
      email: 'norole@example.com',
      oid: 'oid-norole',
      groups: ['some-other-group'],
    }, 'oidc')).rejects.toMatchObject({
      statusCode: 403,
      code: 'NO_ROLE_ASSIGNED',
    });

    // Denied before provisioning — no orphan user row is left behind
    expect(createUser).not.toHaveBeenCalled();
    expect(updateUser).not.toHaveBeenCalled();
  });

  test('denies a JIT re-login when mappings no longer match, without wiping stored roles', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'department', mapping_value: 'IT', role_id: 'role-admin', role_name: 'Admin', priority: 1 },
    ]);
    findUserByOid.mockResolvedValue({ user_id: 'user-6', display_name: 'Existing User', roles: ['role-admin'] });

    await expect(resolveUser('company-1', {
      email: 'existing@example.com',
      oid: 'oid-6',
      department: 'Sales',
      groups: [],
    }, 'oidc')).rejects.toMatchObject({
      statusCode: 403,
      code: 'NO_ROLE_ASSIGNED',
    });

    expect(updateUser).not.toHaveBeenCalled();
  });

  test('updates an existing JIT user on re-login', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'default', mapping_value: null, role_id: 'role-manager', priority: 99 },
    ]);
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
      roles: ['role-manager'],
      display_name: 'New Name',
      last_login: expect.any(String),
    }));
    expect(result.action).toBe('updated');
  });

  test('falls back to non-JIT mode when the jit_enabled flag is turned off', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
    isEnabled.mockResolvedValue(false);
    findUserByOid.mockResolvedValue(null);
    findUserByEmail.mockResolvedValue({
      user_id: 'user-3',
      email: 'user@example.com',
      login_method: 'password',
      roles: ['role-temporary'],
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
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-2', jit_status: false });
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
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    findUserByOid.mockResolvedValue({
      user_id: 'user-4',
      email: 'user@example.com',
      oid: 'oid-4',
      login_method: 'sso',
      roles: ['role-manager'],
    });

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
        roles: ['role-manager'],
      },
      // Non-JIT roles are built from the user's stored role values (name = the
      // stored value); permissions come from RMS/Firestore downstream.
      roles: [{ role_id: 'role-manager', role_name: 'role-manager', permissions: [] }],
      action: 'login',
    });
  });

  test('denies a non-JIT login when the provisioned user has no roles', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    findUserByOid.mockResolvedValue({
      user_id: 'user-7',
      email: 'noroles@example.com',
      oid: 'oid-7',
      login_method: 'sso',
      roles: [],
    });

    await expect(resolveUser('company-1', {
      email: 'noroles@example.com',
      oid: 'oid-7',
      groups: [],
    }, 'oidc')).rejects.toMatchObject({
      statusCode: 403,
      code: 'NO_ROLE_ASSIGNED',
    });

    // Denied attempts are not recorded as a successful login
    expect(updateUser).not.toHaveBeenCalled();
  });

  test('denies a non-JIT login when the provisioned user has no roles column value', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    findUserByOid.mockResolvedValue(null);
    findUserByEmail.mockResolvedValue({
      user_id: 'user-8',
      email: 'nullroles@example.com',
      oid: 'pending:placeholder-uuid',
      login_method: 'sso',
      roles: null,
    });

    await expect(resolveUser('company-1', {
      email: 'nullroles@example.com',
      oid: 'real-oid-8',
      groups: [],
    }, 'oidc')).rejects.toMatchObject({
      statusCode: 403,
      code: 'NO_ROLE_ASSIGNED',
    });

    // oid backfill must not happen for a denied login either
    expect(updateUser).not.toHaveBeenCalled();
  });

  test('backfills a pending oid placeholder on first non-JIT login', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    // Pre-provisioned via POST /sso/users — real Entra oid unknown at creation
    findUserByOid.mockResolvedValue(null);
    findUserByEmail.mockResolvedValue({
      user_id: 'user-5',
      email: 'user5@example.com',
      oid: 'pending:placeholder-uuid',
      login_method: 'sso',
      roles: ['role-temporary'],
    });

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
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-3', jit_status: true });
    getJitMappings.mockResolvedValue([
      { mapping_source: 'default', mapping_value: null, role_id: 'role-manager', priority: 99 },
    ]);
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
      roles: ['role-manager'],
    }));
  });
});
