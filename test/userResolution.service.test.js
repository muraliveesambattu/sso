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

// The non-JIT path reads and writes Firestore directly (the JIT path still uses
// the Postgres data service above), so firebase-admin is mocked rather than
// initialised.
jest.mock('firebase-admin', () => ({ firestore: jest.fn() }));

const crypto = require('node:crypto');
const admin = require('firebase-admin');
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

// ── Firestore mock ────────────────────────────────────────────────────────────
// resolveUser's non-JIT path walks two chains off admin.firestore():
//   collection('tenants').doc(id).collection('users').where('email').limit(1).get()
//   collection('tenants').doc(id).collection('users').where('UUID').get()
// plus collection('tenants').doc(id).update() for the tenant timestamp. The
// helper below returns that shape and exposes the write spies so a test can
// assert whether the "Joined" transition actually ran.
const firestoreDouble = ({ userDoc = null, uuidDoc = undefined } = {}) => {
  const userRefUpdate = jest.fn().mockResolvedValue(undefined);
  const tenantUpdate  = jest.fn().mockResolvedValue(undefined);

  // Step F re-queries by UUID; default to returning the same doc Step A found.
  const stepFDoc = uuidDoc === undefined ? userDoc : uuidDoc;

  const snapshotFor = (doc) => ({
    empty: !doc,
    docs: doc ? [{ data: () => doc, ref: { update: userRefUpdate } }] : [],
  });

  const usersCollection = {
    where: jest.fn((field) => (field === 'email'
      ? { limit: jest.fn(() => ({ get: jest.fn().mockResolvedValue(snapshotFor(userDoc)) })) }
      : { get: jest.fn().mockResolvedValue(snapshotFor(stepFDoc)) })),
  };

  const db = {
    collection: jest.fn(() => ({
      doc: jest.fn(() => ({
        collection: jest.fn(() => usersCollection),
        update: tenantUpdate,
      })),
    })),
  };

  admin.firestore.mockReturnValue(db);
  return { userRefUpdate, tenantUpdate };
};

// Mirrors the real Firestore document: the id and the display name are two
// separate fields, and both matter downstream (permissionResolver keys the
// roleConfig lookup on the name).
const ssoUser = (over = {}) => ({
  email: 'user@example.com',
  loginMethod: 'Entra SSO',
  roleId: 15559,
  roleName: 'Manager',
  UUID: 'uuid-user-1',
  status: 'Joined',
  ...over,
});

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

  test('falls back to non-JIT mode when the jit_enabled feature flag is turned off', async () => {
    // jit_status is true on the record, but the kill-switch flag wins — so the
    // Firestore (non-JIT) path runs and rejects the password-based account.
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
    isEnabled.mockResolvedValue(false);
    firestoreDouble({ userDoc: ssoUser({ loginMethod: 'password' }) });

    await expect(resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-3',
      name: 'User Three',
      groups: [],
    }, 'oidc')).rejects.toMatchObject({
      statusCode: 403,
      code: 'LOGIN_METHOD_NOT_ALLOWED',
    });

    expect(getJitMappings).not.toHaveBeenCalled();
  });

  test('rejects a non-JIT login when Firestore has no user for that email', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-2', jit_status: false });
    firestoreDouble({ userDoc: null });

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

  test('rejects a non-JIT login for an expired account', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    firestoreDouble({ userDoc: ssoUser({ status: 'expired' }) });

    await expect(resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-exp',
      groups: [],
    }, 'oidc')).rejects.toMatchObject({
      statusCode: 403,
      code: 'USER_EXPIRED',
    });
  });

  test('allows a non-JIT login, flips the user to Joined, and stamps both documents', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    const user = ssoUser({ status: 'invited' });
    const { userRefUpdate, tenantUpdate } = firestoreDouble({
      userDoc: user,
      // Step F re-reads by UUID; the stored doc still says Entra SSO
      uuidDoc: { ...user, status: 'invited' },
    });

    const result = await resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-4',
      name: 'User Four',
      groups: [],
    }, 'oidc');

    expect(result).toEqual({
      user,
      roles: [{ role_id: 15559, role_name: 'Manager', permissions: [] }],
      action: 'login',
    });

    expect(userRefUpdate).toHaveBeenCalledWith({
      status: 'Joined',
      lastLoginTime: expect.any(Number),
      updatedDateTime: expect.any(Number),
    });
    expect(tenantUpdate).toHaveBeenCalledWith({
      lastLoginTime: expect.any(Number),
      updatedDateTime: expect.any(Number),
    });
  });

  test('accepts role_id as an alias for roleId', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    firestoreDouble({ userDoc: ssoUser({ roleId: undefined, role_id: 'Field Technician' }) });

    const { roles } = await resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-alias',
      groups: [],
    }, 'oidc');

    expect(roles).toEqual([
      { role_id: 'Field Technician', role_name: 'Manager', permissions: [] },
    ]);
  });

  // role_name drives two things downstream: permissionResolver's roleConfig
  // lookup (which is skipped entirely without it, leaving the user with zero
  // permissions) and the custom token's `role` claim, which otherwise falls
  // back to the literal string 'user'.
  test('carries roleName through as role_name so permissions can resolve', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    firestoreDouble({ userDoc: ssoUser({ roleId: 42, roleName: 'Field Technician' }) });

    const { roles } = await resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-name',
      groups: [],
    }, 'oidc');

    expect(roles).toEqual([
      { role_id: 42, role_name: 'Field Technician', permissions: [] },
    ]);
    // Both token-mint paths read roles[0].role_name for the `role` claim
    expect(roles[0].role_name).not.toBe('user');
  });

  test('falls back to the role id when the document carries no roleName', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    firestoreDouble({ userDoc: ssoUser({ roleId: 15559, roleName: undefined }) });

    const { roles } = await resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-noname',
      groups: [],
    }, 'oidc');

    expect(roles).toEqual([{ role_id: 15559, role_name: 15559, permissions: [] }]);
  });

  test('denies a non-JIT login when the provisioned user carries no role', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    const { userRefUpdate, tenantUpdate } = firestoreDouble({
      userDoc: ssoUser({ roleId: undefined, role_id: undefined }),
    });

    await expect(resolveUser('company-1', {
      email: 'noroles@example.com',
      oid: 'oid-7',
      groups: [],
    }, 'oidc')).rejects.toMatchObject({
      statusCode: 403,
      code: 'NO_ROLE_ASSIGNED',
    });

    // Denied before Step F — no "Joined" transition, no lastLoginTime stamp
    expect(userRefUpdate).not.toHaveBeenCalled();
    expect(tenantUpdate).not.toHaveBeenCalled();
  });

  test('skips the Joined transition when the stored doc is not an SSO account', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    const { userRefUpdate, tenantUpdate } = firestoreDouble({
      userDoc: ssoUser(),
      // Step A saw an SSO account, but the UUID re-query returns a different one
      uuidDoc: { loginMethod: 'password' },
    });

    const result = await resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-9',
      groups: [],
    }, 'oidc');

    expect(result.action).toBe('login');
    expect(userRefUpdate).not.toHaveBeenCalled();
    expect(tenantUpdate).not.toHaveBeenCalled();
  });

  test('tolerates a UUID re-query that returns nothing', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    const { userRefUpdate } = firestoreDouble({ userDoc: ssoUser(), uuidDoc: null });

    const result = await resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-10',
      groups: [],
    }, 'oidc');

    expect(result.action).toBe('login');
    expect(userRefUpdate).not.toHaveBeenCalled();
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
