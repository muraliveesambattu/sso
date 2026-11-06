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

// ── Firestore mock ────────────────────────────────────
// resolveUser's non-JIT path walks two chains off admin.firestore():
//   collection('tenants').doc(id).collection('users').where('email').limit(1).get()
//   collection('tenants').doc(id).collection('users').where('UUID').get()
// plus collection('tenants').doc(id).update() for the tenant timestamp. The
// helper below returns that shape and exposes the write spies so a test can
// assert whether the "Joined" transition actually ran.
const firestoreDouble = ({ userDoc = null, uuidDoc = undefined, rejectUpdate = false } = {}) => {
  const userRefUpdate = rejectUpdate 
    ? jest.fn().mockRejectedValue(new Error('Firestore Write Failure'))
    : jest.fn().mockResolvedValue(undefined);
  const uuidRefUpdate = jest.fn().mockResolvedValue(undefined); // Uncoupled spy to avoid double trigger conflicts
  const tenantUpdate   = jest.fn().mockResolvedValue(undefined);

  // Step F re-queries by UUID; default to returning the same doc Step A found.
  const stepFDoc = uuidDoc === undefined ? userDoc : uuidDoc;

  const snapshotFor = (doc, updateSpy) => ({
    empty: !doc,
    docs: doc ? [{ data: () => doc, ref: { update: updateSpy } }] : [],
  });

  const usersCollection = {
    where: jest.fn((field) => (field === 'email'
      ? { limit: jest.fn(() => ({ get: jest.fn().mockResolvedValue(snapshotFor(userDoc, userRefUpdate)) })) }
      : { get: jest.fn().mockResolvedValue(snapshotFor(stepFDoc, uuidRefUpdate)) })),
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
  return { userRefUpdate, uuidRefUpdate, tenantUpdate };
};

const ssoUser = (over = {}) => ({
  email: 'user@example.com',
  loginMethod: 'Entra SSO',
  roleId: 'Admin',
  userUUID: 'uuid-user-1',
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
      { mapping_source: 'jobtitle',   mapping_value: 'engineer',   role_id: 'role-manager', role_name: 'Manager',   priority: 2 },
      { mapping_source: 'role',       mapping_value: 'Zdna.Admin', role_id: 'role-admin',   role_name: 'Admin',     priority: 3 },
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
    const user = ssoUser({ roleId: 'Manager', status: 'invited' });
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
      roles: [{ role_id: 'Manager', role_name: 'Manager', permissions: [] }], 
      action: 'login' 
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

    expect(roles).toEqual([{ role_id: 'Field Technician', role_name: 'Field Technician', permissions: [] }]);
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
    const { uuidRefUpdate } = firestoreDouble({
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
    // Change expectation: uuidRefUpdate must never run for the non-SSO account type.
    expect(uuidRefUpdate).not.toHaveBeenCalled(); 
  });

  test('tolerates a UUID re-query that returns nothing', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
    const { uuidRefUpdate } = firestoreDouble({ userDoc: ssoUser(), uuidDoc: null });

    const result = await resolveUser('company-1', {
      email: 'user@example.com',
      oid: 'oid-10',
      groups: [],
    }, 'oidc');

    expect(result.action).toBe('login');
    // Change expectation: uuidRefUpdate must never run for the missing UUID record.
    expect(uuidRefUpdate).not.toHaveBeenCalled(); 
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

  // ── Claim normalization and extraction fallback branches ──────────────────────
  describe('Claim normalization and extraction fallback branches', () => {
    test('extracts alternative claim combinations in SAML protocols', async () => {
      getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-saml', jit_status: true });
      getJitMappings.mockResolvedValue([
        { mapping_source: 'default', mapping_value: null, role_id: 'role-temporary', priority: 99 },
      ]);
      findUserByOid.mockResolvedValue(null);
      createUser.mockImplementation(async (u) => u);

      // Verify the claim resolution checks for alternate SAML namespaces (department/jobtitle/roles)
      await resolveUser('company-saml', {
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'saml.alt@example.com',
        'http://schemas.microsoft.com/identity/claims/objectidentifier': 'oid-saml-alt',
        givenname: 'GivenNameSAML',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department': 'Engineering',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/jobtitle': 'Staff Engineer',
        role: ['SAMLRole1', 'SAMLRole2']
      }, 'saml');

      expect(createUser).toHaveBeenCalledWith(expect.objectContaining({
        email: 'saml.alt@example.com',
        oid: 'oid-saml-alt',
        display_name: 'GivenNameSAML'
      }));
    });

    test('extracts alternative claim combinations in OIDC protocols', async () => {
      getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-oidc', jit_status: true });
      getJitMappings.mockResolvedValue([
        { mapping_source: 'default', mapping_value: null, role_id: 'role-temporary', priority: 99 },
      ]);
      findUserByOid.mockResolvedValue(null);
      createUser.mockImplementation(async (u) => u);

      // Verify claim resolution checks for alternate OIDC claim fields (preferred_username/upn/sub/jobtitle/roles)
      await resolveUser('company-oidc', {
        preferred_username: 'oidc.alt@example.com',
        sub: 'sub-oidc-alt',
        jobtitle: 'Architect',
        roles: ['OIDCRole1']
      }, 'oidc');

      expect(createUser).toHaveBeenCalledWith(expect.objectContaining({
        email: 'oidc.alt@example.com',
        oid: 'sub-oidc-alt',
        display_name: 'oidc.alt@example.com'
      }));

      // Test upn fallback
      await resolveUser('company-oidc', {
        upn: 'oidc.upn@example.com',
        sub: 'sub-oidc-upn'
      }, 'oidc');

      expect(createUser).toHaveBeenCalledWith(expect.objectContaining({
        email: 'oidc.upn@example.com',
        oid: 'sub-oidc-upn'
      }));
    });

    test('handles empty appRoles and claims arrays gracefully inside matchesMapping', async () => {
      getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
      getJitMappings.mockResolvedValue([
        { mapping_source: 'role', mapping_value: 'Zdna.Admin', role_id: 'role-admin', priority: 1 },
        { mapping_source: 'default', mapping_value: null, role_id: 'role-temporary', priority: 99 }
      ]);
      findUserByOid.mockResolvedValue(null);
      createUser.mockImplementation(async (u) => u);

      // Ensure that matchesMapping handles a custom claim evaluation where claim value is an array or string
      await resolveUser('company-1', {
        email: 'empty-role@example.com',
        oid: 'oid-empty-role',
        roles: undefined, // empty appRoles
        customClaim: ['Value1', 'Value2']
      }, 'oidc');

      expect(createUser).toHaveBeenCalledWith(expect.objectContaining({
        email: 'empty-role@example.com'
      }));
    });
  });

  describe('matchesMapping JIT mapping source evaluation', () => {
    test('compares mapped fields properly against array vs single elements', async () => {
      getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: true });
      getJitMappings.mockResolvedValue([
        { mapping_source: 'customField', mapping_value: 'match', role_id: 'role-custom', priority: 1 },
        { mapping_source: 'default', mapping_value: null, role_id: 'role-temporary', priority: 99 }
      ]);
      findUserByOid.mockResolvedValue(null);
      createUser.mockImplementation(async (u) => u);

      // Test single value custom mapping match
      await resolveUser('company-1', {
        email: 'custom@example.com',
        oid: 'oid-custom',
        customField: 'match'
      }, 'oidc');

      expect(createUser).toHaveBeenCalledWith(expect.objectContaining({ roles: ['role-custom'] }));
    });
  });

  describe('non-JIT login metadata and first name extraction auto-naming', () => {
    test('extracts firstName from split preferred_username on @ when firstName is empty', async () => {
      getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
      const user = ssoUser({ roleId: 'Manager', status: 'invited', firstName: '' });
      const { userRefUpdate } = firestoreDouble({
        userDoc: user,
        uuidDoc: { ...user, status: 'invited' },
      });

      await resolveUser('company-1', {
        email: 'user@example.com',
        oid: 'oid-name-extract',
        preferred_username: 'extractedname@example.com'
      }, 'oidc');

      expect(userRefUpdate).toHaveBeenCalledWith(expect.objectContaining({
        firstName: 'extractedname'
      }));
    });

    test('extracts firstName from split email on @ when preferred_username lacks @', async () => {
      getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
      const user = ssoUser({ roleId: 'Manager', status: 'invited', firstName: '', email: 'emailname@example.com' });
      const { userRefUpdate } = firestoreDouble({
        userDoc: user,
        uuidDoc: { ...user, status: 'invited' },
      });

      await resolveUser('company-1', {
        email: 'emailname@example.com',
        oid: 'oid-name-extract-email',
        preferred_username: 'NotAnEmail'
      }, 'oidc');

      expect(userRefUpdate).toHaveBeenCalledWith(expect.objectContaining({
        firstName: 'emailname'
      }));
    });

    test('handles errors during Firestore login metadata updates gracefully', async () => {
      getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1', jit_status: false });
      const user = ssoUser({ roleId: 'Manager', status: 'invited' });
      
      // Inject failure on database write to make sure try/catch wraps it safely without throwing
      firestoreDouble({
        userDoc: user,
        uuidDoc: { ...user, status: 'invited' },
        rejectUpdate: true
      });

      const result = await resolveUser('company-1', {
        email: 'user@example.com',
        oid: 'oid-write-fail'
      }, 'oidc');

      // Execution succeeds and login continues despite write failure
      expect(result.action).toBe('login');
    });
  });
});