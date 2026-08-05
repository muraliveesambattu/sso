const loadFirebaseUtil = ({
  env = {},
  adminApps = [],
  createCustomTokenImpl,
  tenantDoc,            // controls what a Firestore doc .get() resolves to
  roleConfigSnap,       // controls what the roleConfig where().limit().get() resolves to
  verifyIdTokenImpl,
} = {}) => {
  jest.resetModules();

  delete process.env.FIREBASE_PROJECT_ID;
  delete process.env.FIREBASE_CLIENT_EMAIL;
  delete process.env.FIREBASE_PRIVATE_KEY;
  delete process.env.FIREBASE_CONFIG;
  delete process.env.FUNCTIONS_EMULATOR;
  delete process.env.GCLOUD_PROJECT;
  Object.assign(process.env, env);

  const createCustomToken = jest.fn(createCustomTokenImpl || (async () => 'firebase-token'));
  const verifyIdToken = jest.fn(verifyIdTokenImpl || (async () => ({ uid: 'uid-1', email: 'user@example.com' })));
  const auth = jest.fn(() => ({ createCustomToken, verifyIdToken }));
  const cert = jest.fn((config) => ({ kind: 'cert', config }));
  const initializeApp = jest.fn();

  // Chainable Firestore mock: collection().doc().collection().doc().set()
  const permissionSet = jest.fn(async () => undefined);
  const tenantGet = jest.fn(async () => (tenantDoc || { exists: false, data: () => ({}) }));
  const firestorePath = [];
  const chain = {
    collection: jest.fn((c) => { firestorePath.push(['collection', c]); return chain; }),
    doc: jest.fn((d) => { firestorePath.push(['doc', d]); return chain; }),
    set: permissionSet,
    get: tenantGet,
    // getRolePermissionStrings ends in .where('roleName','==',x).limit(1).get()
    where: jest.fn(() => ({
      limit: jest.fn(() => ({
        get: jest.fn(async () => roleConfigSnap || { empty: true, docs: [] }),
      })),
    })),
  };
  const firestore = jest.fn(() => chain);

  jest.doMock('../src/config/logger', () => ({
    logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
  }));
  jest.doMock('firebase-admin', () => ({
    apps: adminApps,
    auth,
    firestore,
    initializeApp,
    credential: { cert },
  }));

  const {
    generateCustomToken, transformRolePermissions, getTenantFriendlyId,
    getRolePermissionStrings, verifyIdToken: verifyIdTokenUnderTest,
  } = require('../src/utils/firebase/firebaseAdmin.util');
  return {
    generateCustomToken, transformRolePermissions, getTenantFriendlyId,
    getRolePermissionStrings, verifyIdToken: verifyIdTokenUnderTest,
    adminMock: { auth, createCustomToken, verifyIdToken, cert, initializeApp, firestore, permissionSet, tenantGet, firestorePath },
  };
};

describe('firebaseAdmin.util', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  test('transformRolePermissions maps a role config matrix to enforcement permissionStrings', () => {
    const { transformRolePermissions } = loadFirebaseUtil();

    const managerMatrix = {
      'My Services': 'No Access',
      'Users': 'No Access',
      'My Devices': 'Editable',
      'Licensing': 'View Only',
      'Unknown Feature': 'Editable',   // unmapped → dropped
    };

    expect(transformRolePermissions(managerMatrix)).toEqual([
      { permissionString: 'zdna.all' },
      { permissionString: 'zdna.myServices.noaccess' },
      { permissionString: 'zdna.userManagement.noaccess' },
      { permissionString: 'zdna.myDevice.edit' },
      { permissionString: 'zdna.licensing.view' },
    ]);
    // Always includes the base grant; unmapped features are excluded
    expect(transformRolePermissions({}).map(p => p.permissionString)).toEqual(['zdna.all']);
  });

  test('returns a mock token in local dev mode when Firebase is not configured', async () => {
    const { generateCustomToken, adminMock } = loadFirebaseUtil();

    const token = await generateCustomToken('user-1', {
      email: 'user@example.com',
      role: 'Admin',
      companyId: 'company-1',
      displayName: 'User One',
    });

    expect(token).toMatch(/^dev-mock-token::user-1::user@example\.com::\d+$/);
    expect(adminMock.initializeApp).not.toHaveBeenCalled();
    expect(adminMock.auth).not.toHaveBeenCalled();
  });

  test('initializes Firebase with service account credentials and creates custom tokens', async () => {
    const { generateCustomToken, adminMock } = loadFirebaseUtil({
      env: {
        FIREBASE_PROJECT_ID: 'dnacloud-demo2-t',
        FIREBASE_CLIENT_EMAIL: 'firebase-admin@example.test',
        FIREBASE_PRIVATE_KEY: String.raw`-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n`,
      },
    });

    const token = await generateCustomToken('user-2', {
      email: 'user2@example.com',
      role: 'Manager',
      roles: [
        { role_id: 'role-manager', role_name: 'Manager', permissions: [] },
        { role_id: 'role-temporary', role_name: 'Temporary', permissions: [] },
      ],
      // Permissions arrive pre-resolved from permissionResolver (RMS → Firestore).
      permissions: ['my_devices:editable', 'licensing:editable'],
      companyId: 'company-2',
      displayName: 'User Two',
    });

    expect(adminMock.cert).toHaveBeenCalledWith({
      projectId: 'dnacloud-demo2-t',
      clientEmail: 'firebase-admin@example.test',
      privateKey: '-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n',
    });
    expect(adminMock.initializeApp).toHaveBeenCalledWith({
      credential: {
        kind: 'cert',
        config: expect.objectContaining({ projectId: 'dnacloud-demo2-t' }),
      },
    });
    expect(adminMock.createCustomToken).toHaveBeenCalledWith('user-2', {
      email: 'user2@example.com',
      // Firestore rules gate on role "Tenant Owner"/"Administrative User" + identity == tenant,
      // so the token mirrors the native/console model (real role stays in zdnaRoles).
      role: 'Tenant Owner',
      tenantId: 'user-2',
      identity: 'company-2',
      loginType: 'entra',
      companyId: 'company-2',
      friendlyId: null,
      displayName: 'User Two',
      zdnaRoles: [
        { id: 'role-manager', name: 'Manager' },
        { id: 'role-temporary', name: 'Temporary' },
      ],
      zdnaPermissions: ['my_devices:editable', 'licensing:editable'],
    });
    expect(token).toBe('firebase-token');
  });

  const FIREBASE_ENV = {
    FIREBASE_PROJECT_ID: 'dnacloud-demo2-t',
    FIREBASE_CLIENT_EMAIL: 'firebase-admin@example.test',
    FIREBASE_PRIVATE_KEY: String.raw`-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n`,
  };

  test('propagates a provided friendlyId into the token claims (SSO parity with native login)', async () => {
    const { generateCustomToken, adminMock } = loadFirebaseUtil({ env: FIREBASE_ENV });

    await generateCustomToken('user-3', {
      email: 'user3@example.com',
      role: 'Admin',
      companyId: 'company-3',
      friendlyId: 'ad954a56',
      displayName: 'User Three',
    });

    expect(adminMock.createCustomToken).toHaveBeenCalledWith('user-3',
      expect.objectContaining({ friendlyId: 'ad954a56', companyId: 'company-3' }));
  });

  test('getTenantFriendlyId reads friendlyId from the tenants/{companyId} doc', async () => {
    const { getTenantFriendlyId, adminMock } = loadFirebaseUtil({
      env: FIREBASE_ENV,
      tenantDoc: { exists: true, data: () => ({ friendlyId: 'ad954a56' }) },
    });

    expect(await getTenantFriendlyId('company-3')).toBe('ad954a56');
    expect(adminMock.firestore().collection).toHaveBeenCalledWith('tenants');
  });

  test('getTenantFriendlyId returns null when the tenant doc is missing or has no friendlyId', async () => {
    const missing = loadFirebaseUtil({ env: FIREBASE_ENV, tenantDoc: { exists: false, data: () => ({}) } });
    expect(await missing.getTenantFriendlyId('company-x')).toBeNull();

    const noField = loadFirebaseUtil({ env: FIREBASE_ENV, tenantDoc: { exists: true, data: () => ({}) } });
    expect(await noField.getTenantFriendlyId('company-y')).toBeNull();
  });

  test('getTenantFriendlyId returns null in dev mode (Firebase not configured) without touching Firestore', async () => {
    const { getTenantFriendlyId, adminMock } = loadFirebaseUtil();
    expect(await getTenantFriendlyId('company-3')).toBeNull();
    expect(adminMock.tenantGet).not.toHaveBeenCalled();
  });

  test('prefers pre-resolved permissions over the zdna_roles union', async () => {
    const { generateCustomToken, adminMock } = loadFirebaseUtil({
      env: {
        FIREBASE_PROJECT_ID: 'dnacloud-demo2-t',
        FIREBASE_CLIENT_EMAIL: 'firebase-admin@example.test',
        FIREBASE_PRIVATE_KEY: String.raw`-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n`,
      },
    });

    await generateCustomToken('user-5', {
      email: 'user5@example.com',
      role: 'Manager',
      roles: [{ role_id: 'role-manager', role_name: 'Manager', permissions: ['my_devices:editable'] }],
      permissions: ['console:dashboard'],   // from permissionResolver (role-mgmt service)
      companyId: 'company-5',
      displayName: 'User Five',
    });

    expect(adminMock.createCustomToken).toHaveBeenCalledWith('user-5', expect.objectContaining({
      zdnaPermissions: ['console:dashboard'],
    }));
  });

  test('provisions the per-user Firestore permissionList doc the console reads', async () => {
    const { generateCustomToken, adminMock } = loadFirebaseUtil({
      env: {
        FIREBASE_PROJECT_ID: 'dnacloud-demo2-t',
        FIREBASE_CLIENT_EMAIL: 'firebase-admin@example.test',
        FIREBASE_PRIVATE_KEY: String.raw`-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n`,
      },
    });

    const perms = [
      { permissionString: 'zdna.myServices.noaccess', permissionId: 38 },
      { permissionString: 'zdna.userManagement.noaccess', permissionId: 44 },
    ];
    await generateCustomToken('sso-uid-1', {
      email: 'mgr@example.com',
      role: 'Manager',
      roles: [{ role_id: 'Manager', role_name: 'Manager' }],
      permissions: perms,
      companyId: 'company-xyz',
      displayName: 'Manager User',
    });

    // Path: tenants/{companyId}/users/{uid}/userPermissions/permissionList
    expect(adminMock.firestorePath).toEqual([
      ['collection', 'tenants'],
      ['doc', 'company-xyz'],
      ['collection', 'users'],
      ['doc', 'sso-uid-1'],
      ['collection', 'userPermissions'],
      ['doc', 'permissionList'],
    ]);
    expect(adminMock.permissionSet).toHaveBeenCalledWith({ permissions: perms });
  });

  test('does not fail token generation when the Firestore write throws', async () => {
    const { generateCustomToken, adminMock } = loadFirebaseUtil({
      env: {
        FIREBASE_PROJECT_ID: 'dnacloud-demo2-t',
        FIREBASE_CLIENT_EMAIL: 'firebase-admin@example.test',
        FIREBASE_PRIVATE_KEY: String.raw`-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n`,
      },
    });
    adminMock.permissionSet.mockRejectedValueOnce(new Error('firestore down'));

    const token = await generateCustomToken('sso-uid-2', {
      email: 'mgr2@example.com',
      role: 'Manager',
      roles: [],
      permissions: [{ permissionString: 'x', permissionId: 1 }],
      companyId: 'company-abc',
      displayName: 'Mgr Two',
    });

    // Login/token still succeeds despite the write failure (best-effort).
    expect(token).toBe('firebase-token');
    expect(adminMock.createCustomToken).toHaveBeenCalled();
  });

  test('defers oversized permission lists to /sso/me instead of blowing the claim budget', async () => {
    const { generateCustomToken, adminMock } = loadFirebaseUtil({
      env: {
        FIREBASE_PROJECT_ID: 'dnacloud-demo2-t',
        FIREBASE_CLIENT_EMAIL: 'firebase-admin@example.test',
        FIREBASE_PRIVATE_KEY: String.raw`-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n`,
      },
    });

    const hugePermissions = Array.from({ length: 60 }, (_, i) => `console:feature:${i}:noaccess`);
    await generateCustomToken('user-6', {
      email: 'user6@example.com',
      role: 'Manager',
      roles: [],
      permissions: hugePermissions,
      companyId: 'company-6',
      displayName: 'User Six',
    });

    expect(adminMock.createCustomToken).toHaveBeenCalledWith('user-6', expect.objectContaining({
      zdnaPermissions: [],
      zdnaPermissionsRef: 'me',
    }));
  });

  test('auto-initializes with default credentials in Firebase runtime environments', async () => {
    const { generateCustomToken, adminMock } = loadFirebaseUtil({
      env: { GCLOUD_PROJECT: 'firebase-project' },
    });

    await generateCustomToken('user-3', {
      email: 'user3@example.com',
      role: 'Temporary',
      companyId: 'company-3',
      displayName: 'User Three',
    });

    expect(adminMock.initializeApp).toHaveBeenCalledWith();
    expect(adminMock.createCustomToken).toHaveBeenCalled();
  });

  // ── getRolePermissionStrings ────────────────────────────────────────────────
  // Reads tenants/{id}/tenantConfig/roleConfig/roleConfig where roleName == x.
  // Every failure mode returns [] rather than throwing — a permissions lookup
  // must never break a login.
  const CONFIGURED_ENV = {
    FIREBASE_PROJECT_ID: 'proj', FIREBASE_CLIENT_EMAIL: 'sa@proj.iam', FIREBASE_PRIVATE_KEY: 'key',
  };

  test('getRolePermissionStrings derives permission strings from the roleConfig doc', async () => {
    const { getRolePermissionStrings } = loadFirebaseUtil({
      env: CONFIGURED_ENV,
      roleConfigSnap: {
        empty: false,
        docs: [{ data: () => ({ permissions: { deviceManagement: { view: true, edit: true } } }) }],
      },
    });

    const perms = await getRolePermissionStrings('company-1', 'Manager');
    expect(Array.isArray(perms)).toBe(true);
    expect(perms.length).toBeGreaterThan(0);
  });

  test('getRolePermissionStrings returns [] when no roleConfig doc matches the role', async () => {
    const { getRolePermissionStrings } = loadFirebaseUtil({
      env: CONFIGURED_ENV,
      roleConfigSnap: { empty: true, docs: [] },
    });

    await expect(getRolePermissionStrings('company-1', 'Nonexistent')).resolves.toEqual([]);
  });

  test('getRolePermissionStrings returns [] without touching Firestore when args are missing', async () => {
    const { getRolePermissionStrings, adminMock } = loadFirebaseUtil({ env: CONFIGURED_ENV });

    await expect(getRolePermissionStrings(null, 'Manager')).resolves.toEqual([]);
    await expect(getRolePermissionStrings('company-1', null)).resolves.toEqual([]);
    expect(adminMock.firestore).not.toHaveBeenCalled();
  });

  test('getRolePermissionStrings returns [] in dev mode (Firebase not configured)', async () => {
    const { getRolePermissionStrings, adminMock } = loadFirebaseUtil();

    await expect(getRolePermissionStrings('company-1', 'Manager')).resolves.toEqual([]);
    expect(adminMock.firestore).not.toHaveBeenCalled();
  });

  test('getRolePermissionStrings swallows a Firestore failure — a read must not break login', async () => {
    const { getRolePermissionStrings } = loadFirebaseUtil({
      env: CONFIGURED_ENV,
      roleConfigSnap: null,
    });
    // Force the query itself to reject
    const admin = require('firebase-admin');
    admin.firestore.mockImplementationOnce(() => { throw new Error('permission denied'); });

    await expect(getRolePermissionStrings('company-1', 'Manager')).resolves.toEqual([]);
  });

  // ── verifyIdToken ───────────────────────────────────────────────────────────
  test('verifyIdToken delegates to the Admin SDK and returns the decoded claims', async () => {
    const { verifyIdToken, adminMock } = loadFirebaseUtil({
      env: CONFIGURED_ENV,
      verifyIdTokenImpl: async () => ({ uid: 'uid-9', email: 'a@b.com', companyId: 'c1' }),
    });

    await expect(verifyIdToken('id-token')).resolves.toMatchObject({ uid: 'uid-9', companyId: 'c1' });
    expect(adminMock.verifyIdToken).toHaveBeenCalledWith('id-token');
  });

  test('verifyIdToken throws 503 AUTH_NOT_CONFIGURED when the SDK has no credentials', async () => {
    const { verifyIdToken, adminMock } = loadFirebaseUtil(); // dev mode, nothing configured

    await expect(verifyIdToken('id-token')).rejects.toMatchObject({
      statusCode: 503, code: 'AUTH_NOT_CONFIGURED',
    });
    expect(adminMock.auth).not.toHaveBeenCalled();
  });

  test('verifyIdToken propagates an invalid-token rejection from the SDK', async () => {
    const { verifyIdToken } = loadFirebaseUtil({
      env: CONFIGURED_ENV,
      verifyIdTokenImpl: async () => { throw new Error('Firebase ID token has expired'); },
    });

    await expect(verifyIdToken('stale')).rejects.toThrow('Firebase ID token has expired');
  });

  test('wraps Firebase SDK failures with a service-specific error code', async () => {
    const { generateCustomToken } = loadFirebaseUtil({
      env: {
        FIREBASE_PROJECT_ID: 'dnacloud-demo2-t',
        FIREBASE_CLIENT_EMAIL: 'firebase-admin@example.test',
        FIREBASE_PRIVATE_KEY: String.raw`-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n`,
      },
      createCustomTokenImpl: async () => {
        throw new Error('boom');
      },
    });

    await expect(generateCustomToken('user-4', {
      email: 'user4@example.com',
      role: 'Temporary',
      companyId: 'company-4',
      displayName: 'User Four',
    })).rejects.toMatchObject({
      statusCode: 500,
      code: 'FIREBASE_TOKEN_FAILED',
    });
  });
});
