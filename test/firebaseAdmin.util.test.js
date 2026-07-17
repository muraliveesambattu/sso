const loadFirebaseUtil = ({
  env = {},
  adminApps = [],
  createCustomTokenImpl,
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
  const auth = jest.fn(() => ({ createCustomToken }));
  const cert = jest.fn((config) => ({ kind: 'cert', config }));
  const initializeApp = jest.fn();

  // Chainable Firestore mock: collection().doc().collection().doc().set()
  const permissionSet = jest.fn(async () => undefined);
  const firestorePath = [];
  const chain = {
    collection: jest.fn((c) => { firestorePath.push(['collection', c]); return chain; }),
    doc: jest.fn((d) => { firestorePath.push(['doc', d]); return chain; }),
    set: permissionSet,
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

  const { generateCustomToken, transformRolePermissions } = require('../src/utils/firebase/firebaseAdmin.util');
  return { generateCustomToken, transformRolePermissions, adminMock: { auth, createCustomToken, cert, initializeApp, firestore, permissionSet, firestorePath } };
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
        FIREBASE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----\\n',
      },
    });

    const token = await generateCustomToken('user-2', {
      email: 'user2@example.com',
      role: 'Manager',
      roles: [
        { role_id: 'role-manager', role_name: 'Manager', permissions: ['my_devices:editable', 'licensing:editable'] },
        // JSON-store rows may carry permissions as a string — must be parsed
        { role_id: 'role-temporary', role_name: 'Temporary', permissions: '["licensing:editable"]' },
      ],
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
      role: 'Manager',
      tenantId: 'user-2',
      identity: 'user-2',
      loginType: 'entra',
      companyId: 'company-2',
      displayName: 'User Two',
      zdnaRoles: [
        { id: 'role-manager', name: 'Manager' },
        { id: 'role-temporary', name: 'Temporary' },
      ],
      zdnaPermissions: ['my_devices:editable', 'licensing:editable'],
    });
    expect(token).toBe('firebase-token');
  });

  test('prefers pre-resolved permissions over the zdna_roles union', async () => {
    const { generateCustomToken, adminMock } = loadFirebaseUtil({
      env: {
        FIREBASE_PROJECT_ID: 'dnacloud-demo2-t',
        FIREBASE_CLIENT_EMAIL: 'firebase-admin@example.test',
        FIREBASE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----\\n',
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
        FIREBASE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----\\n',
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
        FIREBASE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----\\n',
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
        FIREBASE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----\\n',
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

  test('wraps Firebase SDK failures with a service-specific error code', async () => {
    const { generateCustomToken } = loadFirebaseUtil({
      env: {
        FIREBASE_PROJECT_ID: 'dnacloud-demo2-t',
        FIREBASE_CLIENT_EMAIL: 'firebase-admin@example.test',
        FIREBASE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----\\n',
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
