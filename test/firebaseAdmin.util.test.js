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

  jest.doMock('../src/config/logger', () => ({
    logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
  }));
  jest.doMock('firebase-admin', () => ({
    apps: adminApps,
    auth,
    initializeApp,
    credential: { cert },
  }));

  const { generateCustomToken } = require('../src/utils/firebase/firebaseAdmin.util');
  return { generateCustomToken, adminMock: { auth, createCustomToken, cert, initializeApp } };
};

describe('firebaseAdmin.util', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  test('returns a mock token in local dev mode when Firebase is not configured', async () => {
    const { generateCustomToken, adminMock } = loadFirebaseUtil();

    const token = await generateCustomToken('user-1', {
      email: 'user@example.com',
      role: 'Administrator',
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
      role: 'Analyst',
      roles: [
        { role_id: 'role-analyst', role_name: 'Analyst', permissions: ['read', 'write'] },
        // JSON-store rows may carry permissions as a string — must be parsed
        { role_id: 'role-viewer', role_name: 'Viewer', permissions: '["read"]' },
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
      role: 'Analyst',
      tenantId: 'user-2',
      identity: 'user-2',
      loginType: 'entra',
      companyId: 'company-2',
      displayName: 'User Two',
      zdnaRoles: [
        { id: 'role-analyst', name: 'Analyst' },
        { id: 'role-viewer', name: 'Viewer' },
      ],
      zdnaPermissions: ['read', 'write'],
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
      role: 'Analyst',
      roles: [{ role_id: 'role-analyst', role_name: 'Analyst', permissions: ['read', 'write'] }],
      permissions: ['console:dashboard'],   // from permissionResolver (role-mgmt service)
      companyId: 'company-5',
      displayName: 'User Five',
    });

    expect(adminMock.createCustomToken).toHaveBeenCalledWith('user-5', expect.objectContaining({
      zdnaPermissions: ['console:dashboard'],
    }));
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
      role: 'Analyst',
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
      role: 'Viewer',
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
      role: 'Viewer',
      companyId: 'company-4',
      displayName: 'User Four',
    })).rejects.toMatchObject({
      statusCode: 500,
      code: 'FIREBASE_TOKEN_FAILED',
    });
  });
});
