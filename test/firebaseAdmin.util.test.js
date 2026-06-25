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
    });
    expect(token).toBe('firebase-token');
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
