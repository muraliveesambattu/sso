jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/utils/firebase/firebaseAdmin.util', () => ({
  verifyIdToken: jest.fn(),
}));

jest.mock('../src/services/db/ssoDataService', () => ({
  findUserById: jest.fn(),
  getRolesByIds: jest.fn(),
}));

const { requireAdminKeyOrPermission, requireUser } = require('../src/middlewares/userAuth.middleware');
const { verifyIdToken } = require('../src/utils/firebase/firebaseAdmin.util');
const { findUserById, getRolesByIds } = require('../src/services/db/ssoDataService');

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

const mockReq = (overrides = {}) => ({
  headers: {},
  params: {},
  query: {},
  body: {},
  path: '/v1/auth/sso/config',
  ip: '127.0.0.1',
  ...overrides,
});

describe('userAuth.middleware', () => {
  const OLD_ENV = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...OLD_ENV, ADMIN_API_KEY: 'super-secret-key' };
  });

  afterAll(() => {
    process.env = OLD_ENV;
  });

  describe('requireAdminKeyOrPermission', () => {
    test('delegates to admin-key auth when X-Admin-API-Key header is present', async () => {
      const req = mockReq({ headers: { 'x-admin-api-key': 'super-secret-key' } });
      const next = jest.fn();

      await requireAdminKeyOrPermission('write')(req, mockRes(), next);

      expect(next).toHaveBeenCalledWith(); // admin key valid → pass-through
      expect(verifyIdToken).not.toHaveBeenCalled();
    });

    test('rejects a wrong admin key without falling back to Bearer auth', async () => {
      const req = mockReq({ headers: { 'x-admin-api-key': 'wrong-key' } });
      const res = mockRes();
      const next = jest.fn();

      await requireAdminKeyOrPermission('write')(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(verifyIdToken).not.toHaveBeenCalled();
    });

    test('401 MISSING_ID_TOKEN when neither admin key nor Bearer token is sent', async () => {
      const req = mockReq();
      const next = jest.fn();

      await requireAdminKeyOrPermission('write')(req, mockRes(), next);

      expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 401, code: 'MISSING_ID_TOKEN' }));
    });

    test('401 INVALID_ID_TOKEN when token verification fails', async () => {
      verifyIdToken.mockRejectedValue(new Error('bad token'));
      const req = mockReq({ headers: { authorization: 'Bearer bad-token' } });
      const next = jest.fn();

      await requireAdminKeyOrPermission('write')(req, mockRes(), next);

      expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 401, code: 'INVALID_ID_TOKEN' }));
    });

    test('403 USER_NOT_PROVISIONED when the uid has no sso_users record', async () => {
      verifyIdToken.mockResolvedValue({ uid: 'user-1', email: 'a@b.com', companyId: 'company-1' });
      findUserById.mockResolvedValue(null);
      const req = mockReq({ headers: { authorization: 'Bearer good-token' } });
      const next = jest.fn();

      await requireAdminKeyOrPermission('write')(req, mockRes(), next);

      expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 403, code: 'USER_NOT_PROVISIONED' }));
    });

    test('403 INSUFFICIENT_PERMISSIONS when roles lack the required permission', async () => {
      verifyIdToken.mockResolvedValue({ uid: 'user-1', email: 'a@b.com', companyId: 'company-1' });
      findUserById.mockResolvedValue({ user_id: 'user-1', company_id: 'company-1', roles: ['role-viewer'] });
      getRolesByIds.mockResolvedValue([{ role_id: 'role-viewer', role_name: 'Viewer', permissions: ['read'] }]);
      const req = mockReq({ headers: { authorization: 'Bearer good-token' } });
      const next = jest.fn();

      await requireAdminKeyOrPermission('write')(req, mockRes(), next);

      expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 403, code: 'INSUFFICIENT_PERMISSIONS' }));
    });

    test('403 COMPANY_SCOPE_VIOLATION when targeting another company', async () => {
      verifyIdToken.mockResolvedValue({ uid: 'user-1', email: 'a@b.com', companyId: 'company-1' });
      findUserById.mockResolvedValue({ user_id: 'user-1', company_id: 'company-1', roles: ['role-admin'] });
      getRolesByIds.mockResolvedValue([{ role_id: 'role-admin', role_name: 'Administrator', permissions: ['read', 'write', 'delete', 'manage_users'] }]);
      const req = mockReq({
        headers: { authorization: 'Bearer good-token' },
        params: { company_id: 'company-OTHER' },
      });
      const next = jest.fn();

      await requireAdminKeyOrPermission('write')(req, mockRes(), next);

      expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 403, code: 'COMPANY_SCOPE_VIOLATION' }));
    });

    test('passes and attaches req.user when permission + company scope match', async () => {
      verifyIdToken.mockResolvedValue({ uid: 'user-1', email: 'a@b.com', companyId: 'company-1' });
      findUserById.mockResolvedValue({ user_id: 'user-1', email: 'a@b.com', company_id: 'company-1', roles: ['role-admin'] });
      getRolesByIds.mockResolvedValue([{ role_id: 'role-admin', role_name: 'Administrator', permissions: ['read', 'write', 'delete', 'manage_users'] }]);
      const req = mockReq({
        headers: { authorization: 'Bearer good-token' },
        query: { company_id: 'company-1' },
      });
      const next = jest.fn();

      await requireAdminKeyOrPermission('write')(req, mockRes(), next);

      expect(next).toHaveBeenCalledWith();
      expect(req.user).toMatchObject({
        uid: 'user-1',
        companyId: 'company-1',
        permissions: expect.arrayContaining(['read', 'write', 'delete', 'manage_users']),
      });
    });

    test('permissions from zdna_roles stored as JSON strings are parsed', async () => {
      verifyIdToken.mockResolvedValue({ uid: 'user-1', email: 'a@b.com', companyId: 'company-1' });
      findUserById.mockResolvedValue({ user_id: 'user-1', company_id: 'company-1', roles: ['role-analyst'] });
      getRolesByIds.mockResolvedValue([{ role_id: 'role-analyst', role_name: 'Analyst', permissions: '["read","write"]' }]);
      const req = mockReq({ headers: { authorization: 'Bearer good-token' } });
      const next = jest.fn();

      await requireAdminKeyOrPermission('write')(req, mockRes(), next);

      expect(next).toHaveBeenCalledWith();
      expect(req.user.permissions).toEqual(['read', 'write']);
    });
  });

  describe('requireUser', () => {
    test('attaches identity from a valid Bearer token without permission checks', async () => {
      verifyIdToken.mockResolvedValue({ uid: 'user-1', email: 'a@b.com', companyId: 'company-1' });
      const req = mockReq({ headers: { authorization: 'Bearer good-token' } });
      const next = jest.fn();

      await requireUser(req, mockRes(), next);

      expect(next).toHaveBeenCalledWith();
      expect(req.user).toMatchObject({ uid: 'user-1', companyId: 'company-1' });
      expect(findUserById).not.toHaveBeenCalled();
    });

    test('401 when no token is provided', async () => {
      const next = jest.fn();

      await requireUser(mockReq(), mockRes(), next);

      expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 401, code: 'MISSING_ID_TOKEN' }));
    });
  });
});
