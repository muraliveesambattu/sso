jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/services/db/ssoDataService', () => ({
  getSsoIntegrationByCompanyId: jest.fn(),
  findUserById: jest.fn(),
  findUserByEmail: jest.fn(),
  listUsersByCompany: jest.fn(),
  createUser: jest.fn(),
  updateUser: jest.fn(),
  deleteUser: jest.fn(),
}));

jest.mock('../src/services/SSO/permissionResolver.service', () => ({
  resolvePermissions: jest.fn(async () => ({ permissions: [], source: 'none' })),
}));

const crypto = require('crypto');
const {
  handleGetMe, handleListUsers,
  handleCreateUser, handleUpdateUser, handleDeleteUser,
} = require('../src/controllers/ssoUsers.controller');
const {
  getSsoIntegrationByCompanyId,
  findUserById, findUserByEmail, createUser, updateUser, deleteUser, listUsersByCompany,
} = require('../src/services/db/ssoDataService');
const { resolvePermissions } = require('../src/services/SSO/permissionResolver.service');

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

const mockReq = (overrides = {}) => ({
  headers: {}, params: {}, query: {}, body: {}, path: '/v1/auth/sso/users', ip: '127.0.0.1',
  ...overrides,
});

const ROLE_ROWS = [
  { role_id: 'role-admin',   role_name: 'Admin',   permissions: ['my_services:editable', 'users:editable'] },
  { role_id: 'role-manager', role_name: 'Manager', permissions: ['my_devices:editable', 'licensing:editable'] },
];

describe('ssoUsers.controller', () => {
  let randomUuidSpy;

  beforeEach(() => {
    jest.clearAllMocks();
    randomUuidSpy = jest.spyOn(crypto, 'randomUUID').mockReturnValue('uuid-123');
  });

  afterEach(() => {
    randomUuidSpy.mockRestore();
  });

  test('handleGetMe returns roles (built from stored values) + resolver permissions', async () => {
    findUserById.mockResolvedValue({
      user_id: 'user-1', company_id: 'company-1', email: 'a@b.com',
      display_name: 'A', roles: ['role-admin', 'role-manager'], last_login: null,
    });
    resolvePermissions.mockResolvedValue({
      permissions: ['my_services:editable', 'users:editable'], source: 'role_config',
    });
    const req = mockReq({ user: { uid: 'user-1' } });
    const res = mockRes();

    await handleGetMe(req, res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(200);
    const payload = res.json.mock.calls[0][0];
    // roles built from stored values (role_name = the stored value; permissions
    // resolved separately from RMS/Firestore).
    expect(payload.data.roles).toEqual([
      { role_id: 'role-admin',   role_name: 'role-admin',   permissions: [] },
      { role_id: 'role-manager', role_name: 'role-manager', permissions: [] },
    ]);
    expect(payload.data.permissions).toEqual(['my_services:editable', 'users:editable']);
    expect(payload.data.permissions_source).toBe('role_config');
  });

  test('handleGetMe 404s when the caller has no sso_users record', async () => {
    findUserById.mockResolvedValue(null);
    const res = mockRes();

    await handleGetMe(mockReq({ user: { uid: 'ghost' } }), res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(404);
  });

  test('handleListUsers falls back to the caller company and 400s without one', async () => {
    listUsersByCompany.mockResolvedValue([{ user_id: 'u1' }]);
    const res = mockRes();
    await handleListUsers(mockReq({ user: { uid: 'user-1', companyId: 'company-1' } }), res, jest.fn());
    expect(listUsersByCompany).toHaveBeenCalledWith('company-1');
    expect(res.status).toHaveBeenCalledWith(200);

    const res2 = mockRes();
    await handleListUsers(mockReq(), res2, jest.fn()); // admin-key caller, no query
    expect(res2.status).toHaveBeenCalledWith(400);
  });

  describe('handleCreateUser', () => {
    const validBody = {
      company_id: 'company-1', email: 'new@b.com',
      roles: ['role-manager'], display_name: 'New User',
    };

    test('creates a pre-provisioned user with a pending oid placeholder', async () => {
      getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1' });
      findUserByEmail.mockResolvedValue(null);
      createUser.mockImplementation(async (u) => u);
      const res = mockRes();

      await handleCreateUser(mockReq({ body: validBody }), res, jest.fn());

      expect(res.status).toHaveBeenCalledWith(201);
      expect(createUser).toHaveBeenCalledWith(expect.objectContaining({
        company_id: 'company-1',
        email: 'new@b.com',
        roles: ['role-manager'],
        oid: 'pending:uuid-123',
        login_method: 'sso',
        jit_provisioned: false,
      }));
    });

    test('404 INTEGRATION_NOT_FOUND when the company has no SSO integration', async () => {
      getSsoIntegrationByCompanyId.mockResolvedValue(null);
      const next = jest.fn();

      await handleCreateUser(mockReq({ body: validBody }), mockRes(), next);

      expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 404, code: 'INTEGRATION_NOT_FOUND' }));
    });

    test('400 MISSING_ROLES when no roles are assigned', async () => {
      getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1' });
      const next = jest.fn();

      await handleCreateUser(mockReq({ body: { ...validBody, roles: [] } }), mockRes(), next);

      expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 400, code: 'MISSING_ROLES' }));
    });

    test('409 USER_ALREADY_EXISTS for a duplicate email in the same company', async () => {
      getSsoIntegrationByCompanyId.mockResolvedValue({ company_id: 'company-1' });
      findUserByEmail.mockResolvedValue({ user_id: 'existing' });
      const next = jest.fn();

      await handleCreateUser(mockReq({ body: validBody }), mockRes(), next);

      expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 409, code: 'USER_ALREADY_EXISTS' }));
    });

    test('400 INVALID_EMAIL for a malformed email', async () => {
      const next = jest.fn();

      await handleCreateUser(mockReq({ body: { ...validBody, email: 'not-an-email' } }), mockRes(), next);

      expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 400, code: 'INVALID_EMAIL' }));
    });
  });

  describe('handleUpdateUser / handleDeleteUser', () => {
    test('update validates roles and persists them', async () => {
      findUserById.mockResolvedValue({ user_id: 'user-1', company_id: 'company-1', roles: ['role-manager'] });
      const res = mockRes();

      await handleUpdateUser(mockReq({ params: { user_id: 'user-1' }, body: { roles: ['role-admin'] } }), res, jest.fn());

      expect(updateUser).toHaveBeenCalledWith('user-1', { roles: ['role-admin'] });
      expect(res.status).toHaveBeenCalledWith(200);
    });

    test('Bearer callers cannot update users of another company', async () => {
      findUserById.mockResolvedValue({ user_id: 'user-1', company_id: 'company-OTHER', roles: [] });
      const next = jest.fn();

      await handleUpdateUser(mockReq({
        params: { user_id: 'user-1' },
        body: { display_name: 'X' },
        user: { uid: 'caller', companyId: 'company-1' },
      }), mockRes(), next);

      expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 403, code: 'COMPANY_SCOPE_VIOLATION' }));
      expect(updateUser).not.toHaveBeenCalled();
    });

    test('delete removes the user and 404s when missing', async () => {
      findUserById.mockResolvedValue({ user_id: 'user-1', company_id: 'company-1' });
      deleteUser.mockResolvedValue(true);
      const res = mockRes();
      await handleDeleteUser(mockReq({ params: { user_id: 'user-1' } }), res, jest.fn());
      expect(deleteUser).toHaveBeenCalledWith('user-1');
      expect(res.status).toHaveBeenCalledWith(200);

      findUserById.mockResolvedValue(null);
      const res2 = mockRes();
      await handleDeleteUser(mockReq({ params: { user_id: 'ghost' } }), res2, jest.fn());
      expect(res2.status).toHaveBeenCalledWith(404);
    });
  });
});
