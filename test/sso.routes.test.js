describe('sso.routes', () => {
  afterEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
  });

  test('registers the expected controller and middleware wiring', () => {
    const routerMock = {
      get: jest.fn(),
      post: jest.fn(),
      patch: jest.fn(),
      delete: jest.fn(),
    };

    const expressMock = { Router: jest.fn(() => routerMock) };
    const requireAdminKey = jest.fn();
    const requireUser = jest.fn();
    // requireAdminKeyOrPermission is a factory — return a distinct sentinel per
    // permission so the assertions verify BOTH the wiring and the permission.
    const permissionSentinels = {};
    const requireAdminKeyOrPermission = jest.fn((permission) => {
      permissionSentinels[permission] = permissionSentinels[permission] || jest.fn();
      return permissionSentinels[permission];
    });
    const domainCheckLimiter = jest.fn();
    const samlCallbackLimiter = jest.fn();

    const domainCheck = jest.fn();
    const samlCallbackController = jest.fn();
    const handleOidcCallback = jest.fn();
    const handleOidcRedirect = jest.fn();
    const handleTestConnection = jest.fn();
    const oidcTestCallbackController = jest.fn();
    const handleSaveSsoConfig = jest.fn();
    const handleGetSsoConfig = jest.fn();
    const handleSetSsoStatus = jest.fn();
    const handleDeleteSsoConfig = jest.fn();
    const handleListRoles = jest.fn();
    const handleGetMe = jest.fn();
    const handleListUsers = jest.fn();
    const handleCreateUser = jest.fn();
    const handleUpdateUser = jest.fn();
    const handleDeleteUser = jest.fn();
    const getFlags = jest.fn();
    const updateFlag = jest.fn();

    jest.doMock('express', () => expressMock);
    jest.doMock('../src/controllers/domianCheck.Controller', () => ({ domainCheck }));
    jest.doMock('../src/controllers/samlCallback.Controller', () => ({ samlCallbackController }));
    jest.doMock('../src/controllers/oidcTokenExchange.controller', () => ({ handleOidcCallback }));
    jest.doMock('../src/controllers/oidcRedirect.controller', () => ({ handleOidcRedirect }));
    jest.doMock('../src/controllers/testConnection.controller', () => ({ handleTestConnection }));
    jest.doMock('../src/controllers/oidcTestCallback.controller', () => ({ oidcTestCallbackController }));
    jest.doMock('../src/controllers/saveSsoConfig.controller', () => ({ handleSaveSsoConfig }));
    jest.doMock('../src/controllers/ssoAdmin.controller', () => ({
      handleGetSsoConfig,
      handleSetSsoStatus,
      handleDeleteSsoConfig,
    }));
    jest.doMock('../src/controllers/ssoUsers.controller', () => ({
      handleListRoles,
      handleGetMe,
      handleListUsers,
      handleCreateUser,
      handleUpdateUser,
      handleDeleteUser,
    }));
    jest.doMock('../src/controllers/featureFlag.controller', () => ({ getFlags, updateFlag }));
    jest.doMock('../src/middlewares/rateLimiter', () => ({ domainCheckLimiter, samlCallbackLimiter }));
    jest.doMock('../src/middlewares/adminAuth.middleware', () => ({ requireAdminKey }));
    jest.doMock('../src/middlewares/userAuth.middleware', () => ({ requireAdminKeyOrPermission, requireUser }));

    require('../src/routers/sso.routes');

    expect(expressMock.Router).toHaveBeenCalled();

    // Feature flags stay platform-admin-key only
    expect(routerMock.get).toHaveBeenCalledWith('/admin/flags/:company_id', requireAdminKey, getFlags);
    expect(routerMock.post).toHaveBeenCalledWith('/admin/flags', requireAdminKey, updateFlag);

    // RBAC endpoints
    expect(routerMock.get).toHaveBeenCalledWith('/sso/roles', permissionSentinels['my_services:view'], handleListRoles);
    expect(routerMock.get).toHaveBeenCalledWith('/sso/me', requireUser, handleGetMe);
    expect(routerMock.get).toHaveBeenCalledWith('/sso/users', permissionSentinels['users:editable'], handleListUsers);
    expect(routerMock.post).toHaveBeenCalledWith('/sso/users', permissionSentinels['users:editable'], handleCreateUser);
    expect(routerMock.patch).toHaveBeenCalledWith('/sso/users/:user_id', permissionSentinels['users:editable'], handleUpdateUser);
    expect(routerMock.delete).toHaveBeenCalledWith('/sso/users/:user_id', permissionSentinels['users:editable'], handleDeleteUser);

    // Config endpoints: admin key OR the named zdna_roles permission
    expect(routerMock.post).toHaveBeenCalledWith('/test-connection', permissionSentinels['my_services:editable'], handleTestConnection);
    expect(routerMock.post).toHaveBeenCalledWith('/test-connection/oidc/callback', oidcTestCallbackController);
    expect(routerMock.post).toHaveBeenCalledWith('/sso/save', permissionSentinels['my_services:editable'], handleSaveSsoConfig);
    expect(routerMock.get).toHaveBeenCalledWith('/sso/config', permissionSentinels['my_services:view'], handleGetSsoConfig);
    expect(routerMock.patch).toHaveBeenCalledWith('/sso/config/:company_id/status', permissionSentinels['my_services:editable'], handleSetSsoStatus);
    expect(routerMock.delete).toHaveBeenCalledWith('/sso/config/:company_id', permissionSentinels['my_services:editable'], handleDeleteSsoConfig);

    // Login-flow endpoints unchanged
    expect(routerMock.post).toHaveBeenCalledWith('/domain-check', domainCheckLimiter, domainCheck);
    expect(routerMock.post).toHaveBeenCalledWith('/callback', samlCallbackLimiter, samlCallbackController);
    expect(routerMock.get).toHaveBeenCalledWith('/oidc/callback', handleOidcRedirect);
    expect(routerMock.post).toHaveBeenCalledWith('/oidc/token-exchange', handleOidcCallback);
  });
});
