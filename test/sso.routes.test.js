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
    jest.doMock('../src/controllers/featureFlag.controller', () => ({ getFlags, updateFlag }));
    jest.doMock('../src/middlewares/rateLimiter', () => ({ domainCheckLimiter, samlCallbackLimiter }));
    jest.doMock('../src/middlewares/adminAuth.middleware', () => ({ requireAdminKey }));

    require('../src/routers/sso.routes');

    expect(expressMock.Router).toHaveBeenCalled();
    expect(routerMock.get).toHaveBeenCalledWith('/admin/flags/:company_id', requireAdminKey, getFlags);
    expect(routerMock.post).toHaveBeenCalledWith('/admin/flags', requireAdminKey, updateFlag);
    expect(routerMock.post).toHaveBeenCalledWith('/test-connection', requireAdminKey, handleTestConnection);
    expect(routerMock.post).toHaveBeenCalledWith('/test-connection/oidc/callback', oidcTestCallbackController);
    expect(routerMock.post).toHaveBeenCalledWith('/sso/save', requireAdminKey, handleSaveSsoConfig);
    expect(routerMock.get).toHaveBeenCalledWith('/sso/config', requireAdminKey, handleGetSsoConfig);
    expect(routerMock.patch).toHaveBeenCalledWith('/sso/config/:company_id/status', requireAdminKey, handleSetSsoStatus);
    expect(routerMock.delete).toHaveBeenCalledWith('/sso/config/:company_id', requireAdminKey, handleDeleteSsoConfig);
    expect(routerMock.post).toHaveBeenCalledWith('/domain-check', domainCheckLimiter, domainCheck);
    expect(routerMock.post).toHaveBeenCalledWith('/callback', samlCallbackLimiter, samlCallbackController);
    expect(routerMock.get).toHaveBeenCalledWith('/oidc/callback', handleOidcRedirect);
    expect(routerMock.post).toHaveBeenCalledWith('/oidc/token-exchange', handleOidcCallback);
  });
});
