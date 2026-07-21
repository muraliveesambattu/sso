const loadOidcRedirectController = ({ nodeEnv = 'test', frontendUrl = 'http://localhost:3000' } = {}) => {
  jest.resetModules();
  const originalNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = nodeEnv;
  const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };

  jest.doMock('../src/config/logger', () => ({ logger }));
  jest.doMock('../src/config/constants', () => ({
    defaults: { FRONTEND_URL: frontendUrl },
  }));

  const { handleOidcRedirect } = require('../src/controllers/oidcRedirect.controller');
  return {
    handleOidcRedirect,
    logger,
    restore: () => { process.env.NODE_ENV = originalNodeEnv; },
  };
};

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.redirect = jest.fn().mockReturnValue(res);
  res.sendFile = jest.fn().mockReturnValue(res);
  return res;
};

describe('oidcRedirect.controller', () => {
  afterEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
  });

  test('redirects frontend errors when Entra returns an error', () => {
    const loader = loadOidcRedirectController({ frontendUrl: 'http://localhost:5173' });
    const res = mockRes();

    loader.handleOidcRedirect({
      query: { error: 'access_denied', error_description: 'user cancelled' },
    }, res);

    expect(res.redirect).toHaveBeenCalledWith(
      'http://localhost:5173/auth/oidc/error?error=access_denied&description=user%20cancelled'
    );
    loader.restore();
  });

  test('returns 400 when code or state are missing', () => {
    const loader = loadOidcRedirectController();
    const res = mockRes();

    loader.handleOidcRedirect({ query: { code: 'code-only' } }, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Missing code or state in OIDC redirect',
      code: 'MISSING_OIDC_PARAMS',
    });
    loader.restore();
  });

  test('redirects to the frontend callback in development', () => {
    const loader = loadOidcRedirectController({ nodeEnv: 'development', frontendUrl: 'http://localhost:3000' });
    const res = mockRes();

    loader.handleOidcRedirect({ query: { code: 'code-1', state: 'state-1' } }, res);

    expect(res.redirect).toHaveBeenCalledWith(
      'http://localhost:3000/auth/oidc/callback?code=code-1&state=state-1'
    );
    loader.restore();
  });

  test('relays to the separately-hosted frontend callback in production (no bundled client)', () => {
    const loader = loadOidcRedirectController({ nodeEnv: 'production', frontendUrl: 'https://app.example.com' });
    const res = mockRes();

    loader.handleOidcRedirect({ query: { code: 'code-2', state: 'state-2' } }, res);

    expect(res.redirect).toHaveBeenCalledWith(
      'https://app.example.com/auth/oidc/callback?code=code-2&state=state-2'
    );
    expect(res.sendFile).not.toHaveBeenCalled();
    loader.restore();
  });
});
