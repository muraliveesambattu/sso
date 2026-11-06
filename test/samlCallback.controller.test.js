jest.mock('../src/services/Saml/samlCallback.service', () => ({
  processSamlCallback: jest.fn(),
}));

jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/config/constants', () => ({
  defaults: { FRONTEND_URL: 'http://localhost:3000' },
}));

const { samlCallbackController } = require('../src/controllers/samlCallback.Controller');
const { processSamlCallback } = require('../src/services/Saml/samlCallback.service');

const mockReq = (body = {}, headers = {}) => ({
  body,
  headers,
  ip: '1.2.3.4',
  connection: { remoteAddress: '5.6.7.8' },
  socket: { remoteAddress: '9.9.9.9' },
  session: { sid: 'session' },
});

const mockRes = () => {
  const res = {};
  res.redirect = jest.fn().mockReturnValue(res);
  return res;
};

describe('samlCallback.Controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('redirects with an error when SAMLResponse is missing', async () => {
    const res = mockRes();

    await samlCallbackController(mockReq({ RelayState: 'relay-1' }), res, jest.fn());

    expect(res.redirect).toHaveBeenCalledWith('http://localhost:3000/auth/oidc/callback?error=MISSING_SAML_RESPONSE');
  });

  test('redirects with an error when RelayState is missing', async () => {
    const res = mockRes();

    await samlCallbackController(mockReq({ SAMLResponse: 'response-1' }), res, jest.fn());

    expect(res.redirect).toHaveBeenCalledWith('http://localhost:3000/auth/oidc/callback?error=MISSING_RELAY_STATE');
  });

  test('redirects to the frontend with the encoded token on success', async () => {
    const req = mockReq(
      { SAMLResponse: 'response-2', RelayState: 'relay-2' },
      { 'x-forwarded-for': '10.0.0.1, 10.0.0.2' }
    );
    const res = mockRes();
    processSamlCallback.mockResolvedValue({
      customToken: 'token+/=',
      user: { user_id: 'user-1' },
    });

    await samlCallbackController(req, res, jest.fn());

    expect(processSamlCallback).toHaveBeenCalledWith('response-2', 'relay-2', req.session, '10.0.0.1');
    expect(res.redirect).toHaveBeenCalledWith('http://localhost:3000/auth/oidc/callback?token=token%2B%2F%3D');
  });

  test('redirects with the service error code on failure', async () => {
    const req = mockReq({ SAMLResponse: 'response-3', RelayState: 'relay-3' });
    const res = mockRes();
    processSamlCallback.mockRejectedValue(Object.assign(new Error('bad saml'), { code: 'SAML_BAD' }));

    await samlCallbackController(req, res, jest.fn());

    expect(res.redirect).toHaveBeenCalledWith('http://localhost:3000/auth/oidc/callback?error=SAML_BAD');
  });

  // ==========================================
  // NEW ADDITIONS FOR >90% CODE COVERAGE
  // ==========================================

  test('resolves client IP when x-forwarded-for is missing but req.ip is present', async () => {
    const req = mockReq({ SAMLResponse: 'response-4', RelayState: 'relay-4' });
    delete req.headers['x-forwarded-for']; // Remove header
    req.ip = '192.168.1.1';
    
    const res = mockRes();
    processSamlCallback.mockResolvedValue({ customToken: 'token4', user: { user_id: 'user-4' } });

    await samlCallbackController(req, res, jest.fn());

    expect(processSamlCallback).toHaveBeenCalledWith('response-4', 'relay-4', req.session, '192.168.1.1');
    expect(res.redirect).toHaveBeenCalledWith('http://localhost:3000/auth/oidc/callback?token=token4');
  });

  test('resolves client IP when x-forwarded-for and req.ip are missing but req.connection is present', async () => {
    const req = mockReq({ SAMLResponse: 'response-5', RelayState: 'relay-5' });
    delete req.headers['x-forwarded-for'];
    delete req.ip;
    req.connection = { remoteAddress: '172.16.0.1' };

    const res = mockRes();
    processSamlCallback.mockResolvedValue({ customToken: 'token5', user: { user_id: 'user-5' } });

    await samlCallbackController(req, res, jest.fn());

    expect(processSamlCallback).toHaveBeenCalledWith('response-5', 'relay-5', req.session, '172.16.0.1');
  });

  test('resolves client IP when all other IP properties are missing except req.socket', async () => {
    const req = mockReq({ SAMLResponse: 'response-6', RelayState: 'relay-6' });
    delete req.headers['x-forwarded-for'];
    delete req.ip;
    req.connection = {}; // Keep connection object empty to prevent crash in catch block
    req.socket = { remoteAddress: '10.0.0.5' };

    const res = mockRes();
    processSamlCallback.mockResolvedValue({ customToken: 'token6', user: { user_id: 'user-6' } });

    await samlCallbackController(req, res, jest.fn());

    expect(processSamlCallback).toHaveBeenCalledWith('response-6', 'relay-6', req.session, '10.0.0.5');
  });

  test('redirects with default error string when error does not have a code or custom statusCode in catch block', async () => {
    const req = mockReq({ SAMLResponse: 'response-7', RelayState: 'relay-7' });
    delete req.headers['x-forwarded-for'];
    const res = mockRes();
    const err = new Error('Generic failure'); // Error without code, statusCode
    processSamlCallback.mockRejectedValue(err);

    await samlCallbackController(req, res, jest.fn());

    expect(res.redirect).toHaveBeenCalledWith('http://localhost:3000/auth/oidc/callback?error=SAML_LOGIN_FAILED');
  });
});