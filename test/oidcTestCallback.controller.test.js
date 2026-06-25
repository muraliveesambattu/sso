jest.mock('../src/utils/oidc/tokenExchange.util', () => ({
  decodeJwt: jest.fn(),
  generateJwtAssertion: jest.fn(),
}));

jest.mock('../src/utils/oidc/jwkValidation.util', () => ({
  verifyJwtSignature: jest.fn(),
}));

jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/utils/shared/testConnectionStore', () => ({
  consume: jest.fn(),
}));

jest.mock('../src/config/constants', () => ({
  microsoft: {
    tokenUrl: jest.fn((tenantId) => `https://token.example.test/${tenantId}`),
  },
}));

const { EventEmitter } = require('events');
const https = require('https');
const { oidcTestCallbackController } = require('../src/controllers/oidcTestCallback.controller');
const { decodeJwt, generateJwtAssertion } = require('../src/utils/oidc/tokenExchange.util');
const { verifyJwtSignature } = require('../src/utils/oidc/jwkValidation.util');
const tcStore = require('../src/utils/shared/testConnectionStore');

const mockReq = (body = {}) => ({ body });
const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

const mockHttpsResponse = (responseFactory) => jest.spyOn(https, 'request').mockImplementation((url, options, callback) => {
  const req = new EventEmitter();
  let body = '';
  req.write = jest.fn((chunk) => { body += chunk; });
  req.end = jest.fn(() => {
    const response = responseFactory({ url, options, body, req });
    if (response.error) {
      process.nextTick(() => req.emit('error', response.error));
      return;
    }
    const res = new EventEmitter();
    res.statusCode = response.statusCode;
    callback(res);
    process.nextTick(() => {
      if (response.body !== undefined) res.emit('data', response.body);
      res.emit('end');
    });
  });
  return req;
});

describe('oidcTestCallback.controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('returns 400 when required params are missing', async () => {
    const res1 = mockRes();
    await oidcTestCallbackController(mockReq({}), res1, jest.fn());
    expect(res1.status).toHaveBeenCalledWith(400);

    const res2 = mockRes();
    await oidcTestCallbackController(mockReq({ code: 'code-1', state: 'state-1' }), res2, jest.fn());
    expect(res2.status).toHaveBeenCalledWith(400);
  });

  test('returns 401 when the stored test session is missing or state mismatches', async () => {
    const res1 = mockRes();
    tcStore.consume.mockReturnValueOnce(null);
    await oidcTestCallbackController(mockReq({ code: 'code-1', state: 'state-1', sessionRef: 'session-1' }), res1, jest.fn());
    expect(res1.status).toHaveBeenCalledWith(401);

    const res2 = mockRes();
    tcStore.consume.mockReturnValueOnce({ state: 'different-state' });
    await oidcTestCallbackController(mockReq({ code: 'code-2', state: 'state-2', sessionRef: 'session-2' }), res2, jest.fn());
    expect(res2.status).toHaveBeenCalledWith(401);
    expect(res2.json.mock.calls[0][0].error.code).toBe('STATE_MISMATCH');
  });

  test('returns 400 when token exchange fails', async () => {
    const res = mockRes();
    tcStore.consume.mockReturnValue({
      tenant_id: 'tenant-1',
      client_id: 'client-1',
      client_auth_method: 'client_secret_post',
      client_secret: 'secret-1',
      redirect_uri: 'http://localhost/callback',
      state: 'state-1',
      nonce: 'nonce-1',
    });
    mockHttpsResponse(() => ({
      statusCode: 400,
      body: JSON.stringify({
        error: 'invalid_grant',
        error_description: 'Grant invalid\r\ntrace-id',
      }),
    }));

    await oidcTestCallbackController(
      mockReq({ code: 'code-3', state: 'state-1', sessionRef: 'session-3' }),
      res,
      jest.fn()
    );

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: { message: 'Grant invalid', code: 'invalid_grant' },
    });
  });

  test('returns 401 when nonce mismatches', async () => {
    const res = mockRes();
    tcStore.consume.mockReturnValue({
      tenant_id: 'tenant-2',
      client_id: 'client-2',
      client_auth_method: 'none',
      code_verifier: 'verifier-1',
      redirect_uri: 'http://localhost/callback',
      state: 'state-2',
      nonce: 'nonce-expected',
    });
    mockHttpsResponse(() => ({
      statusCode: 200,
      body: JSON.stringify({ id_token: 'id-token' }),
    }));
    decodeJwt.mockReturnValue({ nonce: 'nonce-actual', email: 'user@example.com' });
    verifyJwtSignature.mockResolvedValue(undefined);

    await oidcTestCallbackController(
      mockReq({ code: 'code-4', state: 'state-2', sessionRef: 'session-4' }),
      res,
      jest.fn()
    );

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json.mock.calls[0][0].error.code).toBe('NONCE_MISMATCH');
  });

  test('supports private_key_jwt and returns active status on success', async () => {
    const res = mockRes();
    const next = jest.fn();
    tcStore.consume.mockReturnValue({
      tenant_id: 'tenant-3',
      client_id: 'client-3',
      client_auth_method: 'private_key_jwt',
      private_key_b64: 'private-key',
      client_cert_thumbprint: 'thumb',
      redirect_uri: 'http://localhost/callback',
      state: 'state-3',
      nonce: 'nonce-3',
    });
    mockHttpsResponse(({ body }) => {
      expect(body).toContain('client_assertion=signed-assertion');
      return {
        statusCode: 200,
        body: JSON.stringify({ id_token: 'id-token' }),
      };
    });
    generateJwtAssertion.mockReturnValue('signed-assertion');
    decodeJwt.mockReturnValue({ nonce: 'nonce-3', email: 'user@example.com' });
    verifyJwtSignature.mockResolvedValue(undefined);

    await oidcTestCallbackController(
      mockReq({ code: 'code-5', state: 'state-3', sessionRef: 'session-5' }),
      res,
      next
    );

    expect(generateJwtAssertion).toHaveBeenCalledWith('client-3', 'tenant-3', 'private-key', 'thumb');
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      data: { protocol: 'oidc', sso_status: 'active' },
    });
    expect(next).not.toHaveBeenCalled();
  });

  test('passes unexpected errors to next', async () => {
    const res = mockRes();
    const next = jest.fn();
    tcStore.consume.mockReturnValue({
      tenant_id: 'tenant-4',
      client_id: 'client-4',
      client_auth_method: 'client_secret',
      client_secret: 'secret-4',
      redirect_uri: 'http://localhost/callback',
      state: 'state-4',
      nonce: 'nonce-4',
    });
    mockHttpsResponse(() => ({ error: new Error('network down') }));

    await oidcTestCallbackController(
      mockReq({ code: 'code-6', state: 'state-4', sessionRef: 'session-6' }),
      res,
      next
    );

    expect(next).toHaveBeenCalledWith(expect.any(Error));
  });
});
