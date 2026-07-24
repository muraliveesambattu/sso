jest.mock('../src/services/oidc/oidcTokenExchange.service', () => ({
  oidcTokenExchangeService: jest.fn(),
}));

jest.mock('../src/config/stateStore', () => ({
  stateStore: {
    get: jest.fn(),
    del: jest.fn(),
  },
}));

jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/services/audit/audit.service', () => ({
  auditUserLogin: jest.fn(),
}));

const { handleOidcCallback } = require('../src/controllers/oidcTokenExchange.controller');
const { oidcTokenExchangeService } = require('../src/services/oidc/oidcTokenExchange.service');
const { stateStore } = require('../src/config/stateStore');
const { auditUserLogin } = require('../src/services/audit/audit.service');

const mockReq = (body = {}) => ({
  body,
  ip: '1.2.3.4',
});

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('oidcTokenExchange.controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('returns 400 when required fields are missing', async () => {
    const res = mockRes();

    await handleOidcCallback(mockReq({ code: 'code-only' }), res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Missing required fields: code, company_id, state',
      code: 'MISSING_REQUIRED_FIELDS',
    });
  });

  test('returns 401 when state is not found', async () => {
    const req = mockReq({ code: 'code-1', company_id: 'company-1', state: 'state-1' });
    const res = mockRes();
    stateStore.get.mockResolvedValue(null);

    await handleOidcCallback(req, res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Session expired or not found. Please sign in again.',
      code: 'SESSION_EXPIRED',
    });
  });

  test('clears state, exchanges token, audits login, and returns 200 on success', async () => {
    const req = mockReq({ code: 'code-2', company_id: 'company-2', state: 'state-2' });
    const res = mockRes();
    const next = jest.fn();
    stateStore.get.mockResolvedValue({ code_verifier: 'verifier-1', nonce: 'nonce-1' });
    oidcTokenExchangeService.mockResolvedValue({
      customToken: 'firebase-token',
      user: { email: 'user@example.com' },
      roles: [{ role_name: 'Admin' }],
      userAction: 'created',
      session: { protocol: 'oidc' },
    });

    await handleOidcCallback(req, res, next);

    expect(stateStore.del).toHaveBeenCalledWith('state-2');
    expect(oidcTokenExchangeService).toHaveBeenCalledWith('code-2', 'company-2', 'verifier-1', 'nonce-1', '1.2.3.4');
    expect(auditUserLogin).toHaveBeenCalledWith('user@example.com', 'company-2', '1.2.3.4', 'created');
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      customToken: 'firebase-token',
      user: { email: 'user@example.com' },
      roles: [{ role_name: 'Admin' }],
      userAction: 'created',
      session: { protocol: 'oidc' },
    });
    expect(next).not.toHaveBeenCalled();
  });

  test('passes service errors to next', async () => {
    const req = mockReq({ code: 'code-3', company_id: 'company-3', state: 'state-3' });
    const res = mockRes();
    const next = jest.fn();
    const err = Object.assign(new Error('exchange failed'), { code: 'FAIL' });
    stateStore.get.mockResolvedValue({ code_verifier: 'verifier-2', nonce: 'nonce-2' });
    oidcTokenExchangeService.mockRejectedValue(err);

    await handleOidcCallback(req, res, next);

    expect(next).toHaveBeenCalledWith(err);
  });
});
