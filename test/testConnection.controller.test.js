jest.mock('../src/services/SSO/testConnection.service', () => ({
  testConnection: jest.fn(),
}));

jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/services/audit/audit.service', () => ({
  auditTestConnection: jest.fn(),
}));

jest.mock('../src/utils/shared/testConnectionStore', () => ({
  set: jest.fn(),
}));

const { handleTestConnection } = require('../src/controllers/testConnection.controller');
const { testConnection } = require('../src/services/SSO/testConnection.service');
const { auditTestConnection } = require('../src/services/audit/audit.service');
const tcStore = require('../src/utils/shared/testConnectionStore');

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

describe('testConnection.controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('returns 400 when protocol is missing', async () => {
    const res = mockRes();

    await handleTestConnection(mockReq({}), res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ success: false, message: 'protocol is required' });
  });

  test('returns 400 for missing required tenant or SAML location fields', async () => {
    const res1 = mockRes();
    await handleTestConnection(mockReq({ protocol: 'oidc' }), res1, jest.fn());
    expect(res1.status).toHaveBeenCalledWith(400);

    const res2 = mockRes();
    await handleTestConnection(mockReq({ protocol: 'saml' }), res2, jest.fn());
    expect(res2.status).toHaveBeenCalledWith(400);
  });

  test('stores internal OIDC test state, strips it from the response, audits, and returns 200', async () => {
    const req = mockReq({
      protocol: 'oidc',
      auth_method: 'client_secret_post',
      tenant_id: ' tenant-1 ',
      client_id: ' client-1 ',
      domains: [' Example.COM '],
    });
    const res = mockRes();
    const next = jest.fn();
    testConnection.mockResolvedValue({
      success: true,
      data: {
        sessionRef: 'session-ref-1',
        config: { client_id: 'client-1' },
        _internal: { secret: 'keep-server-side' },
      },
    });

    await handleTestConnection(req, res, next);

    expect(testConnection).toHaveBeenCalledWith(expect.objectContaining({
      protocol: 'oidc',
      tenant_id: 'tenant-1',
      client_id: 'client-1',
      domains: 'example.com',
    }));
    expect(tcStore.set).toHaveBeenCalledWith('session-ref-1', { secret: 'keep-server-side' });
    expect(auditTestConnection).toHaveBeenCalledWith('1.2.3.4', 'oidc', true);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json.mock.calls[0][0].data._internal).toBeUndefined();
    expect(next).not.toHaveBeenCalled();
  });

  test('passes service errors to next', async () => {
    const req = mockReq({ protocol: 'oidc', tenant_id: 'tenant-1' });
    const res = mockRes();
    const next = jest.fn();
    const err = new Error('connection failed');
    testConnection.mockRejectedValue(err);

    await handleTestConnection(req, res, next);

    expect(next).toHaveBeenCalledWith(err);
  });
});
