jest.mock('../src/services/SSO/domainCheck.service', () => ({
  checkDomain: jest.fn(),
}));

jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

const { domainCheck } = require('../src/controllers/domianCheck.Controller');
const { checkDomain } = require('../src/services/SSO/domainCheck.service');

const mockReq = (body = {}) => ({
  body,
  ip: '1.2.3.4',
  session: { sid: 'session' },
  sessionID: 'session-1',
});

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('domainCheck.Controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('trims email and domain input and returns the service result', async () => {
    const req = mockReq({ email: ' user@example.com ', domain: ' ignored@example.org ' });
    const res = mockRes();
    const next = jest.fn();
    checkDomain.mockResolvedValue({ found: true, protocol: 'oidc' });

    await domainCheck(req, res, next);

    expect(checkDomain).toHaveBeenCalledWith(
      'user@example.com',
      'example.org',
      req.session,
      'session-1'
    );
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ found: true, protocol: 'oidc' });
    expect(next).not.toHaveBeenCalled();
  });

  test('passes errors to next', async () => {
    const req = mockReq({ domain: 'example.com' });
    const res = mockRes();
    const next = jest.fn();
    const err = Object.assign(new Error('boom'), { code: 'FAIL' });
    checkDomain.mockRejectedValue(err);

    await domainCheck(req, res, next);

    expect(next).toHaveBeenCalledWith(err);
  });

  // ==========================================
  // NEW ADDITIONS FOR >90% CODE COVERAGE
  // ==========================================

  test('handles missing or empty request body parameters (null cases)', async () => {
    const req = mockReq({}); // req.body.email is undefined, req.body.domain is undefined
    const res = mockRes();
    const next = jest.fn();
    checkDomain.mockResolvedValue({ found: false });

    await domainCheck(req, res, next);

    expect(checkDomain).toHaveBeenCalledWith(
      null,
      null,
      req.session,
      'session-1'
    );
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ found: false });
    expect(next).not.toHaveBeenCalled();
  });

  test('handles domain inputs that do not contain an "@" symbol', async () => {
    const req = mockReq({ domain: 'example.com' }); // domain string without @
    const res = mockRes();
    const next = jest.fn();
    checkDomain.mockResolvedValue({ found: true, protocol: 'saml', company_id: '12345' });

    await domainCheck(req, res, next);

    expect(checkDomain).toHaveBeenCalledWith(
      null,
      'example.com',
      req.session,
      'session-1'
    );
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ found: true, protocol: 'saml', company_id: '12345' });
    expect(next).not.toHaveBeenCalled();
  });

  test('handles domain check errors that lack a specific error code', async () => {
    const req = mockReq({ domain: 'error.com' });
    const res = mockRes();
    const next = jest.fn();
    const err = new Error('Generic internal error'); // Error without .code property
    checkDomain.mockRejectedValue(err);

    await domainCheck(req, res, next);

    expect(next).toHaveBeenCalledWith(err);
  });
});