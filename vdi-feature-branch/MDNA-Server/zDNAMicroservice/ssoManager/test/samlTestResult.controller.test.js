jest.mock('../src/services/Saml/samlAuthRequest.service', () => ({
  takeSamlTestResult: jest.fn(),
}));

const { handleSamlTestResult } = require('../src/controllers/samlTestResult.controller');
const { takeSamlTestResult } = require('../src/services/Saml/samlAuthRequest.service');

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('samlTestResult.controller', () => {
  beforeEach(() => jest.clearAllMocks());

  test('returns 400 when sessionRef is missing or not a string', () => {
    const res = mockRes();
    handleSamlTestResult({ body: {} }, res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json.mock.calls[0][0].error.code).toBe('MISSING_SESSION_REF');

    const res2 = mockRes();
    handleSamlTestResult({ body: { sessionRef: { $ne: null } } }, res2);
    expect(res2.status).toHaveBeenCalledWith(400);
    expect(takeSamlTestResult).not.toHaveBeenCalled();
  });

  test('returns 401 when the session is unknown or expired', () => {
    takeSamlTestResult.mockReturnValue(null);
    const res = mockRes();
    handleSamlTestResult({ body: { sessionRef: 'ref-1' } }, res);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json.mock.calls[0][0].error.code).toBe('TC_STORE_EXPIRED');
  });

  test('returns 202 while the ACS callback has not run yet', () => {
    takeSamlTestResult.mockReturnValue({ pending: true });
    const res = mockRes();
    handleSamlTestResult({ body: { sessionRef: 'ref-1' } }, res);
    expect(res.status).toHaveBeenCalledWith(202);
    expect(res.json).toHaveBeenCalledWith({ success: true, pending: true });
  });

  test('returns 400 with the failure code when the test login failed', () => {
    takeSamlTestResult.mockReturnValue({ success: false, code: 'INVALID_AUDIENCE', message: 'wrong audience' });
    const res = mockRes();
    handleSamlTestResult({ body: { sessionRef: 'ref-1' } }, res);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: { message: 'wrong audience', code: 'INVALID_AUDIENCE' },
    });
  });

  test('returns 200 with the claims when the test login passed, without the email', () => {
    const claims = { roles: ['Zebra.Admin'], groups: [], groupsOverage: false };
    takeSamlTestResult.mockReturnValue({ success: true, email: 'user@example.com', claims });
    const res = mockRes();
    handleSamlTestResult({ body: { sessionRef: 'ref-1' } }, res);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      data: { protocol: 'saml', sso_status: 'active', claims },
    });
  });
});
