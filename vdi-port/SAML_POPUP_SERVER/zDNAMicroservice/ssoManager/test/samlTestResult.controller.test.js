jest.mock('../src/services/Saml/samlAuthRequest.service', () => ({
  takeSamlTestResult: jest.fn(),
}));

const { handleSamlTestResult } = require('../src/controllers/samlTestResult.controller');
const { takeSamlTestResult } = require('../src/services/Saml/samlAuthRequest.service');

const SESSION_REF = '11111111-2222-3333-4444-555555555555';

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('samlTestResult.controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test.each([
    ['missing', {}],
    ['not a string', { sessionRef: 42 }],
    ['not a UUID', { sessionRef: 'not-a-uuid' }],
  ])('rejects a sessionRef that is %s', (_label, body) => {
    const res = mockRes();

    handleSamlTestResult({ body }, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: { message: 'sessionRef must be a valid UUID', code: 'MISSING_SESSION_REF' },
    });
    expect(takeSamlTestResult).not.toHaveBeenCalled();
  });

  test('rejects a request with no body', () => {
    const res = mockRes();

    handleSamlTestResult({}, res);

    expect(res.status).toHaveBeenCalledWith(400);
  });

  test('answers 401 when the session is unknown or expired', () => {
    takeSamlTestResult.mockReturnValue(null);
    const res = mockRes();

    handleSamlTestResult({ body: { sessionRef: SESSION_REF } }, res);

    expect(takeSamlTestResult).toHaveBeenCalledWith(SESSION_REF);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: { message: 'Session not found or expired. Please start a new test connection.', code: 'TC_STORE_EXPIRED' },
    });
  });

  test('answers 202 while the popup has not finished', () => {
    takeSamlTestResult.mockReturnValue({ pending: true });
    const res = mockRes();

    handleSamlTestResult({ body: { sessionRef: SESSION_REF } }, res);

    expect(res.status).toHaveBeenCalledWith(202);
    expect(res.json).toHaveBeenCalledWith({ success: true, pending: true });
  });

  test('answers 400 with the failure code when the test failed', () => {
    takeSamlTestResult.mockReturnValue({ success: false, code: 'INVALID_SIGNATURE', message: 'Invalid SAML signature' });
    const res = mockRes();

    handleSamlTestResult({ body: { sessionRef: SESSION_REF } }, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: { message: 'Invalid SAML signature', code: 'INVALID_SIGNATURE' },
    });
  });

  test('falls back to a generic code when the failure has none', () => {
    takeSamlTestResult.mockReturnValue({ success: false, message: 'Something went wrong' });
    const res = mockRes();

    handleSamlTestResult({ body: { sessionRef: SESSION_REF } }, res);

    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: { message: 'Something went wrong', code: 'TEST_CONNECTION_FAILED' },
    });
  });

  test('answers 200 with the claims when the test passed', () => {
    const claims = { roles: ['Admin'], groups: [], groupsOverage: false };
    takeSamlTestResult.mockReturnValue({ success: true, email: 'user@example.com', claims });
    const res = mockRes();

    handleSamlTestResult({ body: { sessionRef: SESSION_REF } }, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      data: { protocol: 'saml', sso_status: 'active', claims },
    });
  });
});
