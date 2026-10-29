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
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test.each([
    ['no body', undefined],
    ['an empty body', {}],
    ['a non-string sessionRef', { sessionRef: 123 }],
    ['an empty sessionRef', { sessionRef: '' }],
  ])('returns 400 MISSING_SESSION_REF for %s', (_label, body) => {
    const res = mockRes();

    handleSamlTestResult({ body }, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: { message: 'sessionRef is required', code: 'MISSING_SESSION_REF' },
    });
    expect(takeSamlTestResult).not.toHaveBeenCalled();
  });

  test('returns 401 TC_STORE_EXPIRED for an unknown or expired session', () => {
    takeSamlTestResult.mockReturnValue(null);
    const res = mockRes();

    handleSamlTestResult({ body: { sessionRef: 'ref-1' } }, res);

    expect(takeSamlTestResult).toHaveBeenCalledWith('ref-1');
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: { message: 'Session expired. Please try again.', code: 'TC_STORE_EXPIRED' },
    });
  });

  test('returns 202 pending until the ACS callback has run', () => {
    takeSamlTestResult.mockReturnValue({ pending: true });
    const res = mockRes();

    handleSamlTestResult({ body: { sessionRef: 'ref-1' } }, res);

    expect(res.status).toHaveBeenCalledWith(202);
    expect(res.json).toHaveBeenCalledWith({ success: true, pending: true });
  });

  test('returns 400 with the validation error when the test login failed', () => {
    takeSamlTestResult.mockReturnValue({ success: false, code: 'INVALID_SIGNATURE', message: 'Invalid signature' });
    const res = mockRes();

    handleSamlTestResult({ body: { sessionRef: 'ref-1' } }, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: { message: 'Invalid signature', code: 'INVALID_SIGNATURE' },
    });
  });

  test('returns 200 with the role and group claims when the test login passed', () => {
    const claims = { roles: ['Zebra.Admin'], groups: ['g-1'], groupsOverage: false };
    takeSamlTestResult.mockReturnValue({ success: true, email: 'admin@example.com', claims });
    const res = mockRes();

    handleSamlTestResult({ body: { sessionRef: 'ref-1' } }, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      data: { protocol: 'saml', sso_status: 'active', claims },
    });
  });

  test('does not echo the email back to the browser', () => {
    takeSamlTestResult.mockReturnValue({ success: true, email: 'admin@example.com', claims: { roles: [], groups: [], groupsOverage: false } });
    const res = mockRes();

    handleSamlTestResult({ body: { sessionRef: 'ref-1' } }, res);

    expect(JSON.stringify(res.json.mock.calls[0][0])).not.toContain('admin@example.com');
  });
});
