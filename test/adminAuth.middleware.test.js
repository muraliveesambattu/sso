jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
  requestLogger: (req, res, next) => next(),
}));

const { requireAdminKey } = require('../src/middlewares/adminAuth.middleware');

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};
const mockReq = (key) => ({ headers: key === undefined ? {} : { 'x-admin-api-key': key }, path: '/auth/sso/save', ip: '1.2.3.4' });

describe('requireAdminKey middleware', () => {
  const ORIG = process.env.ADMIN_API_KEY;
  afterEach(() => { process.env.ADMIN_API_KEY = ORIG; });

  test('503 SERVER_MISCONFIGURED when ADMIN_API_KEY is not set', () => {
    delete process.env.ADMIN_API_KEY;
    const req = mockReq('anything'); const res = mockRes(); const next = jest.fn();
    requireAdminKey(req, res, next);
    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ success: false, error: expect.objectContaining({ code: 'SERVER_MISCONFIGURED' }) }));
    expect(next).not.toHaveBeenCalled();
  });

  test('401 MISSING_API_KEY when header absent', () => {
    process.env.ADMIN_API_KEY = 'secret-key';
    const req = mockReq(undefined); const res = mockRes(); const next = jest.fn();
    requireAdminKey(req, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json.mock.calls[0][0].error.code).toBe('MISSING_API_KEY');
    expect(next).not.toHaveBeenCalled();
  });

  test('403 INVALID_API_KEY when key is wrong (different length)', () => {
    process.env.ADMIN_API_KEY = 'secret-key';
    const req = mockReq('wrong'); const res = mockRes(); const next = jest.fn();
    requireAdminKey(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json.mock.calls[0][0].error.code).toBe('INVALID_API_KEY');
    expect(next).not.toHaveBeenCalled();
  });

  test('403 INVALID_API_KEY when key is wrong (same length)', () => {
    process.env.ADMIN_API_KEY = 'abcdef';
    const req = mockReq('ghijkl'); const res = mockRes(); const next = jest.fn();
    requireAdminKey(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('calls next() when key matches exactly', () => {
    process.env.ADMIN_API_KEY = 'super-secret-key';
    const req = mockReq('super-secret-key'); const res = mockRes(); const next = jest.fn();
    requireAdminKey(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });
});
