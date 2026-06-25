const loadErrorHandler = ({ nodeEnv = 'test' } = {}) => {
  jest.resetModules();
  process.env.NODE_ENV = nodeEnv;
  const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
  jest.doMock('../src/config/logger', () => ({ logger }));
  const errorHandler = require('../src/middlewares/errorHandler');
  return { errorHandler, logger };
};

const mockReq = () => ({ method: 'POST', path: '/auth/oidc/token-exchange' });
const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('errorHandler middleware', () => {
  const originalNodeEnv = process.env.NODE_ENV;

  afterEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
  });

  afterAll(() => {
    process.env.NODE_ENV = originalNodeEnv;
  });

  test('returns mapped safe messages for operational errors', () => {
    const { errorHandler, logger } = loadErrorHandler({ nodeEnv: 'test' });
    const res = mockRes();
    const err = Object.assign(new Error('raw message'), { statusCode: 401, code: 'TENANT_MISMATCH' });

    errorHandler(err, mockReq(), res);

    expect(logger.warn).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: { code: 'TENANT_MISMATCH', message: 'Organisation mismatch. Please contact your administrator.' },
    });
  });

  test('handles Sequelize errors separately', () => {
    const { errorHandler, logger } = loadErrorHandler({ nodeEnv: 'production' });
    const res = mockRes();
    const err = { name: 'SequelizeValidationError', message: 'bad column' };

    errorHandler(err, mockReq(), res);

    expect(logger.error).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json.mock.calls[0][0].error.code).toBe('DATABASE_ERROR');
  });

  test('blocks CORS errors with 403', () => {
    const { errorHandler } = loadErrorHandler({ nodeEnv: 'production' });
    const res = mockRes();
    const err = new Error('CORS: origin not allowed');

    errorHandler(err, mockReq(), res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json.mock.calls[0][0].error.code).toBe('CORS_ERROR');
  });

  test('includes stack traces for unexpected errors outside production', () => {
    const { errorHandler, logger } = loadErrorHandler({ nodeEnv: 'development' });
    const res = mockRes();
    const err = Object.assign(new Error('boom'), { code: 'INTERNAL_ERROR' });

    errorHandler(err, mockReq(), res);

    expect(logger.error).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json.mock.calls[0][0].error).toEqual(expect.objectContaining({
      code: 'INTERNAL_ERROR',
      message: 'boom',
      stack: expect.any(String),
    }));
  });

  test('sanitizes unexpected errors in production', () => {
    const { errorHandler } = loadErrorHandler({ nodeEnv: 'production' });
    const res = mockRes();
    const err = Object.assign(new Error('sensitive details'), { code: 'UNKNOWN_BUG' });

    errorHandler(err, mockReq(), res);

    expect(res.json.mock.calls[0][0].error).toEqual({
      code: 'UNKNOWN_BUG',
      message: 'An unexpected error occurred. Please try again.',
    });
  });
});
