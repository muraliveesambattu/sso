const loadHealthController = ({ nodeEnv = 'test', dbEnv = {}, authenticateImpl } = {}) => {
  jest.resetModules();

  const originalDatabaseUrl = process.env.DATABASE_URL;
  const originalDbHost = process.env.DB_HOST;
  process.env.NODE_ENV = nodeEnv;
  if ('DATABASE_URL' in dbEnv) process.env.DATABASE_URL = dbEnv.DATABASE_URL;
  else delete process.env.DATABASE_URL;
  if ('DB_HOST' in dbEnv) process.env.DB_HOST = dbEnv.DB_HOST;
  else delete process.env.DB_HOST;

  const authenticate = jest.fn(authenticateImpl || (async () => undefined));
  const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };

  jest.doMock('../src/config/db', () => ({ authenticate }));
  jest.doMock('../src/config/logger', () => ({ logger }));
  jest.doMock('../package.json', () => ({ version: '1.0.0-test' }), { virtual: true });

  const { healthCheck } = require('../src/controllers/health.controller');

  return {
    healthCheck,
    authenticate,
    logger,
    restore: () => {
      process.env.DATABASE_URL = originalDatabaseUrl;
      process.env.DB_HOST = originalDbHost;
    },
  };
};

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('health.controller', () => {
  afterEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
  });

  test('reports healthy with JSON fallback when no database is configured', async () => {
    const loader = loadHealthController({ dbEnv: {} });
    const res = mockRes();

    await loader.healthCheck({}, res);

    expect(loader.authenticate).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json.mock.calls[0][0]).toEqual(expect.objectContaining({
      status: 'healthy',
      version: '1.0.0-test',
      checks: { database: { status: 'not_configured', detail: 'Using JSON fallback' } },
    }));
    loader.restore();
  });

  test('reports healthy when database authentication succeeds', async () => {
    const loader = loadHealthController({ dbEnv: { DATABASE_URL: 'postgres://db' } });
    const res = mockRes();

    await loader.healthCheck({}, res);

    expect(loader.authenticate).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json.mock.calls[0][0].checks.database.status).toBe('healthy');
    loader.restore();
  });

  test('reports degraded when database authentication fails', async () => {
    const loader = loadHealthController({
      dbEnv: { DB_HOST: 'localhost' },
      authenticateImpl: async () => { throw new Error('db down'); },
    });
    const res = mockRes();

    await loader.healthCheck({}, res);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json.mock.calls[0][0]).toEqual(expect.objectContaining({
      status: 'degraded',
      checks: { database: expect.objectContaining({ status: 'unhealthy', error: 'db down' }) },
    }));
    loader.restore();
  });
});
