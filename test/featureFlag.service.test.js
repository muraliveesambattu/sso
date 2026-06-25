const loadFeatureFlagService = ({ usePostgres = false, queryImpl } = {}) => {
  jest.resetModules();

  const query = jest.fn(queryImpl || (async () => []));
  const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };

  jest.doMock('../src/config/logger', () => ({ logger }));
  jest.doMock('../src/config/dataSource', () => ({ usePostgres }));
  if (usePostgres) {
    jest.doMock('../src/config/db', () => ({
      query,
      QueryTypes: { SELECT: 'SELECT' },
    }));
  }

  const service = require('../src/services/featureFlag.service');
  return { ...service, query, logger };
};

describe('featureFlag.service', () => {
  const originalEnv = {
    FEATURE_SSO_ENABLED_DISABLED: process.env.FEATURE_SSO_ENABLED_DISABLED,
    FEATURE_JIT_ENABLED_DISABLED: process.env.FEATURE_JIT_ENABLED_DISABLED,
  };

  beforeEach(() => {
    delete process.env.FEATURE_SSO_ENABLED_DISABLED;
    delete process.env.FEATURE_JIT_ENABLED_DISABLED;
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
  });

  afterAll(() => {
    process.env.FEATURE_SSO_ENABLED_DISABLED = originalEnv.FEATURE_SSO_ENABLED_DISABLED;
    process.env.FEATURE_JIT_ENABLED_DISABLED = originalEnv.FEATURE_JIT_ENABLED_DISABLED;
  });

  test('defaults unknown flags to enabled', async () => {
    const { isEnabled } = loadFeatureFlagService();

    await expect(isEnabled('company-1', 'mystery_flag')).resolves.toBe(true);
  });

  test('honors environment kill switches before checking storage', async () => {
    process.env.FEATURE_SSO_ENABLED_DISABLED = 'true';
    const { isEnabled, query } = loadFeatureFlagService({ usePostgres: true });

    await expect(isEnabled('company-1', 'sso_enabled')).resolves.toBe(false);
    expect(query).not.toHaveBeenCalled();
  });

  test('uses the database value when PostgreSQL is enabled', async () => {
    const { isEnabled, query } = loadFeatureFlagService({
      usePostgres: true,
      queryImpl: async () => [{ enabled: false }],
    });

    await expect(isEnabled('company-2', 'jit_enabled')).resolves.toBe(false);
    expect(query).toHaveBeenCalledTimes(1);
  });

  test('falls back to default true when DB reads fail', async () => {
    const { isEnabled } = loadFeatureFlagService({
      usePostgres: true,
      queryImpl: async () => { throw new Error('db offline'); },
    });

    await expect(isEnabled('company-3', 'sso_enabled')).resolves.toBe(true);
  });

  test('lists flags with env overrides, database values, and defaults', async () => {
    process.env.FEATURE_JIT_ENABLED_DISABLED = 'true';
    const { getFlagsForCompany, query } = loadFeatureFlagService({
      usePostgres: true,
      queryImpl: async () => [{ enabled: false }],
    });

    const result = await getFlagsForCompany('company-4');

    expect(result).toEqual({
      sso_enabled: { enabled: false, source: 'database' },
      jit_enabled: { enabled: false, source: 'env_override' },
    });
    expect(query).toHaveBeenCalledTimes(1);
  });

  test('throws on invalid flags during updates', async () => {
    const { setFlag } = loadFeatureFlagService();

    await expect(setFlag('company-5', 'bad_flag', true, 'admin')).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_FLAG',
    });
  });

  test('writes valid flags to PostgreSQL', async () => {
    const { setFlag, query } = loadFeatureFlagService({
      usePostgres: true,
      queryImpl: async () => [],
    });

    await expect(setFlag('company-6', 'sso_enabled', false, 'admin@example.com')).resolves.toBeUndefined();
    expect(query).toHaveBeenCalledWith(
      expect.stringContaining('INSERT INTO feature_flags'),
      expect.objectContaining({
        replacements: {
          companyId: 'company-6',
          flagName: 'sso_enabled',
          enabled: false,
          updatedBy: 'admin@example.com',
        },
      })
    );
  });
});
