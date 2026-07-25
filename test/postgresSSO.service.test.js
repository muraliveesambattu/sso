const loadPostgresService = () => {
  jest.resetModules();

  const transaction = { commit: jest.fn(), rollback: jest.fn() };
  const sequelizeDb = { transaction: jest.fn(async () => transaction) };
  const queryDb = sequelizeDb;

  const SsoIntegration = {
    findOne: jest.fn(),
    upsert: jest.fn(),
    update: jest.fn(),
    destroy: jest.fn(),
  };
  const SsoDomain = {
    findOne: jest.fn(),
    findAll: jest.fn(),
    destroy: jest.fn(),
    bulkCreate: jest.fn(),
  };
  const OidcConfiguration = {
    findOne: jest.fn(),
    upsert: jest.fn(),
    destroy: jest.fn(),
  };
  const SamlConfiguration = {
    findOne: jest.fn(),
    findAll: jest.fn(),
    upsert: jest.fn(),
    destroy: jest.fn(),
  };
  const ZdnaRole = { findAll: jest.fn() };
  const JitMapping = {
    findAll: jest.fn(),
    destroy: jest.fn(),
    bulkCreate: jest.fn(),
  };
  const SsoUser = {
    findOne: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  };
  const encrypt = jest.fn((value) => `enc:${value}`);
  const resolveSecret = jest.fn((value) => value ? `dec:${value}` : value);
  const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };

  jest.doMock('../src/config/logger', () => ({ logger }));
  jest.doMock('../src/config/constants', () => ({
    defaults: {
      OIDC_SCOPE: 'openid profile email offline_access',
      OIDC_REDIRECT_URI: 'http://localhost:3000/auth/oidc/callback',
      SAML_ENTITY_ID: 'https://default.example.com/metadata',
      SAML_ACS_URL: 'https://default.example.com/callback',
    },
  }));
  jest.doMock('../src/models', () => ({
    SsoIntegration,
    SsoDomain,
    OidcConfiguration,
    SamlConfiguration,
    ZdnaRole,
    JitMapping,
    SsoUser,
  }));
  jest.doMock('../src/utils/crypto.util', () => ({ encrypt, resolveSecret }));
  jest.doMock('../src/config/db', () => queryDb);
  jest.doMock('sequelize', () => ({ Op: { in: Symbol('in') } }));

  const service = require('../src/services/db/postgresSSO.service');
  return { service, mocks: { transaction, sequelizeDb, queryDb, SsoIntegration, SsoDomain, OidcConfiguration, SamlConfiguration, ZdnaRole, JitMapping, SsoUser, encrypt, resolveSecret, logger } };
};

describe('postgresSSO.service', () => {
  afterEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
  });

  test('fetches active integrations by domain (via sso_domains) and normalizes results', async () => {
    const { service, mocks } = loadPostgresService();
    mocks.SsoDomain.findOne.mockResolvedValue({ company_id: 'company-1' });
    mocks.SsoIntegration.findOne.mockResolvedValue({ toJSON: () => ({ company_id: 'company-1', protocol: 'oidc' }) });

    await expect(service.getSsoIntegrationByDomain('Example.com')).resolves.toEqual({ company_id: 'company-1', protocol: 'oidc' });
    expect(mocks.SsoDomain.findOne).toHaveBeenCalledWith({ where: { domain: 'example.com' } });
    expect(mocks.SsoIntegration.findOne).toHaveBeenCalledWith({ where: { company_id: 'company-1', sso_status: 'active' } });
  });

  test('returns null when the domain is not registered in sso_domains', async () => {
    const { service, mocks } = loadPostgresService();
    mocks.SsoDomain.findOne.mockResolvedValue(null);

    await expect(service.getSsoIntegrationByDomain('unknown.com')).resolves.toBeNull();
    expect(mocks.SsoIntegration.findOne).not.toHaveBeenCalled();
  });

  test('returns null or empty collections for missing integrations, configs, and roles', async () => {
    const { service, mocks } = loadPostgresService();
    mocks.SsoIntegration.findOne.mockResolvedValue(null);
    mocks.OidcConfiguration.findOne.mockResolvedValue(null);
    mocks.SamlConfiguration.findOne.mockResolvedValue(null);
    mocks.SamlConfiguration.findAll.mockResolvedValue([]);
    mocks.JitMapping.findAll.mockResolvedValue([]);

    await expect(service.getSsoIntegrationByCompanyId('missing-company')).resolves.toBeNull();
    await expect(service.getOidcConfig('missing-company')).resolves.toBeNull();
    await expect(service.getSamlConfig('missing-company')).resolves.toBeNull();
    await expect(service.getSamlConfigByAcsUrl('https://missing.example.com/callback')).resolves.toBeNull();
    await expect(service.getJitMappings('missing-company')).resolves.toEqual([]);
    await expect(service.getRolesByIds([])).resolves.toEqual([]);
  });

  test('decrypts OIDC secrets and resolves env-backed SAML ACS/entity values', async () => {
    const { service, mocks } = loadPostgresService();
    process.env.SAML_ENTITY_ID = 'https://sp.example.com/metadata';
    process.env.SAML_ACS_URL = 'https://sp.example.com/callback';

    mocks.OidcConfiguration.findOne.mockResolvedValue({
      toJSON: () => ({ company_id: 'company-1', client_secret_enc: 'secret-enc', private_key_enc: 'pk-enc' }),
    });
    mocks.SamlConfiguration.findAll.mockResolvedValue([
      { toJSON: () => ({ company_id: 'company-2', entity_id: 'env:SAML_ENTITY_ID', acs_url: 'env:SAML_ACS_URL' }) },
    ]);

    await expect(service.getOidcConfig('company-1')).resolves.toEqual(
      expect.objectContaining({ client_secret: 'dec:secret-enc', client_cert_enc: 'dec:pk-enc' })
    );
    await expect(service.getSamlConfigByAcsUrl('https://sp.example.com/callback')).resolves.toEqual(
      expect.objectContaining({ entity_id: 'https://sp.example.com/metadata', acs_url: 'https://sp.example.com/callback' })
    );
  });

  test('queries roles and user lookups with normalized inputs', async () => {
    const { service, mocks } = loadPostgresService();
    mocks.ZdnaRole.findAll.mockResolvedValue([{ toJSON: () => ({ role_id: 'role-admin' }) }]);
    mocks.SsoUser.findOne
      .mockResolvedValueOnce({ toJSON: () => ({ user_id: 'user-oid', email: 'user@example.com' }) })
      .mockResolvedValueOnce(null);

    await expect(service.getRolesByIds(['role-admin'])).resolves.toEqual([{ role_id: 'role-admin' }]);
    await expect(service.findUserByOid('company-1', 'oid-1')).resolves.toEqual(
      expect.objectContaining({ id: 'user-oid', email: 'user@example.com' })
    );
    await expect(service.findUserByEmail('company-1', 'USER@EXAMPLE.COM')).resolves.toBeNull();
    expect(mocks.SsoUser.findOne).toHaveBeenLastCalledWith({ where: { company_id: 'company-1', email: 'user@example.com' } });
  });

  test('creates and normalizes users', async () => {
    const { service, mocks } = loadPostgresService();
    mocks.SsoUser.create.mockResolvedValue({
      toJSON: () => ({ user_id: 'user-1', email: 'user@example.com' }),
    });

    const user = await service.createUser({ email: 'User@Example.com', company_id: 'company-1' });
    expect(mocks.SsoUser.create).toHaveBeenCalledWith(expect.objectContaining({ email: 'user@example.com' }));
    expect(user).toEqual({ user_id: 'user-1', email: 'user@example.com', id: 'user-1' });
  });

  test('saves SSO config in a transaction and commits on success', async () => {
    const { service, mocks } = loadPostgresService();
    // Re-saving the same company_id (an edit) — the incoming domain already
    // belongs to that same company, so it's not a conflict.
    mocks.SsoDomain.findOne.mockResolvedValue({ company_id: 'existing-company' });

    await service.saveSsoConfig({
      company_id: 'existing-company',
      protocol: 'oidc',
      domains: 'example.com',
      client_id: 'client-1',
      auth_method: 'private_key_jwt',
      client_secret: 'secret-1',
      private_key_b64: 'private-key',
      client_cert_thumbprint: 'thumb',
      jit_enabled: true,
      jit_mappings: [{ mapping_source: 'default', zdna_role: 'role-admin' }],
    });

    expect(mocks.encrypt).toHaveBeenCalledWith('secret-1');
    expect(mocks.encrypt).toHaveBeenCalledWith('private-key');
    expect(mocks.SsoIntegration.upsert).toHaveBeenCalledWith(expect.objectContaining({
      company_id: 'existing-company',
      protocol: 'oidc',
    }), { transaction: mocks.transaction });
    // Domains persisted to the child table, not a column on sso_integrations.
    expect(mocks.SsoDomain.bulkCreate).toHaveBeenCalledWith(
      [{ company_id: 'existing-company', domain: 'example.com' }],
      { transaction: mocks.transaction },
    );
    // role_name persisted on the mapping; falls back to the role id here.
    expect(mocks.JitMapping.bulkCreate).toHaveBeenCalledWith([
      expect.objectContaining({ company_id: 'existing-company', role_id: 'role-admin', role_name: 'role-admin' }),
    ], { transaction: mocks.transaction });
    expect(mocks.OidcConfiguration.upsert).toHaveBeenCalledWith(expect.objectContaining({
      company_id: 'existing-company',
      client_secret_enc: 'enc:secret-1',
      private_key_enc: 'enc:private-key',
    }), { transaction: mocks.transaction });
    expect(mocks.JitMapping.bulkCreate).toHaveBeenCalledWith([
      expect.objectContaining({ company_id: 'existing-company', role_id: 'role-admin' }),
    ], { transaction: mocks.transaction });
    expect(mocks.transaction.commit).toHaveBeenCalled();
  });

  test('saves SAML configs, updates users, and returns booleans for status/delete operations', async () => {
    const { service, mocks } = loadPostgresService();
    mocks.SsoIntegration.findOne.mockResolvedValue(null);
    mocks.SsoIntegration.update.mockResolvedValue([0]);
    mocks.OidcConfiguration.destroy.mockResolvedValue(undefined);
    mocks.SamlConfiguration.destroy.mockResolvedValue(undefined);
    mocks.JitMapping.destroy.mockResolvedValue(undefined);
    mocks.SsoIntegration.destroy.mockResolvedValue(1);

    await service.saveSsoConfig({
      company_id: 'new-company',
      protocol: 'saml',
      domains: 'saml.example.com',
      sso_url: 'https://login.microsoftonline.com/tenant/saml2',
      entity_id: 'https://sp.example.com/metadata',
      acs_url: 'https://sp.example.com/callback',
      certificate: 'cert-value',
      cert_expiry: '2029-01-01T00:00:00Z',
      jit_enabled: false,
    });

    expect(mocks.SamlConfiguration.upsert).toHaveBeenCalledWith(expect.objectContaining({
      company_id: 'new-company',
      entity_id: 'https://sp.example.com/metadata',
      acs_url: 'https://sp.example.com/callback',
      certificate: 'cert-value',
    }), { transaction: mocks.transaction });
    expect(mocks.JitMapping.bulkCreate).not.toHaveBeenCalled();

    await service.updateUser('user-2', { last_login: '2026-06-26T00:00:00Z' });
    expect(mocks.SsoUser.update).toHaveBeenCalledWith({ last_login: '2026-06-26T00:00:00Z' }, { where: { user_id: 'user-2' } });

    await expect(service.setSsoStatus('company-1', 'inactive')).resolves.toBe(false);
    await expect(service.deleteSsoConfig('company-1')).resolves.toBe(true);
    expect(mocks.transaction.commit).toHaveBeenCalledTimes(2);
  });

  test('masks secrets in config details and rolls back failed deletes', async () => {
    const { service, mocks } = loadPostgresService();
    mocks.SsoIntegration.findOne.mockResolvedValue({ toJSON: () => ({ company_id: 'company-1', domains: 'example.com' }) });
    mocks.OidcConfiguration.findOne.mockResolvedValue({
      toJSON: () => ({ company_id: 'company-1', client_secret_enc: 'enc-secret', private_key_enc: 'enc-key', client_id: 'client-1' }),
    });
    mocks.SamlConfiguration.findOne.mockResolvedValue({
      toJSON: () => ({ company_id: 'company-1', sp_private_key_enc: 'sp-key', certificate: 'cert' }),
    });
    mocks.JitMapping.findAll.mockResolvedValue([{ toJSON: () => ({ company_id: 'company-1', role_id: 'role-admin', role_name: 'Admin' }) }]);
    mocks.SsoDomain.findAll.mockResolvedValue([{ domain: 'example.com' }]);

    const details = await service.getSsoConfigDetails({ company_id: 'company-1' });
    expect(details.integration.domains).toEqual(['example.com']);
    expect(details.oidc_config.client_secret_set).toBe(true);
    expect(details.oidc_config.client_secret_enc).toBeUndefined();
    expect(details.saml_config.sp_private_key_enc).toBeUndefined();
    // role_name is stored on the mapping (no zdna_roles JOIN) so the console's
    // RMS-fed dropdown can pre-select the right option when a config is reopened.
    expect(details.jit_mappings[0]).toEqual(expect.objectContaining({ role_id: 'role-admin', role_name: 'Admin' }));

    mocks.OidcConfiguration.destroy.mockRejectedValueOnce(new Error('delete failed'));
    await expect(service.deleteSsoConfig('company-1')).rejects.toThrow('delete failed');
    expect(mocks.transaction.rollback).toHaveBeenCalled();
  });

  test('supports domain lookups (via sso_domains) and no-op cache invalidation', async () => {
    const { service, mocks } = loadPostgresService();
    // Domain lookup resolves via sso_domains → company_id, then the integration.
    mocks.SsoDomain.findOne.mockResolvedValue({ company_id: 'company-2' });
    mocks.SsoIntegration.findOne.mockResolvedValue({ toJSON: () => ({ company_id: 'company-2' }) });
    mocks.OidcConfiguration.findOne.mockResolvedValue(null);
    mocks.SamlConfiguration.findOne.mockResolvedValue(null);
    mocks.JitMapping.findAll.mockResolvedValue([]);
    mocks.SsoDomain.findAll.mockResolvedValue([]);

    await expect(service.getSsoConfigDetails({ domain: 'DOMAIN.EXAMPLE.COM' })).resolves.toEqual(
      expect.objectContaining({ integration: expect.objectContaining({ company_id: 'company-2' }) })
    );
    expect(mocks.SsoDomain.findOne).toHaveBeenCalledWith({ where: { domain: 'domain.example.com' } });

    expect(() => service.invalidateDomainCache('domain.example.com')).not.toThrow();
    expect(mocks.logger.debug).toHaveBeenCalled();
  });
});
