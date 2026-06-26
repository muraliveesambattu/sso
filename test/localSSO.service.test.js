const loadLocalService = ({ initialData, env = {} } = {}) => {
  jest.resetModules();

  const dataset = initialData || {
    sso_integrations: [
      { company_id: 'company-1', domains: 'example.com', protocol: 'oidc', sso_status: 'active', jit_enabled: true },
      { company_id: 'company-2', domains: 'inactive.com', protocol: 'saml', sso_status: 'inactive', jit_enabled: false },
    ],
    oidc_configurations: [
      { company_id: 'company-1', client_secret: 'enc:secret-1', redirect_uri: 'http://localhost/callback' },
    ],
    saml_configurations: [
      { company_id: 'company-3', entity_id: 'env:SAML_ENTITY_ID', acs_url: 'env:SAML_ACS_URL', sso_url: 'https://login.microsoftonline.com/tenant/saml2', certificate: 'cert' },
    ],
    jit_mappings: [
      { company_id: 'company-1', role_id: 'role-admin', status: 'active' },
      { company_id: 'company-1', role_id: 'role-old', status: 'inactive' },
    ],
    zdna_roles: [
      { role_id: 'role-admin', role_name: 'Administrator' },
      { role_id: 'role-viewer', role_name: 'Viewer' },
    ],
    sso_users: [
      { id: 'user-1', company_id: 'company-1', email: 'user@example.com', oid: 'oid-1', roles: ['role-admin'] },
    ],
  };

  process.env.SAML_ENTITY_ID = env.SAML_ENTITY_ID || 'https://sp.example.com/metadata';
  process.env.SAML_ACS_URL = env.SAML_ACS_URL || 'https://sp.example.com/callback';

  const readFileSync = jest.fn(() => JSON.stringify(dataset));
  const writeFileSync = jest.fn();
  const randomUUID = jest.fn(() => 'uuid-local');
  const resolveSecret = jest.fn((val) => val === 'enc:secret-1' ? 'plain-secret-1' : val);
  const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };

  jest.doMock('fs', () => ({ readFileSync, writeFileSync }));
  jest.doMock('crypto', () => ({ randomUUID }));
  jest.doMock('../src/config/logger', () => ({ logger }));
  jest.doMock('../src/config/constants', () => ({
    defaults: {
      OIDC_SCOPE: 'openid profile email offline_access',
      OIDC_REDIRECT_URI: 'http://localhost:3000/auth/oidc/callback',
      SAML_ENTITY_ID: 'https://default.example.com/metadata',
      SAML_ACS_URL: 'https://default.example.com/callback',
    },
  }));
  jest.doMock('../src/utils/crypto.util', () => ({ resolveSecret }));

  const service = require('../src/services/db/localSSO.service');
  return { ...service, mocks: { readFileSync, writeFileSync, randomUUID, resolveSecret, logger } };
};

describe('localSSO.service', () => {
  afterEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
  });

  test('returns only active integrations for domain lookups', async () => {
    const service = loadLocalService();

    await expect(service.getSsoIntegrationByDomain('Example.com')).resolves.toEqual(
      expect.objectContaining({ company_id: 'company-1', domains: 'example.com' })
    );
    await expect(service.getSsoIntegrationByDomain('inactive.com')).resolves.toBeNull();
  });

  test('decrypts OIDC secrets and resolves env refs for SAML config lookups', async () => {
    const service = loadLocalService();

    await expect(service.getOidcConfig('company-1')).resolves.toEqual(
      expect.objectContaining({ client_secret: 'plain-secret-1' })
    );
    await expect(service.getSamlConfigByAcsUrl('https://sp.example.com/callback')).resolves.toEqual(
      expect.objectContaining({
        entity_id: 'https://sp.example.com/metadata',
        acs_url: 'https://sp.example.com/callback',
      })
    );
  });

  test('returns null or empty collections for missing local entries', async () => {
    const service = loadLocalService();

    await expect(service.getOidcConfig('missing-company')).resolves.toBeNull();
    await expect(service.getSamlConfig('missing-company')).resolves.toBeNull();
    await expect(service.getSamlConfigByAcsUrl('https://missing.example.com/callback')).resolves.toBeNull();
    await expect(service.getJitMappings('missing-company')).resolves.toEqual([]);
    await expect(service.getRolesByIds([])).resolves.toEqual([]);
    await expect(service.findUserByOid('company-1', 'missing-oid')).resolves.toBeNull();
    await expect(service.findUserByEmail('company-1', 'missing@example.com')).resolves.toBeNull();
  });

  test('creates users with normalized emails and persists the JSON store', async () => {
    const service = loadLocalService();

    const created = await service.createUser({
      company_id: 'company-1',
      email: 'User@Example.com',
      oid: 'oid-2',
    });

    expect(created).toEqual(expect.objectContaining({
      id: 'uuid-local',
      email: 'user@example.com',
      createdAt: expect.any(String),
      updatedAt: expect.any(String),
    }));
    expect(service.mocks.writeFileSync).toHaveBeenCalledTimes(1);
  });

  test('updates users and warns without persisting when the user is missing', async () => {
    const service = loadLocalService();

    await service.updateUser('user-1', { display_name: 'Updated User' });
    expect(service.mocks.writeFileSync).toHaveBeenCalledTimes(1);

    await service.updateUser('missing-user', { display_name: 'Nobody' });
    expect(service.mocks.logger.warn).toHaveBeenCalled();
    expect(service.mocks.writeFileSync).toHaveBeenCalledTimes(1);
  });

  test('masks secrets in details, updates status, deletes config, and reloads data', async () => {
    const reloadedData = {
      sso_integrations: [{ company_id: 'company-9', domains: 'reload.com', protocol: 'oidc', sso_status: 'active' }],
      oidc_configurations: [],
      saml_configurations: [],
      jit_mappings: [],
      zdna_roles: [],
      sso_users: [],
    };
    const service = loadLocalService({
      initialData: {
        sso_integrations: [{ company_id: 'company-1', domains: 'example.com', protocol: 'oidc', sso_status: 'active' }],
        oidc_configurations: [{ company_id: 'company-1', client_secret: 'secret-set', client_id: 'client-1' }],
        saml_configurations: [],
        jit_mappings: [],
        zdna_roles: [],
        sso_users: [],
      },
    });

    service.mocks.readFileSync.mockReturnValue(JSON.stringify(reloadedData));

    const details = await service.getSsoConfigDetails({ company_id: 'company-1' });
    expect(details.oidc_config.client_secret_set).toBe(true);
    expect(details.oidc_config.client_secret).toBeUndefined();

    await expect(service.setSsoStatus('company-1', 'inactive')).resolves.toBe(true);
    await expect(service.deleteSsoConfig('company-1')).resolves.toBe(true);

    service.invalidateDomainCache('reload.com');
    await expect(service.getSsoIntegrationByCompanyId('company-9')).resolves.toEqual(
      expect.objectContaining({ domains: 'reload.com' })
    );
  });

  test('returns domain-based SAML details, and false for missing status/delete targets', async () => {
    const service = loadLocalService({
      initialData: {
        sso_integrations: [{ company_id: 'company-saml', domains: 'saml.example.com', protocol: 'saml', sso_status: 'active' }],
        oidc_configurations: [],
        saml_configurations: [{ company_id: 'company-saml', certificate: 'cert-value', cert_expiry: '2029-01-01T00:00:00Z' }],
        jit_mappings: [],
        zdna_roles: [],
        sso_users: [],
      },
    });

    await expect(service.getSsoConfigDetails({ domain: 'saml.example.com' })).resolves.toEqual(
      expect.objectContaining({
        integration: expect.objectContaining({ company_id: 'company-saml' }),
        saml_config: expect.objectContaining({ certificate: 'cert-value' }),
      })
    );
    await expect(service.setSsoStatus('missing-company', 'inactive')).resolves.toBe(false);
    await expect(service.deleteSsoConfig('missing-company')).resolves.toBe(false);
  });
});
