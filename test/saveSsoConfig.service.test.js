const loadService = ({
  usePostgres = false,
  readFileImpl,
  writeFileImpl,
  pgSaveImpl,
  getByDomainImpl,
  extractImpl,
} = {}) => {
  jest.resetModules();

  const readFile = jest.fn(readFileImpl || (async () => JSON.stringify({
    sso_integrations: [],
    oidc_configurations: [],
    saml_configurations: [],
    jit_mappings: [],
  })));
  const writeFile = jest.fn(writeFileImpl || (async () => undefined));
  const encrypt = jest.fn((value) => `enc:${value}`);
  const extractFromPkcs12 = jest.fn(extractImpl || (() => ({
    privateKeyB64: 'private-key-b64',
    thumbprintHex: 'thumbprint-hex',
  })));
  const pgSave = jest.fn(pgSaveImpl || (async () => undefined));
  const getSsoIntegrationByDomain = jest.fn(getByDomainImpl || (async (domain) => ({ company_id: `saved-${domain}` })));

  jest.doMock('../src/config/logger', () => ({
    logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
  }));
  jest.doMock('uuid', () => ({ v4: jest.fn(() => 'uuid-value') }));
  jest.doMock('../src/utils/crypto.util', () => ({ encrypt }));
  jest.doMock('../src/utils/oidc/pkcs12.util', () => ({ extractFromPkcs12 }));
  jest.doMock('fs', () => ({ promises: { readFile, writeFile } }));
  jest.doMock('../src/config/dataSource', () => ({ usePostgres }));
  jest.doMock('../src/config/constants', () => ({
    defaults: {
      SSO_STATUS: 'active',
      IDP: 'microsoft_entra',
      OIDC_SCOPE: 'openid profile email offline_access',
      OIDC_REDIRECT_URI: 'http://localhost:3000/auth/oidc/callback',
      SAML_ENTITY_ID: 'https://zdna-sso.web.app/auth/metadata2',
      SAML_ACS_URL: 'https://zdna-sso.web.app/auth/callback',
    },
  }));

  if (usePostgres) {
    jest.doMock('../src/services/db/postgresSSO.service', () => ({
      saveSsoConfig: pgSave,
      getSsoIntegrationByDomain,
    }));
  }

  const { saveSsoConfig } = require('../src/services/SSO/saveSsoConfig.service');
  return { saveSsoConfig, readFile, writeFile, encrypt, extractFromPkcs12, pgSave, getSsoIntegrationByDomain };
};

describe('saveSsoConfig.service', () => {
  let dateNowSpy;

  beforeEach(() => {
    dateNowSpy = jest.spyOn(Date, 'now').mockReturnValue(1700000000000);
  });

  afterEach(() => {
    dateNowSpy.mockRestore();
    jest.clearAllMocks();
    jest.resetModules();
  });

  test('validates required OIDC tenant_id', async () => {
    const { saveSsoConfig } = loadService();

    await expect(saveSsoConfig({
      protocol: 'oidc',
      domains: 'example.com',
    })).rejects.toMatchObject({
      statusCode: 400,
      code: 'MISSING_TENANT_ID',
    });
  });

  test('validates protocol, domain, tenant, and SAML URL formats', async () => {
    const { saveSsoConfig } = loadService();

    await expect(saveSsoConfig({ domains: 'example.com' })).rejects.toMatchObject({ code: 'MISSING_PROTOCOL' });
    await expect(saveSsoConfig({ protocol: 'oauth', domains: 'example.com' })).rejects.toMatchObject({ code: 'INVALID_PROTOCOL' });
    await expect(saveSsoConfig({ protocol: 'oidc', domains: 'not a domain', tenant_id: 'common' })).rejects.toMatchObject({ code: 'INVALID_DOMAINS' });
    await expect(saveSsoConfig({ protocol: 'oidc', domains: 'example.com', tenant_id: 'bad-tenant' })).rejects.toMatchObject({ code: 'INVALID_TENANT_ID' });
    await expect(saveSsoConfig({ protocol: 'saml', domains: 'example.com', sso_url: 'ftp://bad-url' })).rejects.toMatchObject({ code: 'INVALID_SSO_URL' });
  });

  test('saves OIDC configs to JSON with encrypted client secrets and normalized domains', async () => {
    const { saveSsoConfig, writeFile } = loadService();

    const result = await saveSsoConfig({
      protocol: 'oidc',
      domains: 'Example.COM',
      tenant_id: 'common',
      client_id: 'client-1',
      auth_method: 'client_secret',
      client_secret: 'super-secret',
      jit_enabled: true,
      jit_mappings: [{ mapping_source: 'default', zdna_role: 'role-analyst' }],
    });

    const written = JSON.parse(writeFile.mock.calls[0][1]);
    expect(written.sso_integrations[0]).toEqual(expect.objectContaining({
      company_id: 'zdna-Example-COM-1700000000000',
      domains: 'example.com',
      protocol: 'oidc',
      entra_tenant_id: 'common',
      jit_enabled: true,
    }));
    expect(written.oidc_configurations[0]).toEqual(expect.objectContaining({
      company_id: 'zdna-Example-COM-1700000000000',
      client_id: 'client-1',
      client_auth_method: 'client_secret',
      client_secret: 'enc:super-secret',
      scope: 'openid profile email offline_access',
      redirect_uri: 'http://localhost:3000/auth/oidc/callback',
    }));
    expect(written.jit_mappings[0]).toEqual(expect.objectContaining({
      company_id: 'zdna-Example-COM-1700000000000',
      mapping_source: 'default',
      role_id: 'role-analyst',
      status: 'active',
    }));
    expect(result).toEqual({
      success: true,
      company_id: 'zdna-Example-COM-1700000000000',
      message: 'SSO configuration saved and activated successfully',
    });
  });

  test('extracts and stores client certificate material for private_key_jwt auth', async () => {
    const { saveSsoConfig, writeFile, extractFromPkcs12 } = loadService();

    await saveSsoConfig({
      protocol: 'oidc',
      domains: 'cert.example.com',
      tenant_id: 'organizations',
      client_id: 'client-cert',
      auth_method: 'private_key_jwt',
      certificate: 'base64-p12',
      certificate_password: 'password-1',
    });

    const written = JSON.parse(writeFile.mock.calls[0][1]);
    expect(extractFromPkcs12).toHaveBeenCalledWith('base64-p12', 'password-1');
    expect(written.oidc_configurations[0]).toEqual(expect.objectContaining({
      private_key_enc: 'enc:private-key-b64',
      client_cert_thumbprint: 'thumbprint-hex',
    }));
  });

  test('derives SAML tenant ids from the SSO URL and initializes empty JSON stores when the file is missing', async () => {
    const { saveSsoConfig, writeFile } = loadService({
      readFileImpl: async () => {
        const err = new Error('missing');
        err.code = 'ENOENT';
        throw err;
      },
    });

    await saveSsoConfig({
      protocol: 'saml',
      domains: 'zebra.com',
      sso_url: 'https://login.microsoftonline.com/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/saml2',
    });

    const written = JSON.parse(writeFile.mock.calls[0][1]);
    expect(written.sso_integrations[0]).toEqual(expect.objectContaining({
      domains: 'zebra.com',
      protocol: 'saml',
      entra_tenant_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    }));
    expect(written.saml_configurations[0]).toEqual(expect.objectContaining({
      sso_url: 'https://login.microsoftonline.com/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/saml2',
      entity_id: 'https://zdna-sso.web.app/auth/metadata2',
      acs_url: 'https://zdna-sso.web.app/auth/callback',
    }));
  });

  test('throws CONFIG_READ_ERROR for unexpected JSON read failures', async () => {
    const { saveSsoConfig } = loadService({
      readFileImpl: async () => {
        const err = new Error('permission denied');
        err.code = 'EACCES';
        throw err;
      },
    });

    await expect(saveSsoConfig({
      protocol: 'oidc',
      domains: 'example.com',
      tenant_id: 'common',
    })).rejects.toMatchObject({
      statusCode: 500,
      code: 'CONFIG_READ_ERROR',
    });
  });

  test('uses PostgreSQL when enabled and skips JSON writes on success', async () => {
    const { saveSsoConfig, writeFile, pgSave, getSsoIntegrationByDomain } = loadService({
      usePostgres: true,
      getByDomainImpl: async () => ({ company_id: 'existing-company-id' }),
    });

    const result = await saveSsoConfig({
      protocol: 'oidc',
      domains: 'pg.example.com',
      tenant_id: 'common',
      client_id: 'client-pg',
      auth_method: 'client_secret_post',
      client_secret: 'pg-secret',
    });

    expect(pgSave).toHaveBeenCalledWith(expect.objectContaining({
      company_id: 'zdna-pg-example-com-1700000000000',
      domains: 'pg.example.com',
      client_secret: 'pg-secret',
    }));
    expect(getSsoIntegrationByDomain).toHaveBeenCalledWith('pg.example.com');
    expect(writeFile).not.toHaveBeenCalled();
    expect(result.company_id).toBe('existing-company-id');
  });

  // The silent JSON fallback on PostgreSQL failure was removed intentionally:
  // it masked DB write failures (returned 201 while nothing persisted). The
  // error must now propagate so the caller sees the failure.
  test('propagates the error when PostgreSQL save fails (no silent JSON fallback)', async () => {
    const { saveSsoConfig, writeFile, pgSave } = loadService({
      usePostgres: true,
      pgSaveImpl: async () => { throw new Error('db unavailable'); },
      getByDomainImpl: async () => null,
    });

    await expect(saveSsoConfig({
      protocol: 'oidc',
      domains: 'fallback.example.com',
      tenant_id: 'common',
      client_id: 'client-fallback',
      auth_method: 'client_secret_post',
      client_secret: 'secret-fallback',
    })).rejects.toThrow('db unavailable');

    expect(pgSave).toHaveBeenCalled();
    expect(writeFile).not.toHaveBeenCalled(); // must NOT silently fall back to JSON
  });

  test('strips any ?appid= query from the SAML sso_url before persisting', async () => {
    const { saveSsoConfig, writeFile } = loadService({
      readFileImpl: async () => {
        const err = new Error('missing');
        err.code = 'ENOENT';
        throw err;
      },
    });

    await saveSsoConfig({
      protocol: 'saml',
      domains: 'appid.example.com',
      sso_url: 'https://login.microsoftonline.com/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/saml2?appid=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    });

    const written = JSON.parse(writeFile.mock.calls[0][1]);
    // stored URL must be clean (no query) so the login redirect's own '?' is valid
    expect(written.saml_configurations[0].sso_url).toBe(
      'https://login.microsoftonline.com/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/saml2'
    );
  });
});
