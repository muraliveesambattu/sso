// PostgreSQL is the sole backend. This service validates + derives fields and
// hands the raw row to postgresSSO.service (which owns encryption, defaults,
// and table shaping). Tests therefore assert on what pgSave receives.
const loadService = ({
  pgSaveImpl,
  getByDomainImpl,
  extractImpl,
} = {}) => {
  jest.resetModules();

  const extractFromPkcs12 = jest.fn(extractImpl || (() => ({
    privateKeyB64: 'private-key-b64',
    thumbprintHex: 'thumbprint-hex',
  })));
  const pgSave = jest.fn(pgSaveImpl || (async () => undefined));
  const getSsoIntegrationByDomain = jest.fn(getByDomainImpl || (async (domain) => ({ company_id: `saved-${domain}` })));

  jest.doMock('../src/config/logger', () => ({
    logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
  }));
  jest.doMock('../src/utils/oidc/pkcs12.util', () => ({ extractFromPkcs12 }));
  jest.doMock('../src/services/db/postgresSSO.service', () => ({
    saveSsoConfig: pgSave,
    getSsoIntegrationByDomain,
  }));

  const { saveSsoConfig } = require('../src/services/SSO/saveSsoConfig.service');
  return { saveSsoConfig, extractFromPkcs12, pgSave, getSsoIntegrationByDomain };
};

// The row handed to pgSave (company_id + derived fields).
const savedRow = (pgSave) => pgSave.mock.calls[0][0];

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

  test('accepts arbitrary RMS role names as-is — not validated against zdna_roles', async () => {
    const { saveSsoConfig, pgSave } = loadService();

    // RMS roles are defined per-tenant and are not enumerable from this
    // backend — a name with no matching zdna_roles row must save fine.
    await saveSsoConfig({
      protocol: 'oidc', domains: 'rms-names.com', tenant_id: 'common',
      jit_enabled: true,
      jit_mappings: [
        { mapping_source: 'department', mapping_value: 'IT', zdna_role: 'Field Technician' },
        { mapping_source: 'default', zdna_role: 'Supervisor' },
      ],
    });

    expect(savedRow(pgSave).jit_mappings).toEqual([
      expect.objectContaining({ mapping_source: 'department', zdna_role: 'Field Technician' }),
      expect.objectContaining({ mapping_source: 'default', zdna_role: 'Supervisor' }),
    ]);
  });

  test('accepts an arbitrary Entra claim name as mapping_source (matched at login against the raw token)', async () => {
    const { saveSsoConfig, pgSave } = loadService();

    await saveSsoConfig({
      protocol: 'oidc', domains: 'custom-claim.com', tenant_id: 'common',
      jit_enabled: true,
      jit_mappings: [{ mapping_source: 'employeeType', mapping_value: 'Contractor', zdna_role: 'role-admin' }],
    });

    expect(savedRow(pgSave).jit_mappings[0]).toEqual(expect.objectContaining({
      mapping_source: 'employeetype', mapping_value: 'Contractor', zdna_role: 'role-admin',
    }));
  });

  test('rejects a missing mapping_value regardless of mapping_source', async () => {
    const { saveSsoConfig } = loadService();

    await expect(saveSsoConfig({
      protocol: 'oidc', domains: 'example.com', tenant_id: 'common',
      jit_enabled: true,
      jit_mappings: [{ mapping_source: 'department', zdna_role: 'role-admin' }],
    })).rejects.toMatchObject({ statusCode: 400, code: 'MISSING_MAPPING_VALUE' });
  });

  test('normalises mapping_source casing and honours the frontend order field as priority', async () => {
    const { saveSsoConfig, pgSave } = loadService();

    await saveSsoConfig({
      protocol: 'oidc', domains: 'ordered.com', tenant_id: 'common',
      jit_enabled: true,
      jit_mappings: [
        { mapping_source: 'Department', mapping_value: 'IT',    zdna_role: 'role-admin',   order: 5 },
        { mapping_source: 'GROUP',      mapping_value: 'grp-1', zdna_role: 'role-manager', order: 2 },
      ],
    });

    expect(savedRow(pgSave).jit_mappings).toEqual([
      expect.objectContaining({ mapping_source: 'department', zdna_role: 'role-admin',   priority: 5 }),
      expect.objectContaining({ mapping_source: 'group',      zdna_role: 'role-manager', priority: 2 }),
    ]);
  });

  test('falls back to array-position priority when order values are missing or duplicated', async () => {
    const { saveSsoConfig, pgSave } = loadService();

    await saveSsoConfig({
      protocol: 'oidc', domains: 'dup-order.com', tenant_id: 'common',
      jit_enabled: true,
      jit_mappings: [
        { mapping_source: 'group',   mapping_value: 'g1', zdna_role: 'role-admin',   order: 1 },
        { mapping_source: 'group',   mapping_value: 'g2', zdna_role: 'role-manager', order: 1 }, // duplicate
        { mapping_source: 'default', mapping_value: null, zdna_role: 'role-temporary' },            // missing
      ],
    });

    expect(savedRow(pgSave).jit_mappings.map(m => m.priority)).toEqual([1, 2, 3]);
  });

  test('uses the supplied company_id as the Postgres company_id (matches deactivate/delete keying)', async () => {
    const { saveSsoConfig, pgSave } = loadService({
      getByDomainImpl: async () => ({ company_id: 'noaq1xgCe5otm425Yhk3' }),
    });

    const result = await saveSsoConfig({
      protocol: 'oidc',
      domains: 'owner-keyed.com',
      tenant_id: 'common',
      client_id: 'client-1',
      auth_method: 'client_secret',
      company_id: 'noaq1xgCe5otm425Yhk3',
    });

    expect(savedRow(pgSave)).toEqual(expect.objectContaining({
      company_id: 'noaq1xgCe5otm425Yhk3',
    }));
    expect(result.company_id).toBe('noaq1xgCe5otm425Yhk3');
  });

  test('passes the supplied company_id through, falling back to zdna-<domain>-<ts> without one', async () => {
    const { saveSsoConfig, pgSave } = loadService({
      getByDomainImpl: async () => null,
    });

    await saveSsoConfig({
      protocol: 'oidc',
      domains: 'owner-pg.example.com',
      tenant_id: 'common',
      client_id: 'client-pg',
      auth_method: 'client_secret_post',
      company_id: 'owner-tenant-42',
    });
    expect(pgSave).toHaveBeenCalledWith(expect.objectContaining({
      company_id: 'owner-tenant-42',
    }));

    // No company_id supplied → legacy fallback keeps the PK non-null
    await saveSsoConfig({
      protocol: 'oidc',
      domains: 'no-owner.example.com',
      tenant_id: 'common',
      client_id: 'client-pg2',
      auth_method: 'client_secret_post',
    });
    expect(pgSave).toHaveBeenLastCalledWith(expect.objectContaining({
      company_id: 'zdna-no-owner-example-com-1700000000000',
    }));
  });

  test('hands OIDC fields (raw client_secret + jit rows) to the Postgres layer', async () => {
    const { saveSsoConfig, pgSave } = loadService({
      getByDomainImpl: async () => ({ company_id: 'zdna-example-com-1700000000000' }),
    });

    const result = await saveSsoConfig({
      protocol: 'oidc',
      domains: 'Example.COM',
      tenant_id: 'common',
      client_id: 'client-1',
      auth_method: 'client_secret',
      client_secret: 'super-secret',
      jit_enabled: true,
      jit_mappings: [{ mapping_source: 'default', zdna_role: 'role-manager' }],
    });

    // The service derives company_id + entra_tenant_id and passes the secret
    // through verbatim — encryption/defaults are postgresSSO.service's job.
    // domains is lowercased and carried as an array (a company may own many).
    expect(savedRow(pgSave)).toEqual(expect.objectContaining({
      company_id: 'zdna-example-com-1700000000000',
      domains: ['example.com'],
      protocol: 'oidc',
      entra_tenant_id: 'common',
      client_id: 'client-1',
      auth_method: 'client_secret',
      client_secret: 'super-secret',
      jit_enabled: true,
    }));
    expect(savedRow(pgSave).jit_mappings[0]).toEqual(expect.objectContaining({
      mapping_source: 'default',
      zdna_role: 'role-manager',
    }));
    expect(result).toEqual({
      success: true,
      company_id: 'zdna-example-com-1700000000000',
      message: 'SSO configuration saved and activated successfully',
    });
  });

  test('extracts and passes client certificate material for private_key_jwt auth', async () => {
    const { saveSsoConfig, pgSave, extractFromPkcs12 } = loadService();

    await saveSsoConfig({
      protocol: 'oidc',
      domains: 'cert.example.com',
      tenant_id: 'organizations',
      client_id: 'client-cert',
      auth_method: 'private_key_jwt',
      certificate: 'base64-p12',
      certificate_password: 'password-1',
    });

    expect(extractFromPkcs12).toHaveBeenCalledWith('base64-p12', 'password-1');
    expect(savedRow(pgSave)).toEqual(expect.objectContaining({
      private_key_b64: 'private-key-b64',
      client_cert_thumbprint: 'thumbprint-hex',
    }));
  });

  test('derives SAML tenant ids from the SSO URL', async () => {
    const { saveSsoConfig, pgSave } = loadService();

    await saveSsoConfig({
      protocol: 'saml',
      domains: 'zebra.com',
      sso_url: 'https://login.microsoftonline.com/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/saml2',
    });

    expect(savedRow(pgSave)).toEqual(expect.objectContaining({
      domains: ['zebra.com'],
      protocol: 'saml',
      entra_tenant_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      sso_url: 'https://login.microsoftonline.com/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/saml2',
    }));
  });

  test('persists via PostgreSQL and returns the stored company_id', async () => {
    const { saveSsoConfig, pgSave, getSsoIntegrationByDomain } = loadService({
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
      domains: ['pg.example.com'],
      client_secret: 'pg-secret',
    }));
    expect(getSsoIntegrationByDomain).toHaveBeenCalledWith('pg.example.com');
    expect(result.company_id).toBe('existing-company-id');
  });

  test('strips ?appid from the SAML sso_url before the Postgres save (AADSTS750054 regression)', async () => {
    const { saveSsoConfig, pgSave } = loadService({
      getByDomainImpl: async () => ({ company_id: 'saml-company-id' }),
    });

    await saveSsoConfig({
      protocol: 'saml',
      domains: 'saml-pg.example.com',
      sso_url: 'https://login.microsoftonline.com/2c761afb-5a70-452a-ab62-b98b90a6e556/saml2?appid=26ad49ad-797a-47aa-8701-d339de837a68',
    });

    expect(pgSave).toHaveBeenCalledWith(expect.objectContaining({
      // Query string must never reach the store — the login redirect appends
      // its own ?SAMLRequest=... and a second '?' breaks the Entra login.
      sso_url: 'https://login.microsoftonline.com/2c761afb-5a70-452a-ab62-b98b90a6e556/saml2',
      // Tenant derivation still works from the pre-strip URL's path
      entra_tenant_id: '2c761afb-5a70-452a-ab62-b98b90a6e556',
    }));
  });

  // The silent JSON fallback on PostgreSQL failure was removed intentionally:
  // it masked DB write failures (returned 201 while nothing persisted). The
  // error must now propagate so the caller sees the failure.
  test('propagates the error when the PostgreSQL save fails', async () => {
    const { saveSsoConfig, pgSave } = loadService({
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
  });
});
