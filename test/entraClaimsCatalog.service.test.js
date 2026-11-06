jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

const { EventEmitter } = require('node:events');
const https = require('node:https');
const {
  getEntraClaimsCatalog,
  buildAdminConsentUrl,
  checkMappingAgainstCatalog,
  validateMappingsAgainstCatalog,
  clearCatalogCache,
} = require('../src/services/SSO/entraClaimsCatalog.service');

const TENANT = '72f988bf-86f1-41af-91ab-2d7cd011db47';
const APP_ID = '22222222-2222-2222-2222-222222222222';
const SP_ID  = '33333333-3333-3333-3333-333333333333';
const GROUP  = '11111111-1111-1111-1111-111111111111';

describe('entraClaimsCatalog.service', () => {
  let requestSpy;
  let calls;

  // Answers each outbound request by URL; records the URLs for assertions.
  const route = (handlers) => {
    calls = [];
    requestSpy.mockImplementation((url, options, callback) => {
      const href = String(url);
      calls.push({ href, options });
      const req = new EventEmitter();
      req.write = jest.fn();
      req.destroy = jest.fn();
      req.end = jest.fn(() => {
        const match = handlers.find(([pattern]) => href.includes(pattern));
        const [status, body] = match ? match[1] : [404, {}];
        const res = new EventEmitter();
        res.statusCode = status;
        callback(res);
        process.nextTick(() => {
          res.emit('data', JSON.stringify(body));
          res.emit('end');
        });
      });
      return req;
    });
  };

  const sp = {
    id: SP_ID,
    appId: APP_ID,
    appRoles: [
      { value: 'Zebra.Admin', isEnabled: true },
      { value: 'Zebra.Viewer', isEnabled: true },
      { value: 'Zebra.Old', isEnabled: false },
      { value: null, isEnabled: true },
    ],
  };

  const happyPath = [
    ['/oauth2/v2.0/token', [200, { access_token: 'connector-token' }]],
    ['/appRoleAssignedTo', [200, { value: [
      { principalId: GROUP, principalDisplayName: 'ZDNA Admins', principalType: 'Group' },
      { principalId: 'user-1', principalDisplayName: 'Some User', principalType: 'User' },
    ] }]],
    ['/applications(appId=', [200, { optionalClaims: {
      idToken: [{ name: 'employeeType' }],
      saml2Token: [{ name: 'costcenter' }],
    } }]],
    ['/beta/servicePrincipals/', [200, { claims: [
      { name: 'employeeid', namespace: 'http://schemas.zebra.com/claims' },
      { name: 'plant' },
    ] }]],
    ['servicePrincipals(appId=', [200, sp]],
    ['servicePrincipals?$filter=', [200, { value: [sp] }]],
  ];

  beforeEach(() => {
    process.env.ENTRA_CONNECTOR_CLIENT_ID = 'connector-client-id';
    process.env.ENTRA_CONNECTOR_CLIENT_SECRET = 'connector-secret';
    requestSpy = jest.spyOn(https, 'request');
    clearCatalogCache();
  });

  afterEach(() => {
    requestSpy.mockRestore();
    delete process.env.ENTRA_CONNECTOR_CLIENT_ID;
    delete process.env.ENTRA_CONNECTOR_CLIENT_SECRET;
  });

  test('builds the OIDC catalog: enabled app roles, assigned groups, optional id-token claims', async () => {
    route(happyPath);
    const catalog = await getEntraClaimsCatalog({ protocol: 'oidc', tenant_id: TENANT, client_id: APP_ID });

    expect(catalog.roles).toEqual(['Zebra.Admin', 'Zebra.Viewer']);
    expect(catalog.groups).toEqual([{ id: GROUP, name: 'ZDNA Admins' }]);
    expect(catalog.claimNames).toEqual(expect.arrayContaining(['role', 'groups', 'department', 'employeeType']));
    expect(catalog.claimNames).not.toContain('costcenter');
    expect(calls[0].href).toBe(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`);
    expect(calls.some((c) => c.href.includes(`servicePrincipals(appId='${APP_ID}')`))).toBe(true);
    expect(calls.some((c) => c.href.includes('/beta/'))).toBe(false);
  });

  test('finds a SAML app by Entity ID and adds SAML optional and custom claim names', async () => {
    route(happyPath);
    const catalog = await getEntraClaimsCatalog({
      protocol: 'saml',
      sso_url: `https://login.microsoftonline.com/${TENANT}/saml2`,
      entity_id: 'https://zdna-sso.web.app/auth/metadata2',
    });

    const filterCall = calls.find((c) => c.href.includes('servicePrincipals?$filter='));
    expect(decodeURIComponent(filterCall.href)).toContain("servicePrincipalNames/any(x:x eq 'https://zdna-sso.web.app/auth/metadata2')");
    expect(catalog.claimNames).toEqual(expect.arrayContaining([
      'costcenter', 'plant', 'http://schemas.zebra.com/claims/employeeid',
    ]));
  });

  test('uses the ?appid in a SAML SSO URL instead of the Entity ID lookup', async () => {
    route(happyPath);
    await getEntraClaimsCatalog({
      protocol: 'saml',
      sso_url: `https://login.microsoftonline.com/${TENANT}/saml2?appid=${APP_ID}`,
    });
    expect(calls.some((c) => c.href.includes(`servicePrincipals(appId='${APP_ID}')`))).toBe(true);
    expect(calls.some((c) => c.href.includes('$filter='))).toBe(false);
  });

  test('keeps the built-in names when the SAML claims policy cannot be read', async () => {
    route([['/beta/servicePrincipals/', [403, {}]], ...happyPath]);
    const catalog = await getEntraClaimsCatalog({ protocol: 'saml', sso_url: `https://login.microsoftonline.com/${TENANT}/saml2` });
    expect(catalog.claimNames).toEqual(expect.arrayContaining(['role', 'groups', 'department', 'jobtitle']));
  });

  test('follows Graph nextLinks for assigned groups', async () => {
    route([
      ['skiptoken', [200, { value: [{ principalId: 'g2', principalDisplayName: 'Two', principalType: 'Group' }] }]],
      ['/appRoleAssignedTo', [200, {
        value: [{ principalId: 'g1', principalDisplayName: 'One', principalType: 'Group' }],
        '@odata.nextLink': `https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignedTo?$skiptoken=x`,
      }]],
      ...happyPath,
    ]);
    const catalog = await getEntraClaimsCatalog({ protocol: 'oidc', tenant_id: TENANT, client_id: APP_ID });
    expect(catalog.groups.map((g) => g.id)).toEqual(['g1', 'g2']);
  });

  test('caches the catalog per tenant and app', async () => {
    route(happyPath);
    await getEntraClaimsCatalog({ protocol: 'oidc', tenant_id: TENANT, client_id: APP_ID });
    const count = calls.length;
    await getEntraClaimsCatalog({ protocol: 'oidc', tenant_id: TENANT, client_id: APP_ID });
    expect(calls.length).toBe(count);
  });

  test('reports a tenant that never consented to the connector', async () => {
    route([['/oauth2/v2.0/token', [400, { error: 'unauthorized_client' }]]]);
    await expect(getEntraClaimsCatalog({ protocol: 'oidc', tenant_id: TENANT, client_id: APP_ID }))
      .rejects.toMatchObject({ statusCode: 403, code: 'ENTRA_CONNECTOR_NOT_CONSENTED' });
  });

  test('reports missing Graph permissions as not consented', async () => {
    route([['/oauth2/v2.0/token', [200, { access_token: 't' }]], ['servicePrincipals(appId=', [403, {}]]]);
    await expect(getEntraClaimsCatalog({ protocol: 'oidc', tenant_id: TENANT, client_id: APP_ID }))
      .rejects.toMatchObject({ code: 'ENTRA_CONNECTOR_NOT_CONSENTED' });
  });

  test('reports an app that is not in the tenant', async () => {
    route([['/oauth2/v2.0/token', [200, { access_token: 't' }]], ['servicePrincipals(appId=', [404, {}]]]);
    await expect(getEntraClaimsCatalog({ protocol: 'oidc', tenant_id: TENANT, client_id: APP_ID }))
      .rejects.toMatchObject({ statusCode: 404, code: 'ENTRA_APP_NOT_FOUND' });
  });

  test('refuses to run when the connector app is not configured', async () => {
    delete process.env.ENTRA_CONNECTOR_CLIENT_SECRET;
    route(happyPath);
    await expect(getEntraClaimsCatalog({ protocol: 'oidc', tenant_id: TENANT, client_id: APP_ID }))
      .rejects.toMatchObject({ statusCode: 503, code: 'ENTRA_CONNECTOR_NOT_CONFIGURED' });
    expect(calls).toHaveLength(0);
  });

  test('rejects a tenant alias or a malformed client id before calling Microsoft', async () => {
    route(happyPath);
    await expect(getEntraClaimsCatalog({ protocol: 'oidc', tenant_id: 'common', client_id: APP_ID }))
      .rejects.toMatchObject({ code: 'INVALID_TENANT_ID' });
    await expect(getEntraClaimsCatalog({ protocol: 'oidc', tenant_id: TENANT, client_id: "x') or 1 eq 1" }))
      .rejects.toMatchObject({ code: 'INVALID_CLIENT_ID' });
    expect(calls).toHaveLength(0);
  });

  test('builds the admin consent link for the customer tenant', () => {
    const url = new URL(buildAdminConsentUrl({ protocol: 'saml', sso_url: `https://login.microsoftonline.com/${TENANT}/saml2` }));
    expect(url.origin + url.pathname).toBe(`https://login.microsoftonline.com/${TENANT}/v2.0/adminconsent`);
    expect(url.searchParams.get('client_id')).toBe('connector-client-id');
    expect(url.searchParams.get('scope')).toBe('https://graph.microsoft.com/.default');
    expect(url.searchParams.get('redirect_uri')).toMatch(/\/auth\/entra-connector\/callback$/);
  });

  describe('checkMappingAgainstCatalog', () => {
    const catalog = {
      claimNames: ['role', 'roles', 'group', 'groups', 'department', 'jobtitle', 'employeeType'],
      roles: ['Zebra.Admin'],
      groups: [{ id: GROUP, name: 'ZDNA Admins' }],
    };
    const check = (mapping_source, mapping_value) => checkMappingAgainstCatalog({ mapping_source, mapping_value }, catalog);

    test('accepts values that exist in the app, with login-style matching', () => {
      expect(check('ROLE', ' zebra.admin ')).toBeNull();
      expect(check('groups', GROUP)).toBeNull();
      expect(check('group', 'zdna admins')).toBeNull();
      expect(check('employeetype', 'Contractor')).toBeNull();
      expect(check('department', 'Any department')).toBeNull();
      expect(check('default', '')).toBeNull();
    });

    test('rejects names and values the app does not have', () => {
      expect(check('rol', 'Zebra.Admin')).toMatch(/not configured for this app/);
      expect(check('group, department', 'x')).toMatch(/not configured for this app/);
      expect(check('role', 'Zebra.Owner')).toMatch(/not an app role/);
      expect(check('group', 'aaaaaaaa-1111-1111-1111-111111111111')).toMatch(/not a group assigned/);
      expect(check('a'.repeat(31), 'x')).toMatch(/30 characters or fewer/);
    });

    test('validateMappingsAgainstCatalog throws the matching error code', () => {
      expect(() => validateMappingsAgainstCatalog([{ zdna_role: 'A', mapping_source: 'rol', mapping_value: 'x' }], catalog))
        .toThrow(expect.objectContaining({ code: 'INVALID_CLAIM_NAME', statusCode: 400 }));
      expect(() => validateMappingsAgainstCatalog([{ zdna_role: 'A', mapping_source: 'role', mapping_value: 'x' }], catalog))
        .toThrow(expect.objectContaining({ code: 'INVALID_CLAIM_VALUE' }));
    });
  });
});
