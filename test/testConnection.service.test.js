jest.mock('../src/utils/oidc/pkcs12.util', () => ({
  extractFromPkcs12: jest.fn(() => ({
    privateKeyB64: 'private-key-b64',
    thumbprintHex: 'thumbprint-hex',
  })),
}));

jest.mock('../src/config/constants', () => ({
  microsoft: {
    tokenUrl: (tenantId) => `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    discoveryUrl: (tenantId) => `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`,
    samlMetadataUrl: (tenantId) => `https://login.microsoftonline.com/${tenantId}/federationmetadata/2007-06/federationmetadata.xml`,
    authorizeUrl: (tenantId) => `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
    graphScope: 'https://graph.microsoft.com/.default',
    // SSRF guard (mirrors the real config) — fetchJson calls this before every request.
    isAllowedUrl: (rawUrl) => {
      try {
        const u = new URL(rawUrl);
        return u.protocol === 'https:'
          && ['login.microsoftonline.com', 'graph.microsoft.com', 'sts.windows.net'].includes(u.hostname);
      } catch { return false; }
    },
  },
}));

const { EventEmitter } = require('node:events');
const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const { extractFromPkcs12 } = require('../src/utils/oidc/pkcs12.util');
const { testConnection } = require('../src/services/SSO/testConnection.service');

const mockRequest = (moduleRef, responder) => jest.spyOn(moduleRef, 'request').mockImplementation((url, options, callback) => {
  const req = new EventEmitter();
  let body = '';
  req.write = jest.fn((chunk) => { body += chunk; });
  req.end = jest.fn(() => {
    const res = new EventEmitter();
    const response = responder({ url: String(url), options, body, req });

    if (response.error) {
      process.nextTick(() => req.emit('error', response.error));
      return;
    }

    res.statusCode = response.statusCode;
    callback(res);
    process.nextTick(() => {
      if (response.body !== undefined) res.emit('data', response.body);
      res.emit('end');
    });
  });
  req.destroy = jest.fn();
  return req;
});

describe('testConnection.service', () => {
  const originalRedirect = process.env.OIDC_REDIRECT_URI;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.OIDC_REDIRECT_URI = 'http://localhost:3000/auth/oidc/callback';
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(() => {
    process.env.OIDC_REDIRECT_URI = originalRedirect;
  });

  test('verifies client_secret_post credentials and returns an OIDC test session', async () => {
    jest.spyOn(crypto, 'randomUUID')
      .mockReturnValueOnce('session-ref')
      .mockReturnValueOnce('state-1')
      .mockReturnValueOnce('nonce-1');
    jest.spyOn(crypto, 'randomBytes').mockReturnValue(Buffer.from('code-verifier-seed'));

    const httpsSpy = mockRequest(https, ({ url, body }) => {
      expect(url).toBe('https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token');
      expect(body).toContain('grant_type=client_credentials');
      expect(body).toContain('client_id=client-1');
      expect(body).toContain('client_secret=secret-1');
      return {
        statusCode: 200,
        body: JSON.stringify({ access_token: 'access-token' }),
      };
    });

    const result = await testConnection({
      protocol: 'oidc',
      auth_method: 'client_secret_post',
      tenant_id: 'tenant-1',
      client_id: 'client-1',
      client_secret: 'secret-1',
      scope: 'openid profile email',
    });

    expect(httpsSpy).toHaveBeenCalled();
    expect(result).toEqual(expect.objectContaining({
      success: true,
      message: 'Connection successful — credentials verified with Microsoft Entra',
      data: expect.objectContaining({
        protocol: 'oidc',
        client_auth_method: 'client_secret_post',
        sessionRef: 'session-ref',
        config: expect.objectContaining({
          client_id: 'client-1',
          sso_url: 'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/authorize',
          redirect_uri: 'http://localhost:3000/auth/oidc/callback',
          state: 'state-1',
          nonce: 'nonce-1',
        }),
        _internal: expect.objectContaining({
          client_secret: 'secret-1',
          code_verifier: null,
        }),
      }),
    }));
    expect(result.data.config.code_challenge).toBeUndefined();
  });

  test('builds a PKCE session after discovery succeeds', async () => {
    jest.spyOn(crypto, 'randomUUID')
      .mockReturnValueOnce('session-pkce')
      .mockReturnValueOnce('state-pkce')
      .mockReturnValueOnce('nonce-pkce');
    jest.spyOn(crypto, 'randomBytes').mockReturnValue(Buffer.from('pkce-seed'));

    mockRequest(https, ({ url }) => {
      expect(url).toBe('https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration');
      return {
        statusCode: 200,
        body: JSON.stringify({ issuer: 'https://login.microsoftonline.com/common/v2.0' }),
      };
    });

    const result = await testConnection({
      protocol: 'oidc',
      auth_method: 'none',
      tenant_id: 'common',
      client_id: 'client-pkce',
    });

    expect(result.success).toBe(true);
    expect(result.data.config).toEqual(expect.objectContaining({
      client_id: 'client-pkce',
      code_challenge: expect.any(String),
      code_challenge_method: 'S256',
      state: 'state-pkce',
      nonce: 'nonce-pkce',
    }));
    expect(result.data._internal.code_verifier).toBeTruthy();
  });

  test('extracts certificate material for private_key_jwt sessions', async () => {
    jest.spyOn(crypto, 'randomUUID')
      .mockReturnValueOnce('session-cert')
      .mockReturnValueOnce('state-cert')
      .mockReturnValueOnce('nonce-cert');
    jest.spyOn(crypto, 'randomBytes').mockReturnValue(Buffer.from('cert-seed'));

    mockRequest(https, () => ({
      statusCode: 200,
      body: JSON.stringify({ issuer: 'https://login.microsoftonline.com/organizations/v2.0' }),
    }));

    const result = await testConnection({
      protocol: 'oidc',
      auth_method: 'private_key_jwt',
      tenant_id: 'organizations',
      client_id: 'client-cert',
      certificate: 'base64-p12',
      certificate_password: 'pw-1',
    });

    expect(extractFromPkcs12).toHaveBeenCalledWith('base64-p12', 'pw-1');
    expect(result.data._internal).toEqual(expect.objectContaining({
      private_key_b64: 'private-key-b64',
      client_cert_thumbprint: 'thumbprint-hex',
    }));
  });

  test('returns a friendly auth failure when Entra rejects client credentials', async () => {
    mockRequest(https, () => ({
      statusCode: 401,
      body: JSON.stringify({
        error: 'invalid_client',
        error_description: 'Bad credentials\r\ntrace-id',
      }),
    }));

    const result = await testConnection({
      protocol: 'oidc',
      auth_method: 'client_secret_post',
      tenant_id: 'tenant-2',
      client_id: 'client-2',
      client_secret: 'bad-secret',
    });

    expect(result).toEqual({
      success: false,
      message: 'invalid_client: Bad credentials',
    });
  });

  // Azure tenant/app IDs are 36-char GUIDs; the service validates this before
  // fetching metadata, so tests must use real GUID shapes.
  const TENANT_GUID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  const APP_GUID    = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

  // Builds a metadata XML doc carrying the tenant entityID and (optionally) a
  // signing cert, mirroring Azure federation metadata.
  const buildMetadataXml = (rawCert) =>
    `<EntityDescriptor entityID="https://sts.windows.net/${TENANT_GUID}/">` +
    (rawCert ? `<KeyDescriptor use="signing"><X509Certificate>${rawCert}</X509Certificate></KeyDescriptor>` : '') +
    `</EntityDescriptor>`;

  // Frontend uploads the cert as base64(PEM); reproduce that encoding here.
  const encodeUploadedCert = (rawCert) =>
    Buffer.from(`-----BEGIN CERTIFICATE-----\n${rawCert}\n-----END CERTIFICATE-----`, 'utf8').toString('base64');

  test('checks SAML metadata using the derived federation metadata URL', async () => {
    mockRequest(https, ({ url }) => {
      expect(url).toBe(`https://login.microsoftonline.com/${TENANT_GUID}/federationmetadata/2007-06/federationmetadata.xml`);
      return { statusCode: 200, body: buildMetadataXml() };
    });

    const result = await testConnection({
      protocol: 'saml',
      tenant_id: TENANT_GUID,
      sso_url: `https://login.microsoftonline.com/${TENANT_GUID}/saml2`,
    });

    expect(result).toEqual({
      success: true,
      message: 'Connection successful — SAML IdP metadata reachable and certificate verified',
    });
  });

  test('forwards ?appid= to the metadata fetch so per-app signing certs are verified', async () => {
    const rawCert = 'MIIBExampleAppScopedCert0000000000000000';
    let fetchedUrl;
    mockRequest(https, ({ url }) => {
      fetchedUrl = url;
      return { statusCode: 200, body: buildMetadataXml(rawCert) };
    });

    const result = await testConnection({
      protocol: 'saml',
      tenant_id: TENANT_GUID,
      sso_url: `https://login.microsoftonline.com/${TENANT_GUID}/saml2?appid=${APP_GUID}`,
      certificate: encodeUploadedCert(rawCert),
    });

    // the appid query must ride along to the app-scoped federation metadata doc
    expect(fetchedUrl).toBe(
      `https://login.microsoftonline.com/${TENANT_GUID}/federationmetadata/2007-06/federationmetadata.xml?appid=${APP_GUID}`
    );
    expect(result.success).toBe(true);
  });

  test('fails when the uploaded certificate does not match the Azure metadata', async () => {
    mockRequest(https, () => ({
      statusCode: 200,
      body: buildMetadataXml('MIIBAzureSigningCert00000000000000000000'),
    }));

    const result = await testConnection({
      protocol: 'saml',
      tenant_id: TENANT_GUID,
      sso_url: `https://login.microsoftonline.com/${TENANT_GUID}/saml2`,
      certificate: encodeUploadedCert('MIIBSomeOtherCert00000000000000000000000'),
    });

    expect(result).toEqual({
      success: false,
      message: 'Certificate does not match Azure tenant signing certificate',
    });
  });

  test('rejects a SAML SSO URL whose tenant id is not a GUID before any fetch', async () => {
    const httpsSpy = mockRequest(https, () => ({ statusCode: 200, body: buildMetadataXml() }));

    const result = await testConnection({
      protocol: 'saml',
      tenant_id: 'tenant-3',
      sso_url: 'https://login.microsoftonline.com/tenant-3/saml2',
    });

    expect(result.success).toBe(false);
    expect(result.message).toMatch(/Could not extract tenant ID from SSO URL/);
    expect(httpsSpy).not.toHaveBeenCalled(); // must short-circuit, no metadata fetch
  });

  test('returns false for unknown protocols', async () => {
    expect(await testConnection({ protocol: 'ldap' })).toEqual({
      success: false,
      message: 'Unknown protocol',
    });
  });

  test('blocks an SSRF attempt: a non-Microsoft sso_url host is rejected before any fetch', async () => {
    // The tenant-extraction regex only substring-matches "login.microsoftonline.com/{guid}/",
    // so an attacker can embed that in the PATH while using an internal host. The host-based
    // SSRF guard in fetchJson must still block it.
    const guid = '12345678-1234-1234-1234-123456789abc';
    const httpsSpy = mockRequest(https, () => ({ statusCode: 200, body: '<xml/>' }));

    await expect(testConnection({
      protocol: 'saml',
      tenant_id: guid,
      sso_url: `https://internal.evil/login.microsoftonline.com/${guid}/saml2`,
    })).rejects.toMatchObject({ code: 'OUTBOUND_HOST_NOT_ALLOWED' });

    expect(httpsSpy).not.toHaveBeenCalled(); // guard rejects before the request is made
  });
});
