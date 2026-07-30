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
      expect(url).toBe('https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token');
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
      tenant_id: '11111111-1111-1111-1111-111111111111',
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
          sso_url: 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/authorize',
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
      tenant_id: '22222222-2222-2222-2222-222222222222',
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

    // No tenant_id on purpose: the point under test is the sso_url's own
    // tenant-GUID extraction check, not the tenant_id format gate.
    const result = await testConnection({
      protocol: 'saml',
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

  test('blocks an SSRF attempt: a malicious sso_url host never reaches the network', async () => {
    // The tenant-extraction regex only substring-matches "login.microsoftonline.com/{guid}/",
    // so an attacker can embed that in the PATH while using an internal host. The metadata URL
    // is now rebuilt from the constant Microsoft base + the validated guid, so the attacker's
    // host is discarded rather than merely rejected — SSRF is impossible by construction.
    const guid = '12345678-1234-1234-1234-123456789abc';
    const requested = [];
    mockRequest(https, ({ url }) => {
      requested.push(url);
      return { statusCode: 200, body: '<xml/>' };
    });

    await testConnection({
      protocol: 'saml',
      tenant_id: guid,
      sso_url: `https://internal.evil/login.microsoftonline.com/${guid}/saml2`,
    });

    expect(requested).toHaveLength(1);
    expect(requested[0]).toContain(`login.microsoftonline.com/${guid}/federationmetadata`);
    expect(requested[0]).not.toContain('internal.evil');
  });

  test('preserves ?appid scoping when rebuilding the metadata URL', async () => {
    // Per-app Entra signing certs appear ONLY in the appid-scoped metadata, never
    // the tenant default — the rebuild must carry appid through or cert checks break.
    const guid  = '12345678-1234-1234-1234-123456789abc';
    const appId = 'abcdef01-2345-6789-abcd-ef0123456789';
    const requested = [];
    mockRequest(https, ({ url }) => {
      requested.push(url);
      return { statusCode: 200, body: '<xml/>' };
    });

    await testConnection({
      protocol: 'saml',
      tenant_id: guid,
      sso_url: `https://login.microsoftonline.com/${guid}/saml2?appid=${appId}`,
    });

    expect(requested[0]).toContain(`?appid=${appId}`);
  });

  test('rejects a path-traversal tenant_id before any URL is built (S7044)', async () => {
    // tenant_id is interpolated into Microsoft URL paths (tokenUrl/discoveryUrl/
    // authorizeUrl). "common/../x" passes a truthiness check but would steer the
    // request path anywhere on the allowlisted host — the format gate must stop
    // it before any network call.
    const httpsSpy = mockRequest(https, () => ({ statusCode: 200, body: '{}' }));

    const result = await testConnection({
      protocol: 'oidc',
      auth_method: 'none',
      tenant_id: 'common/../../evil-endpoint',
      client_id: 'client-1',
    });

    expect(result).toEqual({
      success: false,
      message: 'tenant_id must be a valid UUID or common/consumers/organizations',
    });
    expect(httpsSpy).not.toHaveBeenCalled();
  });

  test('accepts the documented tenant aliases and GUIDs', async () => {
    mockRequest(https, () => ({ statusCode: 200, body: '{"issuer":"https://login.microsoftonline.com/x/v2.0"}' }));

    for (const tenant of ['common', 'consumers', 'organizations', '12345678-1234-1234-1234-123456789abc']) {
      const result = await testConnection({ protocol: 'oidc', auth_method: 'none', tenant_id: tenant, client_id: 'c' });
      expect(result.success).toBe(true);
    }
  });
});
