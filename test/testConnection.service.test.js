jest.mock('../src/utils/oidc/pkcs12.util', () => ({
  extractFromPkcs12: jest.fn(() => ({
    privateKeyB64: 'private-key-b64',
    thumbprintHex: 'thumbprint-hex',
  })),
}));

// The service reads the DB through these models and the Postgres layer. Mocking them keeps
// sequelize (and config/db, which opens a live connection) out of this suite.
jest.mock('../src/models/ssoIntegration.model', () => ({ findOne: jest.fn(), findByPk: jest.fn() }));
jest.mock('../src/models/oidcConfig.model', () => ({ findOne: jest.fn() }));
jest.mock('../src/models/samlConfig.model', () => ({ findOne: jest.fn() }));
jest.mock('../src/services/db/postgresSSO.service', () => ({
  getSamlConfig: jest.fn(),
  getOidcConfig: jest.fn(),
}));

jest.mock('../src/utils/crypto.util', () => ({
  resolveSecret: jest.fn((value) => (value ? `plain:${value}` : value)),
}));

jest.mock('../src/utils/shared/testConnectionStore', () => ({ set: jest.fn() }));

jest.mock('../src/services/Saml/samlAuthRequest.service', () => ({
  buildSamlRedirectUrl: jest.fn(),
}));

jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/config/constants', () => ({
  microsoft: {
    tokenUrl: (tenantId) => `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    discoveryUrl: (tenantId) => `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`,
    samlMetadataUrl: (tenantId) => `https://login.microsoftonline.com/${tenantId}/federationmetadata/2007-06/federationmetadata.xml`,
    authorizeUrl: (tenantId) => `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
    graphScope: 'https://graph.microsoft.com/.default',
    graphBase: 'https://graph.microsoft.com',
    // SSRF allowlist (mirrors the real config) — fetchJson checks scheme + host before every request.
    allowedHosts: ['login.microsoftonline.com', 'graph.microsoft.com', 'sts.windows.net'],
  },
  defaults: {
    SAML_ENTITY_ID: 'https://sso.example.com/auth/metadata2',
    SAML_ACS_URL: 'https://sso.example.com/auth/callback',
  },
}));

const { EventEmitter } = require('node:events');
const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const { extractFromPkcs12 } = require('../src/utils/oidc/pkcs12.util');
const ssoIntegration = require('../src/models/ssoIntegration.model');
const OidcConfiguration = require('../src/models/oidcConfig.model');
const SamlConfiguration = require('../src/models/samlConfig.model');
const { getSamlConfig, getOidcConfig } = require('../src/services/db/postgresSSO.service');
const tcStore = require('../src/utils/shared/testConnectionStore');
const { buildSamlRedirectUrl } = require('../src/services/Saml/samlAuthRequest.service');
const { logger } = require('../src/config/logger');
const { testConnection, validateSsoConfiguration } = require('../src/services/SSO/testConnection.service');

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

const TENANT = '11111111-1111-1111-1111-111111111111';
const OTHER_TENANT = '22222222-2222-2222-2222-222222222222';
const APP = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const SSO_URL = `https://login.microsoftonline.com/${TENANT}/saml2`;
const APP_SSO_URL = `${SSO_URL}?appid=${APP}`;
const RAW_CERT = 'MIIBCERTAAA';

// Azure federation metadata carrying the tenant entityID and its signing certs.
const metadataXml = ({ tenant = TENANT, certs = [RAW_CERT] } = {}) =>
  `<EntityDescriptor entityID="https://sts.windows.net/${tenant}/">` +
  certs.map((c) => `<KeyDescriptor use="signing"><X509Certificate>${c}</X509Certificate></KeyDescriptor>`).join('') +
  '</EntityDescriptor>';

// The console uploads the IdP cert as base64(PEM).
const uploadedCert = (raw = RAW_CERT) =>
  Buffer.from(`-----BEGIN CERTIFICATE-----\n${raw}\n-----END CERTIFICATE-----`, 'utf8').toString('base64');

// Routes the one outbound SAML call: the federation metadata.
const samlResponder = ({
  metadata = { statusCode: 200, body: metadataXml() },
} = {}) => ({ url }) => {
  if (url.includes('federationmetadata')) return metadata;
  throw new Error(`unexpected request ${url}`);
};

const samlPayload = (overrides = {}) => ({
  protocol: 'saml',
  sso_url: SSO_URL,
  certificate: uploadedCert(),
  ...overrides,
});

describe('testConnection.service', () => {
  const originalRedirect = process.env.OIDC_REDIRECT_URI;

  beforeEach(() => {
    jest.clearAllMocks();
    ssoIntegration.findOne.mockResolvedValue(null);
    buildSamlRedirectUrl.mockResolvedValue('https://login.microsoftonline.com/t/saml2?SAMLRequest=abc');
    process.env.OIDC_REDIRECT_URI = 'http://localhost:3000/auth/oidc/callback';
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(() => {
    process.env.OIDC_REDIRECT_URI = originalRedirect;
  });

  // ── OIDC ──────────────────────────────────────────────────────────────────

  describe('OIDC', () => {
    test('verifies client_secret_post credentials and returns an OIDC test session', async () => {
      jest.spyOn(crypto, 'randomUUID')
        .mockReturnValueOnce('session-ref')
        .mockReturnValueOnce('state-1')
        .mockReturnValueOnce('nonce-1');

      const httpsSpy = mockRequest(https, ({ url, body, options }) => {
        expect(url).toBe(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`);
        expect(options.method).toBe('POST');
        expect(body).toContain('grant_type=client_credentials');
        expect(body).toContain('client_id=client-1');
        expect(body).toContain('client_secret=secret-1');
        return { statusCode: 200, body: JSON.stringify({ access_token: 'access-token' }) };
      });

      const result = await testConnection({
        protocol: 'oidc',
        auth_method: 'client_secret_post',
        tenant_id: TENANT,
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
            sso_url: `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/authorize`,
            redirect_uri: 'http://localhost:3000/auth/oidc/callback',
            state: 'state-1',
            nonce: 'nonce-1',
          }),
          _internal: expect.objectContaining({ client_secret: 'secret-1', code_verifier: null }),
        }),
      }));
      expect(result.data.config.code_challenge).toBeUndefined();
    });

    test('builds a PKCE session after discovery succeeds', async () => {
      mockRequest(https, ({ url }) => {
        expect(url).toBe('https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration');
        return { statusCode: 200, body: JSON.stringify({ issuer: 'https://login.microsoftonline.com/common/v2.0' }) };
      });

      const result = await testConnection({ protocol: 'oidc', auth_method: 'none', tenant_id: 'common', client_id: 'client-pkce' });

      expect(result.success).toBe(true);
      expect(result.message).toBe('Tenant reachable — PKCE flow ready');
      expect(result.data.config).toEqual(expect.objectContaining({
        client_id: 'client-pkce',
        code_challenge: expect.any(String),
        code_challenge_method: 'S256',
      }));
      expect(result.data._internal.code_verifier).toBeTruthy();
    });

    test('fails when the discovery endpoint is unreachable', async () => {
      mockRequest(https, () => ({ statusCode: 404, body: '{}' }));

      const result = await testConnection({ protocol: 'oidc', auth_method: 'none', tenant_id: 'common', client_id: 'c' });

      expect(result).toEqual({ success: false, message: 'Tenant not found or unreachable' });
    });

    test('extracts certificate material for private_key_jwt sessions', async () => {
      mockRequest(https, () => ({ statusCode: 200, body: JSON.stringify({ issuer: 'x' }) }));

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

    test('reuses the saved private key and thumbprint when use_existing_cert is set', async () => {
      mockRequest(https, () => ({ statusCode: 200, body: JSON.stringify({ issuer: 'x' }) }));
      getOidcConfig.mockResolvedValue({ client_cert_enc: 'saved-key', client_cert_thumbprint: 'saved-thumb' });

      const result = await testConnection({
        protocol: 'oidc',
        auth_method: 'private_key_jwt',
        tenant_id: TENANT,
        client_id: 'client-cert',
        use_existing_cert: true,
        company_id: 'company-1',
      });

      expect(getOidcConfig).toHaveBeenCalledWith('company-1');
      expect(extractFromPkcs12).not.toHaveBeenCalled();
      expect(result.data._internal).toEqual(expect.objectContaining({
        private_key_b64: 'saved-key',
        client_cert_thumbprint: 'saved-thumb',
      }));
    });

    test('returns a friendly auth failure when Entra rejects client credentials', async () => {
      mockRequest(https, () => ({
        statusCode: 401,
        body: JSON.stringify({ error: 'invalid_client', error_description: 'Bad credentials\r\ntrace-id' }),
      }));

      const result = await testConnection({
        protocol: 'oidc',
        auth_method: 'client_secret_post',
        tenant_id: TENANT,
        client_id: 'client-2',
        client_secret: 'bad-secret',
      });

      expect(result).toEqual({ success: false, message: 'invalid_client: Bad credentials' });
    });
  });

  // ── Tenant checks ─────────────────────────────────────────────────────────

  describe('tenant checks', () => {
    test('rejects a path-traversal tenant_id before any URL is built (S7044)', async () => {
      const httpsSpy = mockRequest(https, () => ({ statusCode: 200, body: '{}' }));

      const result = await testConnection({ protocol: 'oidc', auth_method: 'none', tenant_id: 'common/../x', client_id: 'c' });

      expect(result).toEqual({ success: false, message: 'tenant_id must be a valid UUID or common/consumers/organizations' });
      expect(httpsSpy).not.toHaveBeenCalled();
    });

    test.each(['common', 'consumers', 'organizations', TENANT])('accepts the tenant value %s', async (tenant_id) => {
      mockRequest(https, () => ({ statusCode: 200, body: JSON.stringify({ issuer: 'x' }) }));

      const result = await testConnection({ protocol: 'oidc', auth_method: 'none', tenant_id, client_id: 'c' });

      expect(result.success).toBe(true);
    });

    test('rejects a tenant already registered by another organization', async () => {
      ssoIntegration.findOne.mockResolvedValue({ dataValues: { company_id: 'other-company' } });
      const httpsSpy = mockRequest(https, () => ({ statusCode: 200, body: '{}' }));

      const result = await testConnection({ protocol: 'oidc', tenant_id: TENANT, company_id: 'company-1', client_id: 'c' });

      expect(ssoIntegration.findOne).toHaveBeenCalledWith({ where: { entra_tenant_id: TENANT } });
      expect(result).toEqual({
        success: false,
        message: 'This Microsoft Entra tenant ID is already registered by another organization.',
      });
      expect(httpsSpy).not.toHaveBeenCalled();
    });

    test('allows the tenant when it belongs to the same company', async () => {
      ssoIntegration.findOne.mockResolvedValue({ company_id: ' company-1 ' });
      mockRequest(https, () => ({ statusCode: 200, body: JSON.stringify({ issuer: 'x' }) }));

      const result = await testConnection({ protocol: 'oidc', auth_method: 'none', tenant_id: TENANT, company_id: 'company-1', client_id: 'c' });

      expect(result.success).toBe(true);
    });

    test('returns a generic error when the ownership lookup fails', async () => {
      ssoIntegration.findOne.mockRejectedValue(new Error('db down'));

      const result = await testConnection({ protocol: 'oidc', tenant_id: TENANT, company_id: 'company-1' });

      expect(result).toEqual({
        success: false,
        message: 'Internal server error occurred while verifying tenant configuration.',
      });
    });

    test('returns failure for unknown protocols', async () => {
      const result = await testConnection({ protocol: 'ldap' });

      expect(result).toEqual({ success: false, message: 'Unknown protocol' });
    });
  });

  // ── SAML discovery ────────────────────────────────────────────────────────

  describe('SAML discovery', () => {
    test('rejects an SSO URL without a GUID tenant before any request', async () => {
      const httpsSpy = mockRequest(https, () => ({ statusCode: 200, body: '{}' }));

      const result = await testConnection(samlPayload({ sso_url: 'https://login.microsoftonline.com/not-a-guid/saml2' }));

      expect(result.success).toBe(false);
      expect(result.message).toMatch(/Could not extract tenant ID from SSO URL/);
      expect(httpsSpy).not.toHaveBeenCalled();
    });

    test('blocks an SSRF attempt: a non-Microsoft SSO host never reaches the network', async () => {
      const httpsSpy = mockRequest(https, () => ({ statusCode: 200, body: '{}' }));
      const httpSpy = jest.spyOn(http, 'request');

      const result = await testConnection(samlPayload({ sso_url: `https://evil.example.com/${TENANT}/saml2` }));

      expect(result.success).toBe(false);
      expect(httpsSpy).not.toHaveBeenCalled();
      expect(httpSpy).not.toHaveBeenCalled();
    });

    test('takes ?appid for the metadata URL from the SSO URL', async () => {
      const urls = [];
      mockRequest(https, (args) => { urls.push(args.url); return samlResponder()(args); });

      await testConnection(samlPayload({ sso_url: APP_SSO_URL }));

      expect(urls[0]).toBe(
        `https://login.microsoftonline.com/${TENANT}/federationmetadata/2007-06/federationmetadata.xml?appid=${APP}`,
      );
    });

    test('fetches the tenant metadata when the SSO URL has no appid', async () => {
      const urls = [];
      mockRequest(https, (args) => { urls.push(args.url); return samlResponder()(args); });

      await testConnection(samlPayload());

      expect(urls[0]).toBe(
        `https://login.microsoftonline.com/${TENANT}/federationmetadata/2007-06/federationmetadata.xml`,
      );
    });

    test('fails when the metadata endpoint is unreachable', async () => {
      mockRequest(https, samlResponder({ metadata: { statusCode: 500, body: 'oops' } }));

      const result = await testConnection(samlPayload());

      expect(result).toEqual({ success: false, message: 'Tenant not found or unreachable' });
    });

    test('fails when the metadata tenant differs from the SSO URL tenant', async () => {
      mockRequest(https, samlResponder({ metadata: { statusCode: 200, body: metadataXml({ tenant: OTHER_TENANT }) } }));

      const result = await testConnection(samlPayload());

      expect(result).toEqual({
        success: false,
        message: `SSO URL tenant does not match metadata tenant. Expected ${TENANT}, got ${OTHER_TENANT}`,
      });
    });

    test('fails when no IdP certificate is supplied', async () => {
      mockRequest(https, samlResponder());

      const result = await testConnection(samlPayload({ certificate: undefined }));

      expect(result).toEqual({ success: false, message: 'Certificate not provided for validation.' });
    });

    test('fails when the metadata carries no signing certificate', async () => {
      mockRequest(https, samlResponder({ metadata: { statusCode: 200, body: metadataXml({ certs: [] }) } }));

      const result = await testConnection(samlPayload({ sso_url: APP_SSO_URL }));

      expect(result).toEqual({ success: false, message: 'Could not extract signing certificate from Azure metadata' });
    });

    test('fails when the uploaded certificate does not match the metadata', async () => {
      mockRequest(https, samlResponder());

      const result = await testConnection(samlPayload({ sso_url: APP_SSO_URL, certificate: uploadedCert('MIIBOTHER') }));

      expect(result).toEqual({ success: false, message: 'Certificate does not match Azure tenant signing certificate' });
    });

    test('matches the uploaded certificate against any of the metadata signing certs', async () => {
      mockRequest(https, samlResponder({ metadata: { statusCode: 200, body: metadataXml({ certs: ['MIIBFIRST', RAW_CERT] }) } }));

      const result = await testConnection(samlPayload({ sso_url: APP_SSO_URL }));

      expect(result.success).toBe(true);
    });

    test('leaves the certificate to the popup when the SSO URL has no appid', async () => {
      mockRequest(https, samlResponder({ metadata: { statusCode: 200, body: metadataXml({ certs: ['MIIBTENANTONLY'] }) } }));

      const result = await testConnection(samlPayload());

      expect(result).toMatchObject({ success: true, message: 'Connection successful — SAML IdP metadata reachable' });
    });

    test('reports a verified certificate when the SSO URL has an appid', async () => {
      mockRequest(https, samlResponder());

      const result = await testConnection(samlPayload({ sso_url: APP_SSO_URL }));

      expect(result).toMatchObject({ success: true, message: 'Connection successful — SAML IdP metadata reachable and certificate verified' });
    });

    describe('signing certificate', () => {
      test('rejects an unreadable signing certificate before any request', async () => {
        extractFromPkcs12.mockRejectedValueOnce(new Error('bad pfx'));
        const httpsSpy = mockRequest(https, samlResponder());

        const result = await testConnection(samlPayload({
          sign_authn_request: true, signing_certificate: 'pfx', signing_certificate_password: 'wrong',
        }));

        expect(result).toEqual({ success: false, message: 'Invalid signing certificate or certificate password.' });
        expect(httpsSpy).not.toHaveBeenCalled();
      });

      test('skips the signing check when AuthnRequest signing is off', async () => {
        mockRequest(https, samlResponder());

        await testConnection(samlPayload({ sign_authn_request: false, signing_certificate: 'pfx' }));

        expect(extractFromPkcs12).not.toHaveBeenCalled();
      });

      test('loads the saved signing key when use_existing_signing_cert is set', async () => {
        mockRequest(https, samlResponder());
        getSamlConfig.mockResolvedValue({ sp_private_key_enc: 'saved-sp-key' });

        const result = await testConnection(samlPayload({
          company_id: 'company-1', sign_authn_request: true, use_existing_signing_cert: true,
        }));

        expect(getSamlConfig).toHaveBeenCalledWith('company-1');
        expect(extractFromPkcs12).not.toHaveBeenCalled();
        expect(result.success).toBe(true);
      });
    });
  });

  // ── SAML Test Connection popup ────────────────────────────────────────────

  describe('SAML Test Connection popup', () => {
    test('returns the popup session once every check passes', async () => {
      mockRequest(https, samlResponder());
      jest.spyOn(crypto, 'randomUUID').mockReturnValueOnce('saml-ref');

      const result = await testConnection(samlPayload());

      expect(result).toEqual({
        success: true,
        message: 'Connection successful — SAML IdP metadata reachable',
        data: {
          protocol: 'saml',
          sessionRef: 'saml-ref',
          redirectUrl: 'https://login.microsoftonline.com/t/saml2?SAMLRequest=abc',
        },
      });
    });

    test('builds a forced-login AuthnRequest marked as a test of the unsaved config', async () => {
      mockRequest(https, samlResponder());
      jest.spyOn(crypto, 'randomUUID').mockReturnValueOnce('saml-ref');
      const certificate = uploadedCert();

      await testConnection(samlPayload({ certificate }));

      expect(buildSamlRedirectUrl).toHaveBeenCalledWith(
        'https://sso.example.com/auth/metadata2',
        'https://sso.example.com/auth/callback',
        SSO_URL,
        {},
        'saml-ref',
        undefined,
        {
          forceAuthn: true,
          testContext: {
            sessionRef: 'saml-ref',
            certificate,
            sso_url: SSO_URL,
            entity_id: 'https://sso.example.com/auth/metadata2',
            acs_url: 'https://sso.example.com/auth/callback',
          },
        },
      );
    });

    test('opens no popup when discovery fails', async () => {
      mockRequest(https, samlResponder({ metadata: { statusCode: 500, body: '' } }));

      const result = await testConnection(samlPayload());

      expect(result.data).toBeUndefined();
      expect(buildSamlRedirectUrl).not.toHaveBeenCalled();
    });

    test('opens no popup without an SSO URL (tenant_id only)', async () => {
      const httpsSpy = mockRequest(https, samlResponder());

      await testConnection(samlPayload({ sso_url: undefined, tenant_id: TENANT }));

      expect(httpsSpy).toHaveBeenCalled();
      expect(buildSamlRedirectUrl).not.toHaveBeenCalled();
    });

    test('keeps the passing discovery result when building the popup fails', async () => {
      mockRequest(https, samlResponder());
      buildSamlRedirectUrl.mockRejectedValue(new Error('deflate failed'));

      const result = await testConnection(samlPayload());

      expect(result).toEqual({
        success: true,
        message: 'Connection successful — SAML IdP metadata reachable',
      });
      expect(logger.warn).toHaveBeenCalledWith('[SAML_TEST_SESSION_FAILED]', { error: 'deflate failed' });
    });
  });

  // ── validateSsoConfiguration (saved config) ───────────────────────────────

  describe('validateSsoConfiguration', () => {
    test('throws 404 SSO_CONFIGURATION_NOT_FOUND when the company has no integration', async () => {
      ssoIntegration.findByPk.mockResolvedValue(null);

      await expect(validateSsoConfiguration('company-1')).rejects.toMatchObject({
        statusCode: 404,
        code: 'SSO_CONFIGURATION_NOT_FOUND',
      });
    });

    test('tests a saved OIDC config and keeps its secrets server-side in tcStore', async () => {
      ssoIntegration.findByPk.mockResolvedValue({ protocol: 'oidc', entra_tenant_id: TENANT });
      OidcConfiguration.findOne.mockResolvedValue({
        client_id: 'client-1',
        client_auth_method: 'client_secret_post',
        client_secret_enc: 'enc-secret',
        scope: 'openid',
        redirect_uri: 'https://app/cb',
      });
      jest.spyOn(crypto, 'randomUUID').mockReturnValueOnce('saved-ref');
      mockRequest(https, ({ body }) => {
        expect(body).toContain('client_secret=plain%3Aenc-secret');
        return { statusCode: 200, body: JSON.stringify({ access_token: 't' }) };
      });

      const result = await validateSsoConfiguration('company-1');

      expect(OidcConfiguration.findOne).toHaveBeenCalledWith({ where: { company_id: 'company-1' } });
      expect(tcStore.set).toHaveBeenCalledWith('saved-ref', expect.objectContaining({ client_secret: 'plain:enc-secret' }));
      expect(result).toEqual(expect.objectContaining({
        success: true,
        data: expect.objectContaining({ protocol: 'oidc', sessionRef: 'saved-ref', client_auth_method: 'client_secret_post' }),
      }));
    });

    test('runs SAML discovery and opens a popup for a saved SAML config', async () => {
      ssoIntegration.findByPk.mockResolvedValue({ protocol: 'saml', entra_tenant_id: TENANT });
      SamlConfiguration.findOne.mockResolvedValue({
        sso_url: SSO_URL,
        certificate: 'stored-cert',
      });
      const resolveSecret = require('../src/utils/crypto.util').resolveSecret;
      resolveSecret.mockImplementation((v) => (v === 'stored-cert' ? uploadedCert() : `plain:${v}`));
      mockRequest(https, samlResponder());

      const result = await validateSsoConfiguration('company-1');

      expect(result).toEqual({
        success: true,
        message: 'Connection successful — SAML IdP metadata reachable',
        data: {
          protocol: 'saml',
          sessionRef: expect.any(String),
          redirectUrl: 'https://login.microsoftonline.com/t/saml2?SAMLRequest=abc',
        },
      });
      expect(buildSamlRedirectUrl).toHaveBeenCalledWith(
        expect.any(String), expect.any(String), SSO_URL, {}, result.data.sessionRef, undefined,
        expect.objectContaining({ forceAuthn: true }),
      );
      resolveSecret.mockImplementation((value) => (value ? `plain:${value}` : value));
    });

    test('opens no popup when the saved SAML config fails discovery', async () => {
      ssoIntegration.findByPk.mockResolvedValue({ protocol: 'saml', entra_tenant_id: TENANT });
      SamlConfiguration.findOne.mockResolvedValue({ sso_url: SSO_URL, certificate: 'stored-cert' });
      mockRequest(https, samlResponder({ metadata: { statusCode: 500, body: 'oops' } }));

      const result = await validateSsoConfiguration('company-1');

      expect(result).toEqual({ success: false, message: 'Tenant not found or unreachable' });
      expect(buildSamlRedirectUrl).not.toHaveBeenCalled();
    });

    test('treats an unsupported saved protocol as not found', async () => {
      ssoIntegration.findByPk.mockResolvedValue({ protocol: 'ldap' });

      await expect(validateSsoConfiguration('company-1')).rejects.toMatchObject({ code: 'SSO_CONFIGURATION_NOT_FOUND' });
    });
  });
});
