jest.mock('../src/utils/oidc/pkcs12.util', () => ({
  extractFromPkcs12: jest.fn(),
}));

jest.mock('../src/models/ssoIntegration.model', () => ({
  findOne: jest.fn(),
  findByPk: jest.fn(),
}));

jest.mock('../src/models/oidcConfig.model', () => ({
  findOne: jest.fn(),
}));

jest.mock('../src/models/samlConfig.model', () => ({
  findOne: jest.fn(),
}));

jest.mock('../src/services/db/postgresSSO.service', () => ({
  getSamlConfig: jest.fn(),
  getOidcConfig: jest.fn(),
}));

jest.mock('../src/utils/crypto.util', () => ({
  resolveSecret: jest.fn((value) => value),
  decrypt: jest.fn(),
}));

jest.mock('../src/utils/shared/testConnectionStore', () => ({
  set: jest.fn(),
  get: jest.fn(),
  delete: jest.fn(),
}));

jest.mock('../src/utils/shared/authMethod.util', () => ({
  isCertAuth: jest.fn((authMethod) =>
    ['private_key_jwt', 'certificate'].includes(authMethod)
  ),
}));

jest.mock('../src/utils/shared/maskId.util', () => ({
  maskInput: jest.fn(() => '***'),
}));

jest.mock('../src/config/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

jest.mock('../src/config/constants', () => ({
  microsoft: {
    tokenUrl: (tenantId) =>
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    discoveryUrl: (tenantId) =>
      `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`,
    samlMetadataUrl: (tenantId) =>
      `https://login.microsoftonline.com/${tenantId}/federationmetadata/2007-06/federationmetadata.xml`,
    authorizeUrl: (tenantId) =>
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
    graphBase: 'https://graph.microsoft.com',
    graphScope: 'https://graph.microsoft.com/.default',
    allowedHosts: [
      'login.microsoftonline.com',
      'graph.microsoft.com',
      'sts.windows.net',
    ],
  },
  defaults: {
    SAML_ENTITY_ID: 'https://sp.example.com/auth/metadata2',
    SAML_ACS_URL: 'https://sp.example.com/auth/callback',
  },
}));

// The SAML popup session is built by samlAuthRequest.service; stub it so these tests
// check what testConnection asks for, not the AuthnRequest encoding.
jest.mock('../src/services/Saml/samlAuthRequest.service', () => ({
  buildSamlRedirectUrl: jest.fn(),
}));

const { EventEmitter } = require('node:events');
const crypto = require('node:crypto');
const https = require('node:https');

const { extractFromPkcs12 } = require('../src/utils/oidc/pkcs12.util');
const ssoIntegration = require('../src/models/ssoIntegration.model');
const OidcConfiguration = require('../src/models/oidcConfig.model');
const SamlConfiguration = require('../src/models/samlConfig.model');
const {
  getSamlConfig,
  getOidcConfig,
} = require('../src/services/db/postgresSSO.service');
const cryptoUtil = require('../src/utils/crypto.util');
const tcStore = require('../src/utils/shared/testConnectionStore');
const { buildSamlRedirectUrl } = require('../src/services/Saml/samlAuthRequest.service');
const {
  testConnection,
  validateSsoConfiguration,
} = require('../src/services/SSO/testConnection.service');

const VALID_TENANT = '11111111-1111-1111-1111-111111111111';
const TENANT_GUID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const OTHER_TENANT_GUID = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const APP_GUID = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const RAW_CERT = 'MIIBExampleAzureSigningCertificate';
const SAML_REDIRECT = 'https://login.microsoftonline.com/tenant/saml2?SAMLRequest=abc&RelayState=_zdna_1';
const VALID_SHA1_THUMBPRINT = 'A'.repeat(40);

const buildMetadataXml = ({
  tenantId = TENANT_GUID,
  certificates = [RAW_CERT],
} = {}) => `
  <EntityDescriptor entityID="https://sts.windows.net/${tenantId}/">
    ${certificates
      .map(
        (certificate) => `
          <KeyDescriptor use="signing">
            <X509Certificate>${certificate}</X509Certificate>
          </KeyDescriptor>`
      )
      .join('')}
  </EntityDescriptor>`;

const encodeUploadedCert = (rawCertificate = RAW_CERT) =>
  Buffer.from(
    [
      '-----BEGIN CERTIFICATE-----',
      rawCertificate,
      '-----END CERTIFICATE-----',
    ].join('\n'),
    'utf8'
  ).toString('base64');

const mockRequest = (responder) =>
  jest.spyOn(https, 'request').mockImplementation((url, options, callback) => {
    const request = new EventEmitter();
    let requestBody = '';

    request.write = jest.fn((chunk) => {
      requestBody += chunk;
    });

    request.end = jest.fn(() => {
      let result;
      try {
        result = responder({
          url: String(url),
          options,
          body: requestBody,
        });
      } catch (error) {
        process.nextTick(() => request.emit('error', error));
        return;
      }

      if (result.error) {
        process.nextTick(() => request.emit('error', result.error));
        return;
      }

      const response = new EventEmitter();
      response.statusCode = result.statusCode;
      callback(response);

      process.nextTick(() => {
        if (result.body !== undefined) {
          response.emit('data', result.body);
        }
        response.emit('end');
      });
    });

    return request;
  });

const mockDiscoverySuccess = (issuer = 'https://issuer.example') =>
  mockRequest(() => ({
    statusCode: 200,
    body: JSON.stringify({ issuer }),
  }));

// SAML Test Connection only reads the federation metadata. Any other request
// (e.g. Microsoft Graph) fails the test.
const mockSamlRequests = ({
  metadataStatus = 200,
  metadataBody = buildMetadataXml(),
} = {}) =>
  mockRequest(({ url }) => {
    if (url.includes('federationmetadata')) {
      return { statusCode: metadataStatus, body: metadataBody };
    }
    throw new Error(`Unexpected URL: ${url}`);
  });

describe('testConnection.service', () => {
  const originalRedirectUri = process.env.OIDC_REDIRECT_URI;

  beforeEach(() => {
    jest.clearAllMocks();
    ssoIntegration.findOne.mockResolvedValue(null);
    extractFromPkcs12.mockResolvedValue({
      privateKeyB64: 'private-key-b64',
      thumbprintHex: VALID_SHA1_THUMBPRINT,
    });
    cryptoUtil.resolveSecret.mockImplementation((value) => value);
    buildSamlRedirectUrl.mockResolvedValue(SAML_REDIRECT);
    process.env.OIDC_REDIRECT_URI =
      'http://localhost:3000/auth/oidc/callback';
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(() => {
    process.env.OIDC_REDIRECT_URI = originalRedirectUri;
  });

  const mockDeterministicCrypto = (
    sessionRef = 'session-ref',
    state = 'state-1',
    nonce = 'nonce-1'
  ) => {
    jest
      .spyOn(crypto, 'randomUUID')
      .mockReturnValueOnce(sessionRef)
      .mockReturnValueOnce(state)
      .mockReturnValueOnce(nonce);
    jest
      .spyOn(crypto, 'randomBytes')
      .mockReturnValue(Buffer.from('code-verifier-seed'));
  };

  describe('OIDC', () => {
    test('verifies client_secret_post and does not expose internal secrets', async () => {
      mockDeterministicCrypto();
      mockRequest(({ url, body, options }) => {
        expect(url).toBe(
          `https://login.microsoftonline.com/${VALID_TENANT}/oauth2/v2.0/token`
        );
        expect(options.method).toBe('POST');
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
        tenant_id: VALID_TENANT,
        client_id: 'client-1',
        client_secret: 'secret-1',
        scope: 'openid profile email',
      });

      expect(result.success).toBe(true);
      expect(result.data.sessionRef).toBe('session-ref');
      expect(result.data).not.toHaveProperty('_internal');
      expect(JSON.stringify(result)).not.toContain('secret-1');
      expect(tcStore.set).toHaveBeenCalledWith(
        'session-ref',
        expect.objectContaining({
          client_secret: 'secret-1',
          code_verifier: null,
          private_key_b64: null,
        })
      );
    });

    test('uses fallback authentication error values when Entra response omits details', async () => {
      mockRequest(() => ({ statusCode: 401, body: '{}' }));

      await expect(
        testConnection({
          protocol: 'oidc',
          auth_method: 'client_secret_post',
          tenant_id: VALID_TENANT,
          client_id: 'client-1',
          client_secret: 'bad-secret',
        })
      ).resolves.toEqual({
        success: false,
        message: 'unknown_error: Authentication failed',
      });
    });

    test('stores PKCE verifier server-side and returns only challenge', async () => {
      mockDeterministicCrypto('session-pkce', 'state-pkce', 'nonce-pkce');
      mockDiscoverySuccess();

      const result = await testConnection({
        protocol: 'oidc',
        auth_method: 'none',
        tenant_id: 'common',
        client_id: 'client-pkce',
      });

      expect(result.success).toBe(true);
      expect(result.data.config).toEqual(
        expect.objectContaining({
          code_challenge: expect.any(String),
          code_challenge_method: 'S256',
          scope: 'openid profile email',
          state: 'state-pkce',
          nonce: 'nonce-pkce',
        })
      );
      expect(tcStore.set).toHaveBeenCalledWith(
        'session-pkce',
        expect.objectContaining({ code_verifier: expect.any(String) })
      );
    });

    test('returns discovery failure without creating a session', async () => {
      mockRequest(() => ({ statusCode: 404, body: '{}' }));

      const result = await testConnection({
        protocol: 'oidc',
        auth_method: 'none',
        tenant_id: 'common',
        client_id: 'client-1',
      });

      expect(result).toEqual({
        success: false,
        message: 'Tenant not found or unreachable',
      });
      expect(tcStore.set).not.toHaveBeenCalled();
    });

 
    test('requires a certificate for private_key_jwt', async () => {
      mockDiscoverySuccess();

      await expect(
        testConnection({
          protocol: 'oidc',
          auth_method: 'private_key_jwt',
          tenant_id: TENANT_GUID,
          client_id: 'client-1',
        })
      ).rejects.toMatchObject({
        code: 'SSO_CERTIFICATE_REQUIRED',
        statusCode: 400,
      });
    });


    test('converts PKCS12 errors to controlled certificate errors', async () => {
      extractFromPkcs12.mockRejectedValueOnce(new Error('Bad PKCS12 data'));
      mockDiscoverySuccess();

      await expect(
        testConnection({
          protocol: 'oidc',
          auth_method: 'private_key_jwt',
          tenant_id: TENANT_GUID,
          client_id: 'client-1',
          certificate: 'invalid-pfx',
        })
      ).rejects.toMatchObject({ code: 'SSO_CERTIFICATE_INVALID' });
    });


    test('throws when stored OIDC configuration is missing', async () => {
      getOidcConfig.mockResolvedValueOnce(null);
      mockDiscoverySuccess();

      await expect(
        testConnection({
          protocol: 'oidc',
          auth_method: 'private_key_jwt',
          tenant_id: TENANT_GUID,
          client_id: 'client-1',
          company_id: 'company-1',
          use_existing_cert: true,
        })
      ).rejects.toMatchObject({
        code: 'SSO_CONFIGURATION_NOT_FOUND',
        statusCode: 404,
      });
    });


    test('rejects invalid tenant before network access', async () => {
      const httpsSpy = mockRequest(() => ({ statusCode: 200, body: '{}' }));

      const result = await testConnection({
        protocol: 'oidc',
        auth_method: 'none',
        tenant_id: 'common/../../evil',
        client_id: 'client-1',
      });

      expect(result.success).toBe(false);
      expect(httpsSpy).not.toHaveBeenCalled();
    });
  });

  describe('tenant ownership', () => {
    test('rejects tenant registered to a different company', async () => {
      const httpsSpy = mockRequest(() => ({ statusCode: 200, body: '{}' }));
      ssoIntegration.findOne.mockResolvedValue({ company_id: 'other-company' });

      const result = await testConnection({
        protocol: 'oidc',
        tenant_id: VALID_TENANT,
        company_id: 'my-company',
      });

      expect(result.success).toBe(false);
      expect(httpsSpy).not.toHaveBeenCalled();
    });

    test('allows a tenant owned by the same company using dataValues', async () => {
      ssoIntegration.findOne.mockResolvedValue({
        dataValues: { company_id: 'my-company' },
      });
      mockDiscoverySuccess();

      const result = await testConnection({
        protocol: 'oidc',
        auth_method: 'none',
        tenant_id: VALID_TENANT,
        company_id: 'my-company',
        client_id: 'client-1',
      });

      expect(result.success).toBe(true);
    });

    test('returns controlled database verification failure', async () => {
      const httpsSpy = mockRequest(() => ({ statusCode: 200, body: '{}' }));
      ssoIntegration.findOne.mockRejectedValue(new Error('ECONNRESET'));

      const result = await testConnection({
        protocol: 'oidc',
        tenant_id: VALID_TENANT,
        company_id: 'company-1',
      });

      expect(result).toEqual({
        success: false,
        message: 'Internal server error occurred while verifying tenant configuration.',
      });
      expect(httpsSpy).not.toHaveBeenCalled();
    });
  });

  describe('SAML', () => {
    const SSO_URL = `https://login.microsoftonline.com/${TENANT_GUID}/saml2`;
    const APP_SSO_URL = `${SSO_URL}?appid=${APP_GUID}`;

    const basePayload = () => ({
      protocol: 'saml',
      tenant_id: TENANT_GUID,
      sso_url: SSO_URL,
      certificate: encodeUploadedCert(),
    });

    // ?appid= scopes the metadata to the app, so the uploaded cert can be matched up front
    const appPayload = () => ({ ...basePayload(), sso_url: APP_SSO_URL });

    const popupSession = { protocol: 'saml', sessionRef: expect.any(String), redirectUrl: SAML_REDIRECT };

    test('leaves the certificate to the popup when the SSO URL has no appid', async () => {
      // Tenant metadata never lists an app's own signing cert, so a different cert here is expected
      const requestSpy = mockSamlRequests({
        metadataBody: buildMetadataXml({ certificates: ['TENANT_DEFAULT_CERT'] }),
      });

      const result = await testConnection(basePayload());

      expect(result).toEqual({
        success: true,
        message: 'Connection successful — SAML IdP metadata reachable',
        data: popupSession,
      });
      expect(String(requestSpy.mock.calls[0][0])).not.toContain('appid=');
    });

    test('builds a ForceAuthn login whose callback is checked against the unsaved cert and SSO URL', async () => {
      mockSamlRequests();
      const payload = basePayload();

      const result = await testConnection(payload);

      const { sessionRef } = result.data;
      expect(buildSamlRedirectUrl).toHaveBeenCalledWith(
        'https://sp.example.com/auth/metadata2',
        'https://sp.example.com/auth/callback',
        SSO_URL,
        {},
        sessionRef,
        undefined,
        {
          forceAuthn: true,
          testContext: {
            sessionRef,
            certificate: payload.certificate,
            sso_url: SSO_URL,
            entity_id: 'https://sp.example.com/auth/metadata2',
            acs_url: 'https://sp.example.com/auth/callback',
          },
        },
      );
    });

    test('verifies the certificate against the app metadata when the SSO URL has ?appid=', async () => {
      const requestSpy = mockSamlRequests();

      const result = await testConnection(appPayload());

      expect(String(requestSpy.mock.calls[0][0])).toContain(`appid=${APP_GUID}`);
      expect(result).toEqual({
        success: true,
        message: 'Connection successful — SAML IdP metadata reachable and certificate verified',
        data: popupSession,
      });
    });

    test('needs no App ID or client secret and calls no Microsoft Graph API', async () => {
      const requestSpy = mockSamlRequests();

      // Older consoles may still send these; they are ignored
      const result = await testConnection({
        ...basePayload(),
        app_id: APP_GUID,
        client_secret: 'saml-client-secret',
      });

      expect(result.success).toBe(true);
      expect(requestSpy).toHaveBeenCalledTimes(1);
      expect(String(requestSpy.mock.calls[0][0])).toContain('federationmetadata');
      expect(String(requestSpy.mock.calls[0][0])).not.toContain('appid=');
    });

    test('returns metadata HTTP failure', async () => {
      mockSamlRequests({ metadataStatus: 503, metadataBody: 'Unavailable' });

      await expect(testConnection(basePayload())).resolves.toEqual({
        success: false,
        message: 'SAML metadata unreachable (HTTP 503)',
      });
      expect(buildSamlRedirectUrl).not.toHaveBeenCalled();
    });

    test('rejects invalid SSO URL before network access', async () => {
      const httpsSpy = mockRequest(() => ({ statusCode: 200, body: '' }));

      const result = await testConnection({
        protocol: 'saml',
        tenant_id: TENANT_GUID,
        sso_url: 'https://login.microsoftonline.com/not-a-guid/saml2',
      });

      expect(result.message).toContain('Could not extract tenant ID');
      expect(httpsSpy).not.toHaveBeenCalled();
    });

    test('rejects metadata belonging to another tenant', async () => {
      mockSamlRequests({
        metadataBody: buildMetadataXml({ tenantId: OTHER_TENANT_GUID }),
      });

      const result = await testConnection(basePayload());
      expect(result.message).toContain('does not match metadata tenant');
      expect(buildSamlRedirectUrl).not.toHaveBeenCalled();
    });

    test('rejects missing uploaded certificate', async () => {
      mockSamlRequests();
      const payload = basePayload();
      delete payload.certificate;

      await expect(testConnection(payload)).resolves.toEqual({
        success: false,
        message: 'Certificate not provided for validation.',
      });
      expect(buildSamlRedirectUrl).not.toHaveBeenCalled();
    });

    test('rejects app metadata without signing certificates', async () => {
      mockSamlRequests({
        metadataBody: buildMetadataXml({ certificates: [] }),
      });

      await expect(testConnection(appPayload())).resolves.toEqual({
        success: false,
        message: 'Could not extract signing certificate from Azure metadata',
      });
    });

    test('rejects certificate mismatch against the app metadata', async () => {
      mockSamlRequests();
      const payload = appPayload();
      payload.certificate = encodeUploadedCert('DIFFERENT_CERTIFICATE');

      await expect(testConnection(payload)).resolves.toEqual({
        success: false,
        message: 'Certificate does not match Azure tenant signing certificate',
      });
      // A failed metadata check never opens the popup
      expect(buildSamlRedirectUrl).not.toHaveBeenCalled();
    });

    test('matches any certificate from the app metadata', async () => {
      mockSamlRequests({
        metadataBody: buildMetadataXml({ certificates: ['OLD_CERT', RAW_CERT] }),
      });

      const result = await testConnection(appPayload());
      expect(result.success).toBe(true);
    });

    test('does not open the popup without an SSO URL', async () => {
      mockSamlRequests();

      const result = await testConnection({
        protocol: 'saml',
        tenant_id: TENANT_GUID,
        certificate: encodeUploadedCert(),
      });

      expect(result).toEqual({
        success: true,
        message: 'Connection successful — SAML IdP metadata reachable',
      });
      expect(buildSamlRedirectUrl).not.toHaveBeenCalled();
    });

    test('fails rather than skip the certificate check when the test sign-in cannot be built', async () => {
      mockSamlRequests();
      buildSamlRedirectUrl.mockRejectedValue(new Error('Failed to generate SAML AuthnRequest'));

      await expect(testConnection(basePayload())).resolves.toEqual({
        success: false,
        message: 'Could not start the SAML test sign-in. Please try again.',
      });
    });

    test('rejects invalid request-signing certificate', async () => {
      extractFromPkcs12.mockRejectedValueOnce(new Error('Invalid PFX password'));

      const result = await testConnection({
        ...basePayload(),
        sign_authn_request: true,
        use_existing_signing_cert: false,
        signing_certificate: 'invalid-pfx',
        signing_certificate_password: 'wrong-password',
      });

      expect(result).toEqual({
        success: false,
        message: 'Invalid signing certificate or certificate password.',
      });
    });

    test('loads existing SAML signing certificate', async () => {
      getSamlConfig.mockResolvedValue({ sp_private_key_enc: 'stored-key' });
      mockSamlRequests();

      const result = await testConnection({
        ...basePayload(),
        company_id: 'company-1',
        sign_authn_request: true,
        use_existing_signing_cert: true,
      });

      expect(getSamlConfig).toHaveBeenCalledWith('company-1');
      expect(result.success).toBe(true);
    });
  });

  describe('validateSsoConfiguration', () => {
    test('validates stored OIDC client secret', async () => {
      mockDeterministicCrypto();
      ssoIntegration.findByPk.mockResolvedValue({
        protocol: 'oidc',
        entra_tenant_id: VALID_TENANT,
      });
      OidcConfiguration.findOne.mockResolvedValue({
        client_id: 'stored-client',
        client_auth_method: 'client_secret_post',
        client_secret_enc: 'encrypted-secret',
        scope: 'openid',
        redirect_uri: 'https://app.example/callback',
      });
      cryptoUtil.resolveSecret.mockReturnValue('plain-secret');
      mockRequest(() => ({
        statusCode: 200,
        body: JSON.stringify({ access_token: 'token' }),
      }));

      const result = await validateSsoConfiguration('company-1');
      expect(result.success).toBe(true);
    });

    test('returns pre-check failure without creating session', async () => {
      ssoIntegration.findByPk.mockResolvedValue({
        protocol: 'oidc',
        entra_tenant_id: VALID_TENANT,
      });
      OidcConfiguration.findOne.mockResolvedValue({
        client_id: 'stored-client',
        client_auth_method: 'private_key_jwt',
        private_key_enc: 'key',
        client_cert_thumbprint: VALID_SHA1_THUMBPRINT,
      });
      mockRequest(() => ({ statusCode: 404, body: '{}' }));

      const result = await validateSsoConfiguration('company-1');
      expect(result.success).toBe(false);
      expect(tcStore.set).not.toHaveBeenCalled();
    });

    test('throws when integration is missing', async () => {
      ssoIntegration.findByPk.mockResolvedValue(null);

      await expect(
        validateSsoConfiguration('missing-company')
      ).rejects.toMatchObject({
        code: 'SSO_CONFIGURATION_NOT_FOUND',
        statusCode: 404,
      });
    });

    test('throws when OIDC configuration is missing', async () => {
      ssoIntegration.findByPk.mockResolvedValue({
        protocol: 'oidc',
        entra_tenant_id: VALID_TENANT,
      });
      OidcConfiguration.findOne.mockResolvedValue(null);

      await expect(
        validateSsoConfiguration('company-1')
      ).rejects.toMatchObject({ code: 'SSO_CONFIGURATION_NOT_FOUND' });
    });

    test('opens the popup for a stored SAML configuration, checked against the stored cert', async () => {
      const storedSsoUrl = `https://login.microsoftonline.com/${TENANT_GUID}/saml2`;
      ssoIntegration.findByPk.mockResolvedValue({
        protocol: 'saml',
        entra_tenant_id: TENANT_GUID,
      });
      SamlConfiguration.findOne.mockResolvedValue({
        sso_url: storedSsoUrl,
        certificate: 'encrypted-cert',
        // Legacy rows may still carry these; activation no longer uses them
        app_id: APP_GUID,
        client_secret_enc: 'encrypted-secret',
      });
      cryptoUtil.resolveSecret.mockImplementation((value) =>
        value === 'encrypted-cert' ? encodeUploadedCert() : value
      );
      const requestSpy = mockSamlRequests();

      const result = await validateSsoConfiguration('company-1');

      expect(result).toEqual({
        success: true,
        message: 'Connection successful — SAML IdP metadata reachable',
        data: { protocol: 'saml', sessionRef: expect.any(String), redirectUrl: SAML_REDIRECT },
      });
      expect(requestSpy).toHaveBeenCalledTimes(1);
      expect(buildSamlRedirectUrl).toHaveBeenCalledWith(
        expect.any(String), expect.any(String), storedSsoUrl, {}, result.data.sessionRef, undefined,
        expect.objectContaining({
          forceAuthn: true,
          testContext: expect.objectContaining({ certificate: encodeUploadedCert(), sso_url: storedSsoUrl }),
        }),
      );
    });

    test('returns a stored SAML metadata failure without a popup', async () => {
      ssoIntegration.findByPk.mockResolvedValue({
        protocol: 'saml',
        entra_tenant_id: TENANT_GUID,
      });
      SamlConfiguration.findOne.mockResolvedValue({
        sso_url: `https://login.microsoftonline.com/${TENANT_GUID}/saml2`,
        certificate: encodeUploadedCert(),
      });
      mockSamlRequests({ metadataStatus: 503, metadataBody: 'Unavailable' });

      await expect(validateSsoConfiguration('company-1')).resolves.toEqual({
        success: false,
        message: 'SAML metadata unreachable (HTTP 503)',
      });
      expect(buildSamlRedirectUrl).not.toHaveBeenCalled();
    });
  });

  test('returns false for unknown direct protocol', async () => {
    await expect(testConnection({ protocol: 'ldap' })).resolves.toEqual({
      success: false,
      message: 'Unknown protocol',
    });
  });
});
 