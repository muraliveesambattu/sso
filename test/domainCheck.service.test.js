jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/services/featureFlag.service', () => ({
  isEnabled: jest.fn(),
}));

jest.mock('../src/services/Saml/samlAuthRequest.service', () => ({
  buildSamlRedirectUrl: jest.fn(),
}));

jest.mock('../src/services/db/ssoDataService', () => ({
  getSsoIntegrationByDomain: jest.fn(),
  getOidcConfig: jest.fn(),
  getSamlConfig: jest.fn(),
}));

jest.mock('../src/config/stateStore', () => ({
  stateStore: { set: jest.fn() },
}));

jest.mock('../src/config/constants', () => ({
  microsoft: {
    authorizeUrl: jest.fn((tenantId) => `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`),
  },
}));

const { checkDomain } = require('../src/services/SSO/domainCheck.service');
const { isEnabled } = require('../src/services/featureFlag.service');
const { buildSamlRedirectUrl } = require('../src/services/Saml/samlAuthRequest.service');
const { getSsoIntegrationByDomain, getOidcConfig, getSamlConfig } = require('../src/services/db/ssoDataService');
const { stateStore } = require('../src/config/stateStore');

describe('domainCheck.service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    isEnabled.mockResolvedValue(true);
  });

  test('throws 400 when both email and domain are missing', async () => {
    await expect(checkDomain(null, null, {}, 'session-1')).rejects.toMatchObject({
      statusCode: 400,
      code: 'MISSING_INPUT',
    });
  });

  test('throws 500 when session data is unavailable', async () => {
    await expect(checkDomain('user@example.com', null, null, null)).rejects.toMatchObject({
      statusCode: 500,
      code: 'MISSING_SESSION',
    });
  });

  test('returns org-domain prompt when email domain is not configured', async () => {
    getSsoIntegrationByDomain.mockResolvedValue(null);

    const result = await checkDomain('User@Example.com', null, {}, 'session-1');

    expect(getSsoIntegrationByDomain).toHaveBeenCalledWith('example.com');
    expect(result).toEqual({
      found: false,
      promptOrgDomain: true,
      message: 'Please enter your organisation domain name',
    });
  });

  test('throws 400 for invalid email and invalid domain inputs', async () => {
    await expect(checkDomain('not-an-email', null, {}, 'session-1')).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_EMAIL',
    });

    await expect(checkDomain(null, 'bad domain', {}, 'session-1')).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_DOMAIN',
    });
  });

  test('treats SSO-disabled companies as not configured', async () => {
    getSsoIntegrationByDomain.mockResolvedValue({
      company_id: 'company-1',
      protocol: 'oidc',
      entra_tenant_id: 'common',
    });
    isEnabled.mockResolvedValue(false);

    const result = await checkDomain('user@example.com', null, {}, 'session-1');

    expect(result).toEqual({
      found: false,
      promptOrgDomain: true,
      message: 'Please enter your organisation domain name',
    });
    expect(getOidcConfig).not.toHaveBeenCalled();
  });

  test('returns not-found responses when integration config records are missing or protocol is unsupported', async () => {
    getSsoIntegrationByDomain
      .mockResolvedValueOnce({
        company_id: 'company-oidc-missing',
        protocol: 'oidc',
        entra_tenant_id: 'common',
      })
      .mockResolvedValueOnce({
        company_id: 'company-saml-missing',
        protocol: 'saml',
      })
      .mockResolvedValueOnce({
        company_id: 'company-unknown',
        protocol: 'ldap',
      });
    getOidcConfig.mockResolvedValue(null);
    getSamlConfig.mockResolvedValue(null);

    await expect(checkDomain('user@example.com', null, {}, 'session-1')).resolves.toEqual({
      found: false,
      promptOrgDomain: true,
      message: 'Please enter your organisation domain name',
    });
    await expect(checkDomain(null, 'example.com', {}, 'session-2')).resolves.toEqual({
      found: false,
      promptOrgDomain: false,
      message: 'SSO is not available for this domain. Please contact your administrator.',
    });
    await expect(checkDomain(null, 'example.com', {}, 'session-3')).resolves.toEqual({
      found: false,
      promptOrgDomain: false,
      message: 'SSO is not available for this domain. Please contact your administrator.',
    });
  });

  test('returns PKCE OIDC config and stores server-side verifier for auth_method none', async () => {
    getSsoIntegrationByDomain.mockResolvedValue({
      company_id: 'company-1',
      protocol: 'oidc',
      entra_tenant_id: 'consumers',
    });
    getOidcConfig.mockResolvedValue({
      client_id: 'client-1',
      client_auth_method: 'none',
      redirect_uri: 'http://localhost:3000/auth/oidc/callback',
    });

    const result = await checkDomain('user@example.com', null, { user: 'session' }, 'session-1');

    expect(result.found).toBe(true);
    expect(result.protocol).toBe('oidc');
    expect(result.client_auth_method).toBe('none');
    expect(result.config).toEqual(expect.objectContaining({
      client_id: 'client-1',
      sso_url: 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize',
      redirect_uri: 'http://localhost:3000/auth/oidc/callback',
      scope: 'openid profile email',
      response_mode: 'query',
      state: expect.any(String),
      nonce: expect.any(String),
      code_challenge: expect.any(String),
      code_challenge_method: 'S256',
    }));
    expect(stateStore.set).toHaveBeenCalledWith(
      result.config.state,
      expect.objectContaining({
        nonce: result.config.nonce,
        code_verifier: expect.any(String),
        createdAt: expect.any(Number),
      }),
      600
    );
  });

  test('returns non-PKCE OIDC config without code challenge for client_secret auth', async () => {
    getSsoIntegrationByDomain.mockResolvedValue({
      company_id: 'company-2',
      protocol: 'oidc',
      entra_tenant_id: 'tenant-123',
    });
    getOidcConfig.mockResolvedValue({
      client_id: 'client-2',
      client_auth_method: 'client_secret',
      client_secret: 'env:SECRET',
      redirect_uri: 'http://localhost:3000/auth/oidc/callback',
    });

    const result = await checkDomain(null, 'example.com', { user: 'session' }, 'session-2');

    expect(result).toEqual(expect.objectContaining({
      found: true,
      protocol: 'oidc',
      client_auth_method: 'client_secret',
    }));
    expect(result.config.code_challenge).toBeUndefined();
    expect(result.config.code_challenge_method).toBeUndefined();
  });

  test('resolves env-based redirect URIs for OIDC responses', async () => {
    process.env.OIDC_REDIRECT_URI_FROM_ENV = 'http://localhost:5173/auth/oidc/callback';
    getSsoIntegrationByDomain.mockResolvedValue({
      company_id: 'company-redirect-env',
      protocol: 'oidc',
      entra_tenant_id: 'tenant-456',
    });
    getOidcConfig.mockResolvedValue({
      client_id: 'client-env',
      client_auth_method: 'client_secret_post',
      redirect_uri: 'env:OIDC_REDIRECT_URI_FROM_ENV',
    });

    const result = await checkDomain(null, 'example.com', { user: 'session' }, 'session-4');

    expect(result.config.redirect_uri).toBe('http://localhost:5173/auth/oidc/callback');
  });

  test('returns SAML redirect for SAML integrations', async () => {
    getSsoIntegrationByDomain.mockResolvedValue({
      company_id: 'company-3',
      protocol: 'saml',
    });
    getSamlConfig.mockResolvedValue({
      entity_id: 'entity-id',
      sso_url: 'https://login.microsoftonline.com/tenant/saml2',
      acs_url: 'http://localhost:5000/auth/callback',
    });
    buildSamlRedirectUrl.mockResolvedValue('https://redirect.example.test');

    const result = await checkDomain(null, 'example.com', { user: 'session' }, 'session-3');

    expect(buildSamlRedirectUrl).toHaveBeenCalledWith(
      'entity-id',
      'http://localhost:5000/auth/callback',
      'https://login.microsoftonline.com/tenant/saml2',
      { user: 'session' },
      'session-3',
      'company-3'
    );
    expect(result).toEqual({
      found: true,
      protocol: 'saml',
      message: 'Redirecting to Microsoft Entra...',
      redirectUrl: 'https://redirect.example.test',
    });
  });
});
