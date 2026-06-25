const { microsoft, defaults, MS_LOGIN_BASE, MS_GRAPH_BASE, MS_STS_BASE } = require('../src/config/constants');

const T = '2c761afb-5a70-452a-ab62-b98b90a6e556';

describe('constants — microsoft endpoint builders', () => {
  test('base hosts', () => {
    expect(MS_LOGIN_BASE).toBe('https://login.microsoftonline.com');
    expect(MS_GRAPH_BASE).toBe('https://graph.microsoft.com');
    expect(MS_STS_BASE).toBe('https://sts.windows.net');
  });

  test('OIDC/OAuth2 URLs are tenant-parameterised', () => {
    expect(microsoft.tokenUrl(T)).toBe(`https://login.microsoftonline.com/${T}/oauth2/v2.0/token`);
    expect(microsoft.authorizeUrl(T)).toBe(`https://login.microsoftonline.com/${T}/oauth2/v2.0/authorize`);
    expect(microsoft.discoveryUrl(T)).toBe(`https://login.microsoftonline.com/${T}/v2.0/.well-known/openid-configuration`);
    expect(microsoft.jwksUrl(T)).toBe(`https://login.microsoftonline.com/${T}/discovery/v2.0/keys`);
    expect(microsoft.issuer(T)).toBe(`https://login.microsoftonline.com/${T}/v2.0`);
  });

  test('SAML URLs are tenant-parameterised', () => {
    expect(microsoft.samlMetadataUrl(T)).toBe(`https://login.microsoftonline.com/${T}/federationmetadata/2007-06/federationmetadata.xml`);
    expect(microsoft.samlSsoUrl(T)).toBe(`https://login.microsoftonline.com/${T}/saml2`);
    expect(microsoft.samlIssuer(T)).toBe(`https://sts.windows.net/${T}/`);
  });

  test('Graph constants', () => {
    expect(microsoft.graphMemberOf).toBe('https://graph.microsoft.com/v1.0/me/memberOf?$select=id,securityEnabled');
    expect(microsoft.graphScope).toBe('https://graph.microsoft.com/.default');
  });

  test('aliases like "common"/"consumers" pass straight through', () => {
    expect(microsoft.tokenUrl('common')).toContain('/common/');
    expect(microsoft.authorizeUrl('consumers')).toContain('/consumers/');
  });

  describe('issuerPattern (validates the OIDC iss claim)', () => {
    test('matches a valid tenant-bound v2.0 issuer', () => {
      expect(microsoft.issuerPattern.test(`https://login.microsoftonline.com/${T}/v2.0`)).toBe(true);
    });
    test('rejects a foreign issuer', () => {
      expect(microsoft.issuerPattern.test('https://evil.example.com/v2.0')).toBe(false);
    });
    test('rejects missing /v2.0 suffix', () => {
      expect(microsoft.issuerPattern.test(`https://login.microsoftonline.com/${T}`)).toBe(false);
    });
  });
});

describe('constants — defaults', () => {
  test('static values', () => {
    expect(defaults.SSO_STATUS).toBe('active');
    expect(defaults.IDP).toBe('microsoft_entra');
    expect(defaults.OIDC_SCOPE).toBe('openid profile email offline_access');
  });

  test('URL defaults are non-empty strings', () => {
    for (const k of ['OIDC_REDIRECT_URI', 'SAML_ENTITY_ID', 'SAML_ACS_URL', 'FRONTEND_URL']) {
      expect(typeof defaults[k]).toBe('string');
      expect(defaults[k].length).toBeGreaterThan(0);
    }
  });

  test('env vars override the fallback URLs', () => {
    jest.isolateModules(() => {
      const prev = process.env.OIDC_REDIRECT_URI;
      process.env.OIDC_REDIRECT_URI = 'https://override.example.com/cb';
      const { defaults: d } = require('../src/config/constants');
      expect(d.OIDC_REDIRECT_URI).toBe('https://override.example.com/cb');
      if (prev === undefined) delete process.env.OIDC_REDIRECT_URI; else process.env.OIDC_REDIRECT_URI = prev;
    });
  });

  test('falls back to localhost when OIDC_REDIRECT_URI is unset', () => {
    jest.isolateModules(() => {
      const prev = process.env.OIDC_REDIRECT_URI;
      delete process.env.OIDC_REDIRECT_URI;
      const { defaults: d } = require('../src/config/constants');
      expect(d.OIDC_REDIRECT_URI).toBe('http://localhost:3000/auth/oidc/callback');
      if (prev !== undefined) process.env.OIDC_REDIRECT_URI = prev;
    });
  });
});
