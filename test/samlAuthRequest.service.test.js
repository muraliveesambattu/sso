const loadSamlAuthRequestService = ({ privateKeyPem = null, envPrivateKeyB64 = null, deflateImpl } = {}) => {
  jest.resetModules();

  if (envPrivateKeyB64) process.env.SP_PRIVATE_KEY_B64 = envPrivateKeyB64;
  else delete process.env.SP_PRIVATE_KEY_B64;

  const readFileSync = jest.fn(() => {
    if (privateKeyPem === null) throw new Error('missing key');
    return privateKeyPem;
  });
  const logger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
  const randomUUID = jest.fn(() => 'request-uuid');
  const sign = jest.fn(() => Buffer.from('signature-bytes'));
  const deflateRaw = jest.fn(deflateImpl || ((buffer, cb) => cb(null, Buffer.from(`deflated:${buffer.toString('utf8')}`))));

  jest.doMock('node:fs', () => ({ readFileSync }));
  jest.doMock('node:crypto', () => ({ randomUUID, sign }));
  jest.doMock('node:zlib', () => ({ deflateRaw }));
  jest.doMock('../src/config/logger', () => ({ logger }));

  const service = require('../src/services/Saml/samlAuthRequest.service');
  return { service, mocks: { readFileSync, logger, randomUUID, sign, deflateRaw } };
};

describe('samlAuthRequest.service', () => {
  afterEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
    delete process.env.SP_PRIVATE_KEY_B64;
  });

  test('builds an unsigned SAML redirect and stores the authn request context when no private key is available', async () => {
    const { service } = loadSamlAuthRequestService();

    const redirectUrl = await service.buildSamlRedirectUrl(
      'https://sp.example.com/metadata',
      'https://sp.example.com/callback',
      'https://login.microsoftonline.com/tenant/saml2',
      {},
      'session-1'
    );

    expect(redirectUrl).toContain('https://login.microsoftonline.com/tenant/saml2?SAMLRequest=');
    expect(redirectUrl).toContain('RelayState=_zdna_request-uuid');
    expect(redirectUrl).not.toContain('Signature=');
    expect(service.samlRequestStore.get('_zdna_request-uuid')).toEqual(expect.objectContaining({
      authnRequestId: '_zdna_request-uuid',
      ssoContext: {
        entity_id: 'https://sp.example.com/metadata',
        acs_url: 'https://sp.example.com/callback',
      },
    }));
    service.samlRequestStore.clear();
  });

  test('joins with & when the stored SSO URL already carries a query string (legacy ?appid rows)', async () => {
    const { service } = loadSamlAuthRequestService();

    const redirectUrl = await service.buildSamlRedirectUrl(
      'https://sp.example.com/metadata',
      'https://sp.example.com/callback',
      'https://login.microsoftonline.com/tenant/saml2?appid=26ad49ad-797a-47aa-8701-d339de837a68',
      {},
      'session-1'
    );

    // A second '?' corrupts the query string — Entra rejects it with AADSTS750054
    expect((redirectUrl.match(/\?/g) || []).length).toBe(1);
    expect(redirectUrl).toContain('appid=26ad49ad-797a-47aa-8701-d339de837a68&SAMLRequest=');
    service.samlRequestStore.clear();
  });

  test('builds a signed SAML redirect when a private key is available via env var', async () => {
    const envKey = Buffer.from('PRIVATE KEY FROM ENV').toString('base64');
    const { service, mocks } = loadSamlAuthRequestService({ envPrivateKeyB64: envKey });

    const redirectUrl = await service.buildSamlRedirectUrl(
      'https://sp.example.com/metadata',
      'https://sp.example.com/callback',
      'https://login.microsoftonline.com/tenant/saml2',
      {},
      'session-2'
    );

    expect(mocks.sign).toHaveBeenCalled();
    expect(redirectUrl).toContain('SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256');
    expect(redirectUrl).toContain('Signature=');
    service.samlRequestStore.clear();
  });

  test('throws a sanitized error when compression fails', async () => {
    const { service } = loadSamlAuthRequestService({
      deflateImpl: (buffer, cb) => cb(new Error('compression failed')),
    });

    await expect(
      service.buildSamlRedirectUrl(
        'https://sp.example.com/metadata',
        'https://sp.example.com/callback',
        'https://login.microsoftonline.com/tenant/saml2',
        {},
        'session-3'
      )
    ).rejects.toMatchObject({
      statusCode: 500,
      code: 'AUTHN_REQUEST_GENERATION_FAILED',
    });
    service.samlRequestStore.clear();
  });

  describe('SAML Test Connection', () => {
    const ENTITY = 'https://sp.example.com/metadata';
    const ACS = 'https://sp.example.com/callback';
    const SSO = 'https://login.microsoftonline.com/tenant/saml2';
    const testContext = {
      sessionRef: 'ref-1',
      certificate: 'cert-b64',
      sso_url: SSO,
      entity_id: ENTITY,
      acs_url: ACS,
    };

    // The deflate mock prefixes the XML with "deflated:", so the SAMLRequest decodes straight back to it.
    const decodeAuthnRequest = (redirectUrl) => {
      const samlRequest = new URL(redirectUrl).searchParams.get('SAMLRequest');
      return Buffer.from(samlRequest, 'base64').toString('utf8');
    };

    afterEach(() => {
      jest.restoreAllMocks();
    });

    test('omits ForceAuthn by default and adds it when options.forceAuthn is set', async () => {
      const { service } = loadSamlAuthRequestService();

      const plain = await service.buildSamlRedirectUrl(ENTITY, ACS, SSO, {}, 's-1');
      const forced = await service.buildSamlRedirectUrl(ENTITY, ACS, SSO, {}, 's-2', 'company-1', { forceAuthn: true });

      expect(decodeAuthnRequest(plain)).not.toContain('ForceAuthn');
      expect(decodeAuthnRequest(forced)).toContain('ForceAuthn="true"');
      service.samlRequestStore.clear();
    });

    test('does not mark a normal login request as a test', async () => {
      const { service } = loadSamlAuthRequestService();

      await service.buildSamlRedirectUrl(ENTITY, ACS, SSO, {}, 's-1', 'company-1');

      const entry = service.samlRequestStore.get('_zdna_request-uuid');
      expect(entry.test).toBeUndefined();
      expect(entry.ssoContext.company_id).toBe('company-1');
      service.samlRequestStore.clear();
    });

    test('stores the testContext server-side with an empty result', async () => {
      const { service } = loadSamlAuthRequestService();

      await service.buildSamlRedirectUrl(ENTITY, ACS, SSO, {}, 'ref-1', undefined, { testContext, forceAuthn: true });

      expect(service.samlRequestStore.get('_zdna_request-uuid').test).toEqual({ ...testContext, result: null });
      service.samlRequestStore.clear();
    });

    test('takeSamlTestResult returns null for an unknown sessionRef', () => {
      const { service } = loadSamlAuthRequestService();

      expect(service.takeSamlTestResult('nope')).toBeNull();
    });

    test('takeSamlTestResult reports pending without consuming the entry', async () => {
      const { service } = loadSamlAuthRequestService();
      await service.buildSamlRedirectUrl(ENTITY, ACS, SSO, {}, 'ref-1', undefined, { testContext });

      expect(service.takeSamlTestResult('ref-1')).toEqual({ pending: true });
      expect(service.takeSamlTestResult('ref-1')).toEqual({ pending: true });
      expect(service.samlRequestStore.has('_zdna_request-uuid')).toBe(true);
      service.samlRequestStore.clear();
    });

    test('takeSamlTestResult returns a finished result once, then null', async () => {
      const { service } = loadSamlAuthRequestService();
      await service.buildSamlRedirectUrl(ENTITY, ACS, SSO, {}, 'ref-1', undefined, { testContext });
      const result = { success: true, email: 'user@example.com', claims: { roles: [], groups: [], groupsOverage: false } };
      service.samlRequestStore.get('_zdna_request-uuid').test.result = result;

      expect(service.takeSamlTestResult('ref-1')).toEqual(result);
      expect(service.takeSamlTestResult('ref-1')).toBeNull();
      expect(service.samlRequestStore.size).toBe(0);
    });

    test('takeSamlTestResult drops and rejects an entry older than 10 minutes', async () => {
      const { service } = loadSamlAuthRequestService();
      const now = 1_000_000_000_000;
      jest.spyOn(Date, 'now').mockReturnValue(now);
      await service.buildSamlRedirectUrl(ENTITY, ACS, SSO, {}, 'ref-1', undefined, { testContext });

      Date.now.mockReturnValue(now + 600001);

      expect(service.takeSamlTestResult('ref-1')).toBeNull();
      expect(service.samlRequestStore.size).toBe(0);
    });

    test('takeSamlTestResult ignores normal login entries', async () => {
      const { service } = loadSamlAuthRequestService();
      await service.buildSamlRedirectUrl(ENTITY, ACS, SSO, {}, 'ref-1', 'company-1');

      expect(service.takeSamlTestResult('ref-1')).toBeNull();
      expect(service.samlRequestStore.size).toBe(1);
      service.samlRequestStore.clear();
    });
  });
});
