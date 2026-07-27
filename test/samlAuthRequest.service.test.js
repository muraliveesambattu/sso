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
});
