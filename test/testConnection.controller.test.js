jest.mock('../src/services/SSO/testConnection.service', () => ({
  testConnection: jest.fn(),
  validateSsoConfiguration: jest.fn(),
}));

jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/services/audit/audit.service', () => ({
  auditTestConnection: jest.fn(),
}));

jest.mock('../src/utils/shared/testConnectionStore', () => ({
  set: jest.fn(),
}));

// The controller reads stored certificates through the Postgres layer; mocking it keeps
// sequelize (and a live DB) out of this suite.
jest.mock('../src/services/db/postgresSSO.service', () => ({
  getOidcConfig: jest.fn(),
  getSamlConfig: jest.fn(),
}));

jest.mock('../src/utils/crypto.util', () => ({
  decrypt: jest.fn(),
}));

const { handleTestConnection } = require('../src/controllers/testConnection.controller');
const { testConnection, validateSsoConfiguration } = require('../src/services/SSO/testConnection.service');
const { auditTestConnection } = require('../src/services/audit/audit.service');
const tcStore = require('../src/utils/shared/testConnectionStore');
const { getOidcConfig, getSamlConfig } = require('../src/services/db/postgresSSO.service');

const mockReq = (body = {}) => ({
  body,
  ip: '1.2.3.4',
});

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

const SSO_URL = 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/saml2';

describe('testConnection.controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    testConnection.mockResolvedValue({ success: true, message: 'ok' });
  });

  describe('request validation', () => {
    test('returns 400 when protocol is missing', async () => {
      const res = mockRes();

      await handleTestConnection(mockReq({}), res, jest.fn());

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ success: false, message: 'protocol is required' });
      expect(testConnection).not.toHaveBeenCalled();
    });

    test('returns 400 when OIDC has no tenant_id', async () => {
      const res = mockRes();

      await handleTestConnection(mockReq({ protocol: 'oidc' }), res, jest.fn());

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ success: false, message: 'tenant_id is required' });
    });

    test('returns 400 when SAML has neither sso_url nor tenant_id', async () => {
      const res = mockRes();

      await handleTestConnection(mockReq({ protocol: 'saml' }), res, jest.fn());

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ success: false, message: 'sso_url (or tenant_id) is required' });
    });

    test('accepts SAML with only tenant_id', async () => {
      const res = mockRes();

      await handleTestConnection(mockReq({ protocol: 'saml', tenant_id: 'tenant-1' }), res, jest.fn());

      expect(res.status).toHaveBeenCalledWith(200);
    });
  });

  describe('existing configuration test', () => {
    test('validates the saved configuration by company_id and skips the new-config flow', async () => {
      validateSsoConfiguration.mockResolvedValue({ success: true, message: 'saved config ok' });
      const res = mockRes();

      await handleTestConnection(mockReq({ is_existing_test: true, company_id: 'company-1' }), res, jest.fn());

      expect(validateSsoConfiguration).toHaveBeenCalledWith('company-1');
      expect(testConnection).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({ success: true, message: 'saved config ok' });
    });

    test('passes validateSsoConfiguration errors to next', async () => {
      const err = Object.assign(new Error('SSO_CONFIGURATION_NOT_FOUND'), { statusCode: 404 });
      validateSsoConfiguration.mockRejectedValue(err);
      const next = jest.fn();

      await handleTestConnection(mockReq({ is_existing_test: true, company_id: 'company-1' }), mockRes(), next);

      expect(next).toHaveBeenCalledWith(err);
    });
  });

  describe('OIDC', () => {
    test('trims identifiers, stores the internal test state, strips it, audits and returns 200', async () => {
      const req = mockReq({
        protocol: 'oidc',
        auth_method: 'client_secret_post',
        tenant_id: ' tenant-1 ',
        client_id: ' client-1 ',
        redirect_uri: ' https://app.example.com/cb ',
        scope: ' openid ',
        domains: [' Example.COM '],
      });
      const res = mockRes();
      const next = jest.fn();
      testConnection.mockResolvedValue({
        success: true,
        data: {
          sessionRef: 'session-ref-1',
          config: { client_id: 'client-1' },
          _internal: { secret: 'keep-server-side' },
        },
      });

      await handleTestConnection(req, res, next);

      expect(testConnection).toHaveBeenCalledWith(expect.objectContaining({
        protocol: 'oidc',
        tenant_id: 'tenant-1',
        client_id: 'client-1',
        redirect_uri: 'https://app.example.com/cb',
        scope: 'openid',
        domains: 'example.com',
      }));
      expect(tcStore.set).toHaveBeenCalledWith('session-ref-1', { secret: 'keep-server-side' });
      expect(auditTestConnection).toHaveBeenCalledWith('1.2.3.4', 'oidc', true);
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json.mock.calls[0][0].data._internal).toBeUndefined();
      expect(next).not.toHaveBeenCalled();
    });

    test('does not store anything when the test fails', async () => {
      testConnection.mockResolvedValue({ success: false, message: 'invalid_client: bad secret' });
      const res = mockRes();

      await handleTestConnection(mockReq({ protocol: 'oidc', tenant_id: 'tenant-1' }), res, jest.fn());

      expect(tcStore.set).not.toHaveBeenCalled();
      expect(auditTestConnection).toHaveBeenCalledWith('1.2.3.4', 'oidc', false);
      expect(res.json).toHaveBeenCalledWith({ success: false, message: 'invalid_client: bad secret' });
    });

    test('loads the saved client certificate when use_existing_cert is set without one', async () => {
      getOidcConfig.mockResolvedValue({ client_cert_enc: 'stored-cert', client_cert_thumbprint: 'thumb' });

      await handleTestConnection(mockReq({
        protocol: 'oidc', tenant_id: 'tenant-1', use_existing_cert: true, company_id: 'company-1',
      }), mockRes(), jest.fn());

      expect(getOidcConfig).toHaveBeenCalledWith('company-1');
      expect(testConnection).toHaveBeenCalledWith(expect.objectContaining({ certificate: 'stored-cert' }));
    });
  });

  describe('SAML', () => {
    const samlBody = {
      protocol: 'saml',
      sso_url: ` ${SSO_URL} `,
      app_id: ' app-1 ',
      client_secret: 'secret',
      entity_id: 'https://sp.example.com/metadata',
      acs_url: 'https://sp.example.com/callback',
      certificate: 'cert-b64',
      company_id: 'company-1',
      sign_authn_request: true,
      signing_certificate: 'pfx-b64',
      signing_certificate_password: 'pw',
      use_existing_signing_cert: false,
    };

    test('passes every SAML field through to the service', async () => {
      await handleTestConnection(mockReq(samlBody), mockRes(), jest.fn());

      expect(testConnection).toHaveBeenCalledWith(expect.objectContaining({
        protocol: 'saml',
        sso_url: SSO_URL,
        app_id: 'app-1',
        client_secret: 'secret',
        entity_id: 'https://sp.example.com/metadata',
        acs_url: 'https://sp.example.com/callback',
        certificate: 'cert-b64',
        company_id: 'company-1',
        sign_authn_request: true,
        signing_certificate: 'pfx-b64',
        signing_certificate_password: 'pw',
        use_existing_signing_cert: false,
      }));
    });

    test('returns the popup redirectUrl and sessionRef untouched and stores nothing in tcStore', async () => {
      const data = { protocol: 'saml', sessionRef: 'ref-1', redirectUrl: 'https://login.microsoftonline.com/x/saml2?SAMLRequest=abc' };
      testConnection.mockResolvedValue({ success: true, message: 'ok', data });
      const res = mockRes();

      await handleTestConnection(mockReq(samlBody), res, jest.fn());

      expect(tcStore.set).not.toHaveBeenCalled();
      expect(auditTestConnection).toHaveBeenCalledWith('1.2.3.4', 'saml', true);
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({ success: true, message: 'ok', data });
    });

    test('loads the saved IdP certificate when use_existing_cert is set without one', async () => {
      getSamlConfig.mockResolvedValue({ certificate: 'stored-idp-cert' });

      await handleTestConnection(mockReq({
        ...samlBody, certificate: undefined, use_existing_cert: true,
      }), mockRes(), jest.fn());

      expect(getSamlConfig).toHaveBeenCalledWith('company-1');
      expect(testConnection).toHaveBeenCalledWith(expect.objectContaining({ certificate: 'stored-idp-cert' }));
    });

    test('keeps an uploaded certificate even when use_existing_cert is set', async () => {
      await handleTestConnection(mockReq({ ...samlBody, use_existing_cert: true }), mockRes(), jest.fn());

      expect(getSamlConfig).not.toHaveBeenCalled();
      expect(testConnection).toHaveBeenCalledWith(expect.objectContaining({ certificate: 'cert-b64' }));
    });

    test('passes undefined when no saved certificate exists', async () => {
      getSamlConfig.mockResolvedValue(null);

      await handleTestConnection(mockReq({
        ...samlBody, certificate: undefined, use_existing_cert: true,
      }), mockRes(), jest.fn());

      expect(testConnection).toHaveBeenCalledWith(expect.objectContaining({ certificate: undefined }));
    });
  });

  test('passes service errors to next', async () => {
    const err = new Error('connection failed');
    testConnection.mockRejectedValue(err);
    const next = jest.fn();

    await handleTestConnection(mockReq({ protocol: 'oidc', tenant_id: 'tenant-1' }), mockRes(), next);

    expect(next).toHaveBeenCalledWith(err);
  });
});
