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

jest.mock('../src/services/db/postgresSSO.service', () => ({
  getOidcConfig: jest.fn(),
  getSamlConfig: jest.fn(),
}));

const { handleTestConnection } = require('../src/controllers/testConnection.controller');
const { testConnection, validateSsoConfiguration } = require('../src/services/SSO/testConnection.service');
const { auditTestConnection } = require('../src/services/audit/audit.service');
const tcStore = require('../src/utils/shared/testConnectionStore');
const { getOidcConfig, getSamlConfig } = require('../src/services/db/postgresSSO.service');
const { logger } = require('../src/config/logger');

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

describe('testConnection.controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // =========================================================================
  // Existing Tests (Preserved)
  // =========================================================================

  test('returns 400 when protocol is missing', async () => {
    const res = mockRes();

    await handleTestConnection(mockReq({}), res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ success: false, message: 'protocol is required' });
  });

  test('returns 400 for missing required tenant or SAML location fields', async () => {
    const res1 = mockRes();
    await handleTestConnection(mockReq({ protocol: 'oidc' }), res1, jest.fn());
    expect(res1.status).toHaveBeenCalledWith(400);

    const res2 = mockRes();
    await handleTestConnection(mockReq({ protocol: 'saml' }), res2, jest.fn());
    expect(res2.status).toHaveBeenCalledWith(400);
  });

  test('stores internal OIDC test state, strips it from the response, audits, and returns 200', async () => {
    const req = mockReq({
      protocol: 'oidc',
      auth_method: 'client_secret_post',
      tenant_id: ' tenant-1 ',
      client_id: ' client-1 ',
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
      domains: 'example.com',
    }));
    expect(tcStore.set).toHaveBeenCalledWith('session-ref-1', { secret: 'keep-server-side' });
    expect(auditTestConnection).toHaveBeenCalledWith('1.2.3.4', 'oidc', true);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json.mock.calls[0][0].data._internal).toBeUndefined();
    expect(next).not.toHaveBeenCalled();
  });

  test('passes service errors to next', async () => {
    const req = mockReq({ protocol: 'oidc', tenant_id: 'tenant-1' });
    const res = mockRes();
    const next = jest.fn();
    const err = new Error('connection failed');
    testConnection.mockRejectedValue(err);

    await handleTestConnection(req, res, next);

    expect(next).toHaveBeenCalledWith(err);
  });

  // =========================================================================
  // Additional Coverage Tests (Pushes coverage to >90%)
  // =========================================================================

  test('handles existing test connection flows with handleTestConnection (is_existing_test)', async () => {
    const req = mockReq({ is_existing_test: true, company_id: 'company-xyz' });
    const res = mockRes();
    const next = jest.fn();
    
    validateSsoConfiguration.mockResolvedValue({ success: true, message: 'Valid config' });

    await handleTestConnection(req, res, next);

    expect(validateSsoConfiguration).toHaveBeenCalledWith('company-xyz');
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ success: true, message: 'Valid config' });
    expect(logger.info).toHaveBeenCalledWith("Test connection result", {
      action: "test_connection_result",
      success: true,
    });
  });

  test('retrieves existing SAML certificate when use_existing_cert is true', async () => {
    const req = mockReq({
      protocol: 'saml',
      sso_url: 'https://saml.example.com',
      company_id: 'company-saml',
      use_existing_cert: true,
    });
    const res = mockRes();
    
    getSamlConfig.mockResolvedValue({ certificate: 'existing-saml-cert-data' });
    testConnection.mockResolvedValue({ success: true });

    await handleTestConnection(req, res, jest.fn());

    expect(getSamlConfig).toHaveBeenCalledWith('company-saml');
    expect(testConnection).toHaveBeenCalledWith(expect.objectContaining({
      certificate: 'existing-saml-cert-data',
    }));
  });

  test('retrieves existing OIDC certificate when use_existing_cert is true and triggers debug logs', async () => {
    const req = mockReq({
      protocol: 'oidc',
      tenant_id: 'tenant-oidc',
      company_id: 'company-oidc',
      use_existing_cert: true,
    });
    const res = mockRes();
    
    getOidcConfig.mockResolvedValue({
      client_cert_enc: 'existing-oidc-cert-data',
      private_key_enc: 'private-key-data',
      client_cert_thumbprint: 'thumbprint-data',
    });
    testConnection.mockResolvedValue({ success: true });

    await handleTestConnection(req, res, jest.fn());

    expect(getOidcConfig).toHaveBeenCalledWith('company-oidc');
    expect(logger.debug).toHaveBeenCalledWith('OIDC existing certificate lookup', {
      hasClientCert: true,
      hasPrivateKey: true,
      hasThumbprint: true,
    });
    expect(testConnection).toHaveBeenCalledWith(expect.objectContaining({
      certificate: 'existing-oidc-cert-data',
    }));
  });

  test('runs successfully if SAML protocol provides sso_url without tenant_id', async () => {
    const req = mockReq({
      protocol: 'saml',
      sso_url: 'https://saml.example.com',
    });
    const res = mockRes();
    testConnection.mockResolvedValue({ success: true });

    await handleTestConnection(req, res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(200);
    expect(testConnection).toHaveBeenCalled();
  });

  test('should NOT store session if result.success is false or missing internal variables', async () => {
    const req = mockReq({
      protocol: 'oidc',
      tenant_id: 'tenant-oidc',
    });
    const res = mockRes();
    
    // Scenario 1: result.success is false
    testConnection.mockResolvedValueOnce({
      success: false,
      data: {
        sessionRef: 'ref-1',
        _internal: { secret: 'data' },
      }
    });

    await handleTestConnection(req, res, jest.fn());
    expect(tcStore.set).not.toHaveBeenCalled();

    // Scenario 2: internal values are missing from response
    testConnection.mockResolvedValueOnce({
      success: true,
      data: {
        sessionRef: 'ref-1', // no _internal field
      }
    });

    await handleTestConnection(req, res, jest.fn());
    expect(tcStore.set).not.toHaveBeenCalled();
  });
});
