jest.mock('../src/services/SSO/saveSsoConfig.service', () => ({
  saveSsoConfig: jest.fn(),
}));

jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/services/audit/audit.service', () => ({
  auditSsoConfigSaved: jest.fn(),
}));

jest.mock('../src/services/db/ssoDataService', () => ({
  getSsoIntegrationByEntraTenantId: jest.fn(),
  getDomainsByCompanyId: jest.fn(),
}));

const { handleSaveSsoConfig } = require('../src/controllers/saveSsoConfig.controller');
const { saveSsoConfig } = require('../src/services/SSO/saveSsoConfig.service');
const { auditSsoConfigSaved } = require('../src/services/audit/audit.service');

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

describe('saveSsoConfig.controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('normalizes fields, saves config, audits it, and returns 201', async () => {
    const req = mockReq({
      protocol: 'oidc',
      idp: 'microsoft_entra',
      domains: [' Example.COM ', 'example.com', null, 'ANOTHER.com '], // Test casing, trimming, deduplication, and filters
      tenant_id: ' tenant-1 ',
      company_id: ' owner-1 ',
      client_id: ' client-1 ',
      auth_method: 'client_secret_post',
      client_secret: 'secret-1',
      redirect_uri: ' http://localhost:3000/auth/oidc/callback ',
      jit_enabled: true,
      jit_mappings: [{ mapping_source: 'default', zdna_role: 'role-admin' }],
      existing_sso_status: 'active', // Evaluates rawStatus === 'active' -> true
    });
    const res = mockRes();
    const next = jest.fn();
    saveSsoConfig.mockResolvedValue({ success: true, company_id: 'company-1' });

    await handleSaveSsoConfig(req, res, next);

    expect(saveSsoConfig).toHaveBeenCalledWith(expect.objectContaining({
      domains: ['example.com', 'another.com'],
      tenant_id: 'tenant-1',
      company_id: 'owner-1',
      client_id: 'client-1',
      redirect_uri: 'http://localhost:3000/auth/oidc/callback',
      existing_sso_status: true,
    }));
    expect(auditSsoConfigSaved).toHaveBeenCalledWith('company-1', null, '1.2.3.4', 'oidc');
    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({ success: true, company_id: 'company-1' });
    expect(next).not.toHaveBeenCalled();
  });

  test('handles domains passed as a single string instead of an array', async () => {
    const req = mockReq({
      protocol: 'saml',
      domains: ' SingleDomain.com ', // Single string test path
    });
    const res = mockRes();
    const next = jest.fn();
    saveSsoConfig.mockResolvedValue({ success: true, company_id: 'company-1' });

    await handleSaveSsoConfig(req, res, next);

    expect(saveSsoConfig).toHaveBeenCalledWith(expect.objectContaining({
      domains: ['singledomain.com'],
    }));
  });

  test('handles domains when omitted or null', async () => {
    const req = mockReq({
      protocol: 'saml',
      domains: null, // Null value test path
    });
    const res = mockRes();
    const next = jest.fn();
    saveSsoConfig.mockResolvedValue({ success: true, company_id: 'company-1' });

    await handleSaveSsoConfig(req, res, next);

    expect(saveSsoConfig).toHaveBeenCalledWith(expect.objectContaining({
      domains: [],
    }));
  });

  test('handles trimStr when value is not a string (e.g. object or boolean)', async () => {
    const req = mockReq({
      protocol: 'oidc',
      tenant_id: 12345, // Number triggers trimStr non-string branch
      client_id: true,  // Boolean triggers trimStr non-string branch
    });
    const res = mockRes();
    const next = jest.fn();
    saveSsoConfig.mockResolvedValue({ success: true, company_id: 'company-1' });

    await handleSaveSsoConfig(req, res, next);

    expect(saveSsoConfig).toHaveBeenCalledWith(expect.objectContaining({
      tenant_id: 12345,
      client_id: true,
    }));
  });

  test('evaluates existing_sso_status as false when status is not "active"', async () => {
    const req = mockReq({
      existing_sso_status: 'inactive', // Evaluates rawStatus === 'active' -> false
    });
    const res = mockRes();
    const next = jest.fn();
    saveSsoConfig.mockResolvedValue({ success: true, company_id: 'company-1' });

    await handleSaveSsoConfig(req, res, next);

    expect(saveSsoConfig).toHaveBeenCalledWith(expect.objectContaining({
      existing_sso_status: false,
    }));
  });

  test('defaults existing_sso_status to true when raw status parameter is entirely omitted', async () => {
    const req = mockReq({}); // Omitted raw status
    const res = mockRes();
    const next = jest.fn();
    saveSsoConfig.mockResolvedValue({ success: true, company_id: 'company-1' });

    await handleSaveSsoConfig(req, res, next);

    expect(saveSsoConfig).toHaveBeenCalledWith(expect.objectContaining({
      existing_sso_status: true,
    }));
  });

  test('evaluates jit_enabled utilizing fallback jit_status values', async () => {
    const req = mockReq({
      jit_status: true, // Fallback parameter test path
    });
    const res = mockRes();
    const next = jest.fn();
    saveSsoConfig.mockResolvedValue({ success: true, company_id: 'company-1' });

    await handleSaveSsoConfig(req, res, next);

    expect(saveSsoConfig).toHaveBeenCalledWith(expect.objectContaining({
      jit_enabled: true,
    }));
  });

  test('defaults jit_enabled to false when both jit parameters are missing', async () => {
    const req = mockReq({}); // both parameters omitted
    const res = mockRes();
    const next = jest.fn();
    saveSsoConfig.mockResolvedValue({ success: true, company_id: 'company-1' });

    await handleSaveSsoConfig(req, res, next);

    expect(saveSsoConfig).toHaveBeenCalledWith(expect.objectContaining({
      jit_enabled: false,
    }));
  });

  test('passes service errors to next middleware', async () => {
    const req = mockReq({ protocol: 'oidc', domains: ['example.com'] });
    const res = mockRes();
    const next = jest.fn();
    const err = Object.assign(new Error('save failed'), { code: 'SAVE_FAIL' });
    saveSsoConfig.mockRejectedValue(err);

    await handleSaveSsoConfig(req, res, next);

    expect(next).toHaveBeenCalledWith(err);
  });
});
