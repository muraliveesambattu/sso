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
}));

const { handleSaveSsoConfig } = require('../src/controllers/saveSsoConfig.controller');
const { saveSsoConfig } = require('../src/services/SSO/saveSsoConfig.service');
const { auditSsoConfigSaved } = require('../src/services/audit/audit.service');
const { getSsoIntegrationByEntraTenantId } = require('../src/services/db/ssoDataService');

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
    getSsoIntegrationByEntraTenantId.mockResolvedValue(null); // no existing tenant by default
  });

  test('normalizes fields, saves config, audits it, and returns 201', async () => {
    const req = mockReq({
      protocol: 'oidc',
      idp: 'microsoft_entra',
      domains: [' Example.COM '],
      tenant_id: ' tenant-1 ',
      owner_tenant_id: ' owner-1 ',
      owner_company_name: ' Example Co ',
      client_id: ' client-1 ',
      auth_method: 'client_secret_post',
      client_secret: 'secret-1',
      redirect_uri: ' http://localhost:3000/auth/oidc/callback ',
      jit_enabled: true,
      jit_mappings: [{ mapping_source: 'default', zdna_role: 'role-admin' }],
    });
    const res = mockRes();
    const next = jest.fn();
    saveSsoConfig.mockResolvedValue({ success: true, company_id: 'company-1' });

    await handleSaveSsoConfig(req, res, next);

    expect(saveSsoConfig).toHaveBeenCalledWith(expect.objectContaining({
      domains: 'example.com',
      tenant_id: 'tenant-1',
      owner_tenant_id: 'owner-1',
      owner_company_name: 'Example Co',
      client_id: 'client-1',
      redirect_uri: 'http://localhost:3000/auth/oidc/callback',
    }));
    expect(auditSsoConfigSaved).toHaveBeenCalledWith('company-1', null, '1.2.3.4', 'oidc');
    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({ success: true, company_id: 'company-1' });
    expect(next).not.toHaveBeenCalled();
  });

  test('passes service errors to next', async () => {
    const req = mockReq({ protocol: 'oidc', domains: ['example.com'] });
    const res = mockRes();
    const next = jest.fn();
    const err = Object.assign(new Error('save failed'), { code: 'SAVE_FAIL' });
    saveSsoConfig.mockRejectedValue(err);

    await handleSaveSsoConfig(req, res, next);

    expect(next).toHaveBeenCalledWith(err);
  });

  test('rejects a tenant_id already registered by a different organisation', async () => {
    const req = mockReq({
      protocol: 'oidc',
      domains: ['example.com'],
      tenant_id: 'tenant-shared',
      owner_tenant_id: 'owner-new',
    });
    const res = mockRes();
    const next = jest.fn();
    getSsoIntegrationByEntraTenantId.mockResolvedValue({ domains: 'someone-else.com' });

    await handleSaveSsoConfig(req, res, next);

    expect(saveSsoConfig).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith(expect.objectContaining({
      statusCode: 409,
      code: 'TENANT_ALREADY_REGISTERED',
    }));
  });

  test('allows the same organisation to re-save its own config with the same tenant_id', async () => {
    const req = mockReq({
      protocol: 'oidc',
      domains: ['example.com'],
      tenant_id: 'tenant-shared',
      owner_tenant_id: 'owner-existing',
    });
    const res = mockRes();
    const next = jest.fn();
    getSsoIntegrationByEntraTenantId.mockResolvedValue({ domains: 'example.com' });
    saveSsoConfig.mockResolvedValue({ success: true, company_id: 'owner-existing' });

    await handleSaveSsoConfig(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(saveSsoConfig).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);
  });

  test('allows the JIT-mappings-only "Manage roles" quick save, which omits owner_tenant_id entirely', async () => {
    // Real bug hit on EMC: ActiveConfigView's "Manage roles" save path sends
    // protocol/domains/tenant_id/jit_mappings but no owner_tenant_id at all.
    // Comparing against owner_tenant_id/company_id treated `undefined` as a
    // mismatch and rejected every quick JIT edit. domains is always present
    // and is itself the org's unique identity, so compare on that instead.
    const req = mockReq({
      protocol: 'oidc',
      domains: ['abc.com'],
      tenant_id: '2c761afb-5a70-452a-ab62-b98b90a6e556',
      jit_enabled: true,
      jit_mappings: [
        { zdna_role: 'Admin', mapping_source: 'department', mapping_value: 'it', order: 1 },
        { zdna_role: 'Manager', mapping_source: 'department', mapping_value: 'sales', order: 2 },
      ],
    });
    const res = mockRes();
    const next = jest.fn();
    getSsoIntegrationByEntraTenantId.mockResolvedValue({
      company_id: 'noaq1xgCe5otm425Yhk3',
      domains: 'abc.com',
    });
    saveSsoConfig.mockResolvedValue({ success: true, company_id: 'noaq1xgCe5otm425Yhk3' });

    await handleSaveSsoConfig(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(saveSsoConfig).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);
  });
});
