jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));
jest.mock('../src/services/SSO/entraClaimsCatalog.service', () => ({
  getEntraClaimsCatalog: jest.fn(),
  buildAdminConsentUrl: jest.fn(),
}));
jest.mock('../src/services/SSO/testConnection.service', () => ({
  validateTenantOwnership: jest.fn(),
}));

const { getEntraClaimsCatalog, buildAdminConsentUrl } = require('../src/services/SSO/entraClaimsCatalog.service');
const { validateTenantOwnership } = require('../src/services/SSO/testConnection.service');
const {
  handleGetEntraClaims,
  handleGetConsentUrl,
  handleConnectorCallback,
} = require('../src/controllers/entraConnector.controller');

const TENANT = '72f988bf-86f1-41af-91ab-2d7cd011db47';

const mockRes = () => {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn(() => res);
  res.type = jest.fn(() => res);
  res.send = jest.fn(() => res);
  return res;
};

describe('entraConnector.controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    validateTenantOwnership.mockResolvedValue(null);
  });

  test('returns the catalog for the caller company', async () => {
    const catalog = { claimNames: ['role'], roles: ['Zebra.Admin'], groups: [] };
    getEntraClaimsCatalog.mockResolvedValue(catalog);
    const res = mockRes();
    const next = jest.fn();

    await handleGetEntraClaims({
      user: { companyId: 'company-1' },
      body: { protocol: 'oidc', tenant_id: ` ${TENANT} `, client_id: 'client-1', company_id: 'ignored' },
    }, res, next);

    expect(validateTenantOwnership).toHaveBeenCalledWith(TENANT, 'company-1');
    expect(getEntraClaimsCatalog).toHaveBeenCalledWith(expect.objectContaining({ protocol: 'oidc', tenant_id: TENANT, client_id: 'client-1' }));
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({ success: true, data: catalog });
    expect(next).not.toHaveBeenCalled();
  });

  test('checks ownership of the SAML tenant taken from the SSO URL', async () => {
    getEntraClaimsCatalog.mockResolvedValue({});
    await handleGetEntraClaims({
      body: { protocol: 'saml', sso_url: `https://login.microsoftonline.com/${TENANT}/saml2`, company_id: 'company-1' },
    }, mockRes(), jest.fn());
    expect(validateTenantOwnership).toHaveBeenCalledWith(TENANT, 'company-1');
  });

  test("refuses another organisation's tenant without calling Microsoft", async () => {
    validateTenantOwnership.mockResolvedValue({ success: false, message: 'already registered' });
    const next = jest.fn();
    await handleGetEntraClaims({ body: { protocol: 'oidc', tenant_id: TENANT, company_id: 'company-2' } }, mockRes(), next);
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 409, code: 'TENANT_ALREADY_REGISTERED' }));
    expect(getEntraClaimsCatalog).not.toHaveBeenCalled();
  });

  test('passes catalog errors to the error handler', async () => {
    const err = Object.assign(new Error('no consent'), { statusCode: 403, code: 'ENTRA_CONNECTOR_NOT_CONSENTED' });
    getEntraClaimsCatalog.mockRejectedValue(err);
    const next = jest.fn();
    await handleGetEntraClaims({ body: { protocol: 'oidc', tenant_id: TENANT } }, mockRes(), next);
    expect(next).toHaveBeenCalledWith(err);
  });

  test('returns the admin consent link', async () => {
    buildAdminConsentUrl.mockReturnValue('https://login.microsoftonline.com/x/v2.0/adminconsent?client_id=c');
    const res = mockRes();
    await handleGetConsentUrl({ query: { protocol: 'oidc', tenant_id: TENANT, company_id: 'company-1' } }, res, jest.fn());
    expect(validateTenantOwnership).toHaveBeenCalledWith(TENANT, 'company-1');
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      data: { url: 'https://login.microsoftonline.com/x/v2.0/adminconsent?client_id=c' },
    });
  });

  test('answers the consent popup with a plain page', () => {
    const ok = mockRes();
    handleConnectorCallback({ query: { admin_consent: 'True', tenant: TENANT } }, ok);
    expect(ok.status).toHaveBeenCalledWith(200);
    expect(ok.type).toHaveBeenCalledWith('html');
    expect(ok.send).toHaveBeenCalledWith(expect.stringContaining('You can close this window'));
    expect(ok.send).toHaveBeenCalledWith(expect.not.stringContaining('<script'));

    const declined = mockRes();
    handleConnectorCallback({ query: { error: 'access_denied' } }, declined);
    expect(declined.status).toHaveBeenCalledWith(400);
    expect(declined.send).toHaveBeenCalledWith(expect.stringContaining('was not connected'));
  });
});
