jest.mock('../src/services/domainConnector.service', () => ({
  buildDomainConsentUrl: jest.fn(),
  getDomainConnectorToken: jest.fn(),
  getTenantDomains: jest.fn(),
}));

jest.mock('../src/config/logger', () => ({
  logger: { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const {
  buildDomainConsentUrl,
  getDomainConnectorToken,
  getTenantDomains,
} = require('../src/services/domainConnector.service');
const { logger } = require('../src/config/logger');
const { createSsoError } = require('../src/utils/shared/responseHandler');
const {
  handleGetDomainConsentUrl,
  handleDomainConsentStatus,
} = require('../src/controllers/domainConnector.controller');

const TENANT = '11111111-2222-3333-4444-555555555555';

const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('domainConnector.controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('handleGetDomainConsentUrl', () => {
    test('returns the consent link', () => {
      buildDomainConsentUrl.mockReturnValue('https://login.microsoftonline.com/t/adminconsent?client_id=c');
      const res = mockRes();

      handleGetDomainConsentUrl({ query: { tenantId: TENANT } }, res);

      expect(buildDomainConsentUrl).toHaveBeenCalledWith(TENANT);
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        success: true,
        data: { consentUrl: 'https://login.microsoftonline.com/t/adminconsent?client_id=c' },
      });
    });

    test('answers 400 for an invalid tenantId', () => {
      buildDomainConsentUrl.mockImplementation(() => {
        throw createSsoError('SSO_TENANT_ID_INVALID', 'tenantId must be a valid Entra tenant ID.', 400);
      });
      const res = mockRes();

      handleGetDomainConsentUrl({ query: { tenantId: 'bad' } }, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ success: false, message: 'tenantId must be a valid Entra tenant ID.' });
    });
  });

  describe('handleDomainConsentStatus', () => {
    test('answers 400 when tenantId is missing', async () => {
      const res = mockRes();

      await handleDomainConsentStatus({ query: {} }, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ success: false, message: 'tenantId is required' });
      expect(getDomainConnectorToken).not.toHaveBeenCalled();
    });

    test('reports consent and the verified domains', async () => {
      getDomainConnectorToken.mockResolvedValue('graph-token');
      getTenantDomains.mockResolvedValue(['contoso.com']);
      const res = mockRes();

      await handleDomainConsentStatus({ query: { tenantId: TENANT } }, res);

      expect(getTenantDomains).toHaveBeenCalledWith('graph-token');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        success: true,
        data: { consentGranted: true, domains: ['contoso.com'] },
      });
      expect(JSON.stringify(logger.info.mock.calls)).not.toContain('graph-token');
    });

    test('reports no consent when the token cannot be issued', async () => {
      getDomainConnectorToken.mockRejectedValue(
        createSsoError('DOMAIN_CONNECTOR_TOKEN_FAILED', 'Unable to get a Microsoft Graph token for this tenant.', 502),
      );
      const res = mockRes();

      await handleDomainConsentStatus({ query: { tenantId: TENANT } }, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({ success: true, data: { consentGranted: false, domains: [] } });
      expect(logger.error).toHaveBeenCalledWith('[DOMAIN_CONNECTOR] Domain consent status failed', expect.objectContaining({
        code: 'DOMAIN_CONNECTOR_TOKEN_FAILED',
      }));
    });

    test('reports no consent when Graph cannot be read', async () => {
      getDomainConnectorToken.mockResolvedValue('graph-token');
      getTenantDomains.mockRejectedValue(
        createSsoError('DOMAIN_CONNECTOR_GRAPH_FAILED', 'Unable to read the tenant domains from Microsoft Graph.', 502),
      );
      const res = mockRes();

      await handleDomainConsentStatus({ query: { tenantId: TENANT } }, res);

      expect(res.json).toHaveBeenCalledWith({ success: true, data: { consentGranted: false, domains: [] } });
    });

    test('answers 400 for an invalid tenantId', async () => {
      getDomainConnectorToken.mockRejectedValue(
        createSsoError('SSO_TENANT_ID_INVALID', 'tenantId must be a valid Entra tenant ID.', 400),
      );
      const res = mockRes();

      await handleDomainConsentStatus({ query: { tenantId: 'common/../x' } }, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ success: false, message: 'tenantId must be a valid Entra tenant ID.' });
      expect(logger.error).not.toHaveBeenCalled();
    });
  });
});
