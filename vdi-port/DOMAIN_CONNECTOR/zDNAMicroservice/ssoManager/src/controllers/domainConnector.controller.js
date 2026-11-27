const {
  buildDomainConsentUrl, getDomainConnectorToken, getTenantDomains,
} = require('../services/domainConnector.service');
const { logger } = require('../config/logger');
const { maskInput } = require('../utils/shared/maskId.util');

// GET /domain-consent-url?tenantId=...
// Admin consent link for the domain connector app in the customer's tenant.
const handleGetDomainConsentUrl = (req, res) => {
  const { tenantId } = req.query;
  try {
    const consentUrl = buildDomainConsentUrl(tenantId);
    return res.status(200).json({ success: true, data: { consentUrl } });
  } catch (error) {
    return res.status(error.statusCode || 400).json({ success: false, message: error.message });
  }
};

// GET /domain-consent-status?tenantId=...
// consentGranted is true once a Graph token can be issued for the tenant; domains
// are the tenant's verified domains. Any failure means "not consented yet".
const handleDomainConsentStatus = async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) {
    return res.status(400).json({ success: false, message: 'tenantId is required' });
  }

  try {
    const accessToken = await getDomainConnectorToken(tenantId);
    const domains = await getTenantDomains(accessToken);
    logger.info('[DOMAIN_CONNECTOR] Domain consent status', {
      tenantIdMasked: maskInput(String(tenantId)),
      consentGranted: true,
      domainCount: domains.length,
    });
    return res.status(200).json({ success: true, data: { consentGranted: true, domains } });
  } catch (error) {
    if (error.code === 'SSO_TENANT_ID_INVALID') {
      return res.status(400).json({ success: false, message: error.message });
    }
    logger.error('[DOMAIN_CONNECTOR] Domain consent status failed', {
      tenantIdMasked: maskInput(String(tenantId)),
      code: error.code,
      error: error.message,
    });
    return res.status(200).json({ success: true, data: { consentGranted: false, domains: [] } });
  }
};

module.exports = {
  handleGetDomainConsentUrl,
  handleDomainConsentStatus,
};
