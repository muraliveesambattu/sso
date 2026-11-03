const { getEntraClaimsCatalog, buildAdminConsentUrl } = require('../services/SSO/entraClaimsCatalog.service');
const { validateTenantOwnership } = require('../services/SSO/testConnection.service');
const { logger } = require('../config/logger');

const trimStr = (v) => (typeof v === 'string' ? v.trim() : v);

// Same tenant as the catalog service reads: SAML carries it in the SSO URL.
const tenantOf = ({ protocol, tenant_id, sso_url }) =>
  (protocol === 'saml' && sso_url?.match(/login\.microsoftonline\.com\/([0-9a-f-]{36})\//i)?.[1]) || tenant_id;

const readConfig = (src) => ({
  protocol:  trimStr(src.protocol),
  tenant_id: trimStr(src.tenant_id),
  client_id: trimStr(src.client_id),
  sso_url:   trimStr(src.sso_url),
  entity_id: trimStr(src.entity_id),
});

// A tenant registered by another organisation is theirs — its app roles and
// groups must not be readable by anyone else.
const assertTenantOwner = async (config, company_id) => {
  const conflict = await validateTenantOwnership(tenantOf(config), company_id);
  if (conflict) {
    throw Object.assign(new Error(conflict.message), { statusCode: 409, code: 'TENANT_ALREADY_REGISTERED' });
  }
};

/**
 * POST /sso/entra-claims
 * Body: { company_id, protocol, tenant_id?, client_id?, sso_url?, entity_id? }
 * Returns the claim names, app roles and assigned groups of the customer's SSO app.
 */
const handleGetEntraClaims = async (req, res, next) => {
  try {
    const config = readConfig(req.body || {});
    const company_id = req.user?.companyId || trimStr(req.body?.company_id) || null;
    await assertTenantOwner(config, company_id);
    const catalog = await getEntraClaimsCatalog(config);
    return res.status(200).json({ success: true, data: catalog });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /sso/entra-connector/consent-url?company_id&protocol&tenant_id|sso_url
 * Returns the admin consent link for the ZDNA connector app in the customer's tenant.
 */
const handleGetConsentUrl = async (req, res, next) => {
  try {
    const config = readConfig(req.query || {});
    const company_id = req.user?.companyId || trimStr(req.query?.company_id) || null;
    await assertTenantOwner(config, company_id);
    return res.status(200).json({ success: true, data: { url: buildAdminConsentUrl(config) } });
  } catch (err) {
    next(err);
  }
};

// Plain page for the consent popup — no script, no console redirect.
const consentPage = (ok) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ZDNA connector</title></head>
<body style="font-family:sans-serif;padding:32px">
<p>${ok
    ? 'Microsoft Entra is connected to ZDNA. You can close this window.'
    : 'Microsoft Entra was not connected. Close this window and ask your Microsoft Entra administrator to approve the ZDNA connector.'}</p>
</body></html>`;

/**
 * GET /entra-connector/callback
 * Entra sends the admin here after the consent screen (opened from the link
 * support shares; see GET /sso/entra-connector/consent-url). Consent is
 * recorded by Microsoft, so nothing is stored here.
 */
const handleConnectorCallback = (req, res) => {
  const ok = String(req.query?.admin_consent).toLowerCase() === 'true' && !req.query?.error;
  if (ok) {
    logger.info('[ENTRA_CONNECTOR] Admin consent granted', { action: 'entra_connector_consent' });
  } else {
    logger.warn('[ENTRA_CONNECTOR] Admin consent not granted', {
      action: 'entra_connector_consent_failed',
      error: req.query?.error || null,
    });
  }
  return res.status(ok ? 200 : 400).type('html').send(consentPage(ok));
};

module.exports = { handleGetEntraClaims, handleGetConsentUrl, handleConnectorCallback };
