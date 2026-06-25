const { saveSsoConfig }      = require('../services/SSO/saveSsoConfig.service');
const { logger }             = require('../config/logger');
const { auditSsoConfigSaved } = require('../services/audit/audit.service');

// Trim identifier fields so stray copy-paste whitespace can't corrupt the
// stored tenant_id / client_id / domain (which break issuer/audience checks
// and create duplicate rows that differ only by a space).
const t = (v) => (typeof v === 'string' ? v.trim() : v);

// The frontend sends `domains` as an array (e.g. ["zebra.com"]); the backend
// works with a single domain string. Take the first entry when it's an array.
const firstDomain = (v) => (Array.isArray(v) ? v[0] : v);

const handleSaveSsoConfig = async (req, res, next) => {
  try {
    const {
      protocol, idp, auth_method, client_secret,
      certificate, certificate_password, jit_enabled, jit_mappings,
    } = req.body;
    const domains      = t(firstDomain(req.body.domains))?.toLowerCase();
    const tenant_id    = t(req.body.tenant_id);
    const client_id    = t(req.body.client_id);
    const redirect_uri = t(req.body.redirect_uri);
    const sso_url      = t(req.body.sso_url);
    const entity_id    = t(req.body.entity_id);   // SAML — SP entity / identifier
    const acs_url      = t(req.body.acs_url);      // SAML — assertion consumer service URL
    const owner_tenant_id    = t(req.body.owner_tenant_id);     // admin who configured this SSO
    const owner_company_name = t(req.body.owner_company_name);  // their company name

    logger.info('Save SSO config request', { action: 'sso_save', protocol, domains, jit_enabled, ip: req.ip });

    const result = await saveSsoConfig({
      protocol, idp, domains, tenant_id,
      owner_tenant_id, owner_company_name,
      client_id, auth_method, client_secret, redirect_uri,
      sso_url, entity_id, acs_url, certificate, certificate_password, jit_enabled, jit_mappings,
    });

    // Audit log — who saved the config, from which IP
    await auditSsoConfigSaved(result.company_id, null, req.ip, protocol);

    logger.info('SSO config saved', { action: 'sso_save_success', company_id: result.company_id });

    return res.status(201).json(result);
  } catch (err) {
    next(err);
  }
};

module.exports = { handleSaveSsoConfig };
