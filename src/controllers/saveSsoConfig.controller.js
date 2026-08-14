const { saveSsoConfig }      = require('../services/SSO/saveSsoConfig.service');
const { logger }             = require('../config/logger');
const { auditSsoConfigSaved } = require('../services/audit/audit.service');
const { getSsoIntegrationByEntraTenantId, getDomainsByCompanyId } = require('../services/db/ssoDataService');

// Trim identifier fields so stray copy-paste whitespace can't corrupt the
// stored tenant_id / client_id / domain (which break issuer/audience checks
// and create duplicate rows that differ only by a space).
const trimStr = (v) => (typeof v === 'string' ? v.trim() : v);

// The frontend sends `domains` as an array (e.g. ["zebra.com"]). Normalise to a
// trimmed, lowercased, de-duplicated array — a company may own many domains.
const toDomainArray = (v) => {
  let arr;
  if (Array.isArray(v)) arr = v;
  else arr = v == null ? [] : [v];
  return [...new Set(arr.map(d => trimStr(d)?.toLowerCase()).filter(Boolean))];
};

// Set equality helper for the tenant-conflict check below.
const sameDomainSet = (a, b) => a.length === b.length && a.every(d => b.includes(d));

const handleSaveSsoConfig = async (req, res, next) => {
  try {
    const {
      protocol, idp, auth_method, client_secret,
      certificate, certificate_password, jit_mappings,
      keep_existing_cert, sign_auth,
    } = req.body;

    // The console has shipped both spellings of this flag: `jit_status` (main
    // Save & Activate) and `jit_enabled` (the inline JIT-mappings save). Accept
    // either so a payload from any console build persists the same way.
    // `??` rather than `||` so an explicit `false` is honoured and not skipped.
    const jit_enabled = req.body.jit_enabled ?? req.body.jit_status;
    const domains      = toDomainArray(req.body.domains);
    const tenant_id    = trimStr(req.body.tenant_id);
    const client_id    = trimStr(req.body.client_id);
    const redirect_uri = trimStr(req.body.redirect_uri);
    const sso_url      = trimStr(req.body.sso_url);
    const entity_id    = trimStr(req.body.entity_id);   // SAML — SP entity / identifier
    const acs_url      = trimStr(req.body.acs_url);      // SAML — assertion consumer service URL
    const company_id   = trimStr(req.body.company_id);   // configuring admin's tenant id (sole owner key)

    // An Entra tenant may only be claimed by one organisation — reject if a
    // DIFFERENT org already registered it. The same org re-saving/editing its
    // own config with the same tenant_id is not a conflict. Compared against
    // the tenant's registered `domains` set rather than company_id: not every
    // save path includes company_id (e.g. the JIT-mappings-only quick save from
    // "Manage roles" may omit it), but the verified domains are always present
    // and are themselves the org's unique identity.
    if (tenant_id) {
      const existingTenant = await getSsoIntegrationByEntraTenantId(tenant_id);
      if (existingTenant) {
        const existingDomains = await getDomainsByCompanyId(existingTenant.company_id);
        if (!sameDomainSet(existingDomains, domains)) {
          throw Object.assign(
            new Error('This Microsoft Entra tenant ID is already registered by another organization.'),
            { statusCode: 409, code: 'TENANT_ALREADY_REGISTERED' }
          );
        }
      }
    }

    logger.info('Save SSO config request', { action: 'sso_save', protocol, domains, jit_enabled, ip: req.ip });

    const result = await saveSsoConfig({
      protocol, idp, domains, tenant_id, company_id,
      client_id, auth_method, client_secret, redirect_uri,
      sso_url, entity_id, acs_url, certificate, certificate_password,
      sign_auth, keep_existing_cert,
      jit_enabled, jit_mappings,
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
