/**
 * SSO Admin Controller
 *
 * CRUD-style admin endpoints for managing SSO configuration.
 * Backed by ssoDataService (PostgreSQL).
 *
 * All endpoints require X-Admin-API-Key (enforced at the router).
 *
 *   GET    /sso/config?company_id=...  or  ?domain=...   → retrieve config
 *   PATCH  /sso/config/:company_id/status               → activate / deactivate
 *   (POST  /sso/save — already exists in saveSsoConfig.controller.js)
 */

const ssoDataService = require('../services/db/ssoDataService');
const { logger }     = require('../config/logger');

// GET /sso/config?company_id=xxx  or  /sso/config?domain=zebra.com
const handleGetSsoConfig = async (req, res, next) => {
  // Personalised, frequently-changing config — never let a CDN/browser cache
  // this (Firebase Hosting's default caching otherwise applies its own
  // max-age when the origin doesn't set anything, which can serve a stale
  // 404/old config for minutes after a fix or a fresh save).
  res.set('Cache-Control', 'no-store');
  try {
    let { company_id, domain, owner_tenant_id } = req.query;

    // Bearer-token callers (req.user set by userAuth.middleware) always get
    // their OWN company's config — ?domain= / ?owner_tenant_id= would
    // otherwise bypass the company_id scope check.
    if (req.user?.companyId) {
      company_id      = req.user.companyId;
      domain          = undefined;
      owner_tenant_id = undefined;
    }

    if (!company_id && !domain && !owner_tenant_id) {
      return res.status(400).json({
        success: false,
        message: 'Provide company_id, domain, or owner_tenant_id as a query parameter',
      });
    }

    logger.info('Admin: get SSO config', { action: 'admin_get_config', company_id, domain, owner_tenant_id });

    const config = await ssoDataService.getSsoConfigDetails({ company_id, domain, owner_tenant_id });

    if (!config) {
      return res.status(404).json({
        success: false,
        message: 'No SSO configuration found for the given company_id, domain, or owner_tenant_id',
      });
    }

    return res.status(200).json({ success: true, data: config });
  } catch (err) {
    logger.error('Admin: get SSO config failed', { action: 'admin_get_config_error', error: err.message });
    next(err);
  }
};

// PATCH /sso/config/:company_id/status   body: { status: "active" | "inactive" }
const handleSetSsoStatus = async (req, res, next) => {
  try {
    const { company_id } = req.params;
    const { status }     = req.body;

    if (!['active', 'inactive'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "status must be 'active' or 'inactive'",
      });
    }

    logger.info('Admin: set SSO status', { action: 'admin_set_status', company_id, status });

    const updated = await ssoDataService.setSsoStatus(company_id, status);

    if (!updated) {
      return res.status(404).json({
        success: false,
        message: `No SSO integration found for company_id: ${company_id}`,
      });
    }

    // Drop cached domain lookups so the change takes effect immediately
    const config = await ssoDataService.getSsoConfigDetails({ company_id });
    if (config?.integration?.domains) {
      ssoDataService.invalidateDomainCache(config.integration.domains);
    }

    return res.status(200).json({
      success: true,
      message: `SSO ${status === 'active' ? 'activated' : 'deactivated'} for ${company_id}`,
      data:    { company_id, sso_status: status },
    });
  } catch (err) {
    logger.error('Admin: set SSO status failed', { action: 'admin_set_status_error', error: err.message });
    next(err);
  }
};

// DELETE /sso/config/:company_id — removes integration, OIDC/SAML config, JIT mappings
const handleDeleteSsoConfig = async (req, res, next) => {
  try {
    const { company_id } = req.params;

    // Capture the domain before deleting so we can invalidate its cache
    const config = await ssoDataService.getSsoConfigDetails({ company_id });
    if (!config) {
      return res.status(404).json({
        success: false,
        message: `No SSO integration found for company_id: ${company_id}`,
      });
    }

    logger.info('Admin: delete SSO config', { action: 'admin_delete_config', company_id });

    await ssoDataService.deleteSsoConfig(company_id);

    if (config.integration?.domains) {
      ssoDataService.invalidateDomainCache(config.integration.domains);
    }

    return res.status(200).json({
      success: true,
      message: `SSO configuration deleted for ${company_id}`,
      data:    { company_id, domain: config.integration?.domains },
    });
  } catch (err) {
    logger.error('Admin: delete SSO config failed', { action: 'admin_delete_config_error', error: err.message });
    next(err);
  }
};

module.exports = { handleGetSsoConfig, handleSetSsoStatus, handleDeleteSsoConfig };
