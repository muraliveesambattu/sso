const { testConnection }      = require('../services/SSO/testConnection.service');
const { logger }              = require('../config/logger');
const { auditTestConnection } = require('../services/audit/audit.service');
const tcStore                 = require('../utils/shared/testConnectionStore');

// Trim identifier fields so a stray copy-paste space can't corrupt the
// Microsoft assertion (aud/iss), issuer validation, or domain lookups.
const t = (v) => (typeof v === 'string' ? v.trim() : v);

// The frontend sends `domains` as an array (e.g. ["zebra.com"]); the backend
// works with a single domain string. Take the first entry when it's an array.
const firstDomain = (v) => (Array.isArray(v) ? v[0] : v);

const handleTestConnection = async (req, res, next) => {
  try {
    const {
      protocol, auth_method, client_secret, certificate, certificate_password,
    } = req.body;
    const tenant_id    = t(req.body.tenant_id);
    const client_id    = t(req.body.client_id);
    const sso_url      = t(req.body.sso_url);
    const redirect_uri = t(req.body.redirect_uri);
    const scope        = t(req.body.scope);
    const domains      = t(firstDomain(req.body.domains))?.toLowerCase();

    if (!protocol) return res.status(400).json({ success: false, message: 'protocol is required' });
    // OIDC always needs tenant_id (used to build the Microsoft token/authorize URLs).
    // SAML uses sso_url instead; tenant_id is only a fallback when sso_url is absent.
    if (protocol === 'oidc' && !tenant_id) {
      return res.status(400).json({ success: false, message: 'tenant_id is required' });
    }
    if (protocol === 'saml' && !tenant_id && !sso_url) {
      return res.status(400).json({ success: false, message: 'sso_url (or tenant_id) is required' });
    }

    logger.info('Test connection request', { action: 'test_connection', protocol, auth_method, ip: req.ip });

    const result = await testConnection({ protocol, auth_method, tenant_id, client_id, client_secret, certificate, certificate_password, sso_url, redirect_uri, scope, domains });

    // For OIDC — store internal config in tcStore keyed by sessionRef.
    // Popup will send sessionRef back in callback so we can retrieve it.
    if (result.success && result.data?.sessionRef && result.data?._internal) {
      tcStore.set(result.data.sessionRef, result.data._internal);
      // Remove _internal from response — never expose secrets to frontend
      delete result.data._internal;
    }

    await auditTestConnection(req.ip, protocol, result.success);

    logger.info('Test connection result', { action: 'test_connection_result', success: result.success });

    return res.status(200).json(result);
  } catch (err) {
    logger.error('Test connection error', { action: 'test_connection_error', error: err.message });
    next(err);
  }
};

module.exports = { handleTestConnection };
