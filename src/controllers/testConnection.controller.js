const { testConnection }      = require('../services/SSO/testConnection.service');
const { logger }              = require('../config/logger');
const { auditTestConnection } = require('../services/audit/audit.service');
const tcStore                 = require('../utils/shared/testConnectionStore');
const { trimStr, trimLowerDomain } = require('../utils/shared/requestNormalize.util');

// Upper bounds so a non-string body or an oversized base64 PKCS#12 cert can't
// reach the test-connection service.
const MAX_CERT_B64_LEN = 20000;
const MAX_SECRET_LEN   = 2048;

// An optional field is valid when absent; if present it must be a non-empty
// string within `max`. Returns an error message, or null when acceptable.
const invalidOptionalString = (value, label, max) => {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > max) {
    return `${label} must be a non-empty string under ${max} characters`;
  }
  return null;
};

const handleTestConnection = async (req, res, next) => {
  try {
    const {
      protocol, auth_method, client_secret, certificate, certificate_password,
    } = req.body;
    const tenant_id    = trimStr(req.body.tenant_id);
    const client_id    = trimStr(req.body.client_id);
    const sso_url      = trimStr(req.body.sso_url);
    const redirect_uri = trimStr(req.body.redirect_uri);
    const scope        = trimStr(req.body.scope);
    const domains      = trimLowerDomain(req.body.domains);

    if (!protocol) return res.status(400).json({ success: false, message: 'protocol is required' });
    // OIDC always needs tenant_id (used to build the Microsoft token/authorize URLs).
    // SAML uses sso_url instead; tenant_id is only a fallback when sso_url is absent.
    if (protocol === 'oidc' && !tenant_id) {
      return res.status(400).json({ success: false, message: 'tenant_id is required' });
    }
    if (protocol === 'saml' && !tenant_id && !sso_url) {
      return res.status(400).json({ success: false, message: 'sso_url (or tenant_id) is required' });
    }

    // Type/size-guard the credential fields before they reach cert parsing.
    const credError =
      invalidOptionalString(certificate, 'certificate', MAX_CERT_B64_LEN) ||
      invalidOptionalString(certificate_password, 'certificate_password', MAX_SECRET_LEN) ||
      invalidOptionalString(client_secret, 'client_secret', MAX_SECRET_LEN);
    if (credError) return res.status(400).json({ success: false, message: credError });

    logger.debug('Test connection request', { action: 'test_connection', protocol, auth_method, ip: req.ip });

    const result = await testConnection({ protocol, auth_method, tenant_id, client_id, client_secret, certificate, certificate_password, sso_url, redirect_uri, scope, domains });

    // For OIDC — store internal config in tcStore keyed by sessionRef.
    // Popup will send sessionRef back in callback so we can retrieve it.
    if (result.success && result.data?.sessionRef && result.data?._internal) {
      tcStore.set(result.data.sessionRef, result.data._internal);
      // Remove _internal from response — never expose secrets to frontend
      delete result.data._internal;
    }

    // Fire-and-forget: the audit write already swallows its own errors; don't
    // add a DB round-trip to the client-facing latency. Promise.resolve guards
    // against a non-thenable return.
    Promise.resolve(auditTestConnection(req.ip, protocol, result.success)).catch(() => {});

    logger.info('Test connection result', { action: 'test_connection_result', success: result.success });

    return res.status(200).json(result);
  } catch (err) {
    logger.error('Test connection error', { action: 'test_connection_error', error: err.message });
    next(err);
  }
};

module.exports = { handleTestConnection };
