const { testConnection, validateSsoConfiguration } = require('../services/SSO/testConnection.service');
const { logger } = require('../config/logger');
const { auditTestConnection } = require('../services/audit/audit.service');
const tcStore = require('../utils/shared/testConnectionStore');
const { getOidcConfig, getSamlConfig } = require('../services/db/postgresSSO.service');
const { decrypt } = require('../utils/crypto.util');

// Trim identifier fields so a stray copy-paste space can't corrupt the
// Microsoft assertion (aud/iss), issuer validation, or domain lookups.
const trimStr = (v) => (typeof v === 'string' ? v.trim() : v);

// The frontend sends `domains` as an array (e.g. ["zebra.com"]); the backend
// works with a single domain string. Take the first entry when it's an array.
const firstDomain = (v) => (Array.isArray(v) ? v[0] : v);

const getExistingCertificate = async (
  protocol,
  company_id
) => {
  if (protocol === 'saml') {
    const saml = await getSamlConfig(company_id);
    return saml?.certificate || undefined;
  }

  if (protocol === 'oidc') {
    const oidc = await getOidcConfig(company_id);

    logger.debug('OIDC existing certificate lookup', {
      hasClientCert: !!oidc?.client_cert_enc,
      hasPrivateKey: !!oidc?.private_key_enc,
      hasThumbprint: !!oidc?.client_cert_thumbprint,
    });

    return oidc?.client_cert_enc || undefined;
  }

  return undefined;
};

const shouldStoreSession = (result) =>
  result.success &&
  result.data?.sessionRef &&
  result.data?._internal;


const handleTestConnection = async (req, res, next) => {
  try {
    if (req.body?.is_existing_test) {
      const result = await validateSsoConfiguration(req.body?.company_id);
      logger.info("Test connection result", {
        action: "test_connection_result",
        success: result.success,
      });
      return res.status(200).json(result);
    }
    const {
      protocol, auth_method, client_secret, certificate_password, company_id, use_existing_cert, sign_authn_request, signing_certificate, signing_certificate_password,
      use_existing_signing_cert
    } = req.body;
    const tenant_id = trimStr(req.body.tenant_id);
    const client_id = trimStr(req.body.client_id);
    const app_id = trimStr(req.body.app_id);
    const sso_url = trimStr(req.body.sso_url);
    const redirect_uri = trimStr(req.body.redirect_uri);
    const scope = trimStr(req.body.scope);
    let { certificate } = req.body;
    const domains = trimStr(firstDomain(req.body.domains))?.toLowerCase();

    if (!protocol) return res.status(400).json({ success: false, message: 'protocol is required' });
    // OIDC always needs tenant_id (used to build the Microsoft token/authorize URLs).
    // SAML uses sso_url instead; tenant_id is only a fallback when sso_url is absent.
    if (!certificate && use_existing_cert && company_id) {
      certificate = await getExistingCertificate(
        protocol,
        company_id
      );
    }
    if (protocol === 'oidc' && !tenant_id) {
      return res.status(400).json({ success: false, message: 'tenant_id is required' });
    }
    if (protocol === 'saml' && !tenant_id && !sso_url) {
      return res.status(400).json({ success: false, message: 'sso_url (or tenant_id) is required' });
    }

    logger.info('Test connection request', { action: 'test_connection', protocol, auth_method, ip: req.ip, app_id });

    const result = await testConnection({ protocol, auth_method, tenant_id, client_id, app_id, client_secret, entity_id: req.body.entity_id,
      acs_url: req.body.acs_url, certificate, certificate_password, sso_url, redirect_uri, scope, domains, company_id, use_existing_cert,
      sign_authn_request, signing_certificate, signing_certificate_password, use_existing_signing_cert });

    // For OIDC — store internal config in tcStore keyed by sessionRef.
    // Popup will send sessionRef back in callback so we can retrieve it.
    if (shouldStoreSession(result)) {
      tcStore.set(
        result.data.sessionRef,
        result.data._internal
      );

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
