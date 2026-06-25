const { v4: uuidv4 } = require('uuid');
const { logger } = require('../../config/logger');
const { encrypt } = require('../../utils/crypto.util');
const { extractFromPkcs12 } = require('../../utils/oidc/pkcs12.util');

// Module-level I/O setup — resolved once at startup, not on every invocation.
const fsp  = require('fs').promises;
const path = require('path');
const CONFIG_PATH = path.join(__dirname, '../../data/ssoConfig.json');

const { usePostgres } = require('../../config/dataSource');

// Centralised defaults — env-overridable, single source in config/constants.js.
const { defaults: DEFAULTS } = require('../../config/constants');

// Validation patterns/allow-lists.
const ALLOWED_PROTOCOLS = ['oidc', 'saml'];
const TENANT_ALIASES    = ['common', 'consumers', 'organizations'];
const DOMAIN_RE = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const UUID_RE   = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const URL_RE    = /^https?:\/\/.+/;

const isCertAuth = (authMethod) => authMethod === 'private_key_jwt' || authMethod === 'certificate';

const fieldError = (message, code = 'MISSING_REQUIRED_FIELDS') =>
  Object.assign(new Error(message), { statusCode: 400, code });

// Protocol-aware validation. Each failure gets a distinct code so logs/clients
// pinpoint the offending field without parsing the free-text message. Presence
// AND format are checked — invalid values must not reach the DB/URL-building
// layer. OIDC needs tenant_id (used to build the Microsoft token/authorize
// URLs); SAML has no Azure-tenant field, so it requires sso_url instead.
const validateRequiredFields = ({ protocol, domains, tenant_id, sso_url }) => {
  if (!protocol) throw fieldError('protocol is required', 'MISSING_PROTOCOL');
  if (!domains)  throw fieldError('domains is required', 'MISSING_DOMAINS');
  if (!ALLOWED_PROTOCOLS.includes(protocol)) {
    throw fieldError(`protocol must be one of: ${ALLOWED_PROTOCOLS.join(', ')}`, 'INVALID_PROTOCOL');
  }
  if (!DOMAIN_RE.test(domains)) {
    throw fieldError('domains must be a valid domain name (e.g. example.com)', 'INVALID_DOMAINS');
  }
  if (protocol === 'oidc') {
    if (!tenant_id) throw fieldError('tenant_id is required for OIDC', 'MISSING_TENANT_ID');
    if (!UUID_RE.test(tenant_id) && !TENANT_ALIASES.includes(tenant_id)) {
      throw fieldError('tenant_id must be a valid UUID or common/consumers/organizations', 'INVALID_TENANT_ID');
    }
  }
  if (protocol === 'saml') {
    if (!sso_url) throw fieldError('sso_url is required for SAML', 'MISSING_SSO_URL');
    if (!URL_RE.test(sso_url)) {
      throw fieldError('sso_url must be a valid HTTP/HTTPS URL', 'INVALID_SSO_URL');
    }
  }
};

// SAML has no tenant_id field — derive the Azure tenant GUID from the IdP
// SSO URL (e.g. https://login.microsoftonline.com/<tenant-guid>/saml2).
const deriveEntraTenantId = (tenant_id, sso_url) => {
  const samlTenant = sso_url?.match(/login\.microsoftonline\.com\/([0-9a-fA-F-]+)\//)?.[1] || null;
  return tenant_id || samlTenant || null;
};

// For the OIDC Client Certificate (private_key_jwt) method, extract the private
// key + SHA-1 thumbprint from the uploaded .pfx/.p12 so they can be persisted.
const extractCert = (protocol, auth_method, certificate, certificate_password) => {
  if (protocol !== 'oidc' || !isCertAuth(auth_method)) {
    return { private_key_b64: null, client_cert_thumbprint: null };
  }
  const { privateKeyB64, thumbprintHex } = extractFromPkcs12(certificate, certificate_password);
  logger.debug('[SAVE-SSO] Extracted private key + thumbprint from PKCS#12');
  return { private_key_b64: privateKeyB64, client_cert_thumbprint: thumbprintHex };
};

// JSON fallback — append to ssoConfig.json (used when no DB is configured, and
// as a safety net when PostgreSQL is unavailable). Fully async so it never
// blocks the event loop.
const saveToJson = async ({ company_id, protocol, idp, domains, entraTenantId,
  owner_tenant_id, owner_company_name, client_id, auth_method, client_secret,
  redirect_uri, sso_url, entity_id, acs_url, certificate,
  private_key_b64, client_cert_thumbprint, jit_enabled, jit_mappings }) => {

  let data;
  try {
    const raw = await fsp.readFile(CONFIG_PATH, 'utf8');
    data = JSON.parse(raw);
  } catch (readErr) {
    if (readErr.code === 'ENOENT') {
      // Fresh deploy — start from an empty store rather than crashing.
      data = { sso_integrations: [], oidc_configurations: [], saml_configurations: [], jit_mappings: [] };
      logger.warn('[SAVE-SSO] Config file missing — initialising empty store', { action: 'save_sso_config_missing' });
    } else {
      const err = new Error(`Failed to read SSO config file before write: ${readErr.message}`);
      err.code = 'CONFIG_READ_ERROR';
      err.statusCode = 500;
      throw err;
    }
  }

  // Remove any existing entry for this domain
  data.sso_integrations = (data.sso_integrations || []).filter(r => r.domains !== domains.toLowerCase());
  data.sso_integrations.push({
    id: `${company_id}_${domains.replace(/\./g, '_')}`,
    company_id, domains: domains.toLowerCase(),
    protocol, sso_status: DEFAULTS.SSO_STATUS,
    idp: idp || DEFAULTS.IDP,
    entra_tenant_id: entraTenantId,
    owner_tenant_id: owner_tenant_id || null,
    owner_company_name: owner_company_name || null,
    jit_enabled: !!jit_enabled,
  });

  if (protocol === 'oidc') {
    data.oidc_configurations = (data.oidc_configurations || []).filter(r => r.company_id !== company_id);
    data.oidc_configurations.push({
      id: company_id, company_id, client_id,
      client_auth_method: auth_method,
      client_secret: client_secret ? encrypt(client_secret) : null,
      // Client Certificate (private_key_jwt) — store encrypted base64(PEM) key + thumbprint
      private_key_enc:        private_key_b64 ? encrypt(private_key_b64) : null,
      client_cert_thumbprint: client_cert_thumbprint || null,
      scope: DEFAULTS.OIDC_SCOPE,
      redirect_uri: redirect_uri || DEFAULTS.OIDC_REDIRECT_URI,
    });
  }

  if (protocol === 'saml') {
    data.saml_configurations = (data.saml_configurations || []).filter(r => r.company_id !== company_id);
    data.saml_configurations.push({
      id: company_id, company_id,
      entity_id: entity_id || DEFAULTS.SAML_ENTITY_ID,
      sso_url,
      acs_url: acs_url || DEFAULTS.SAML_ACS_URL,
      certificate: certificate || null,
    });
  }

  if (jit_enabled && Array.isArray(jit_mappings) && jit_mappings.length) {
    data.jit_mappings = (data.jit_mappings || []).filter(r => r.company_id !== company_id);
    jit_mappings
      .filter(m => m.zdna_role && m.mapping_source)
      .forEach((m, i) => {
        data.jit_mappings.push({
          id: `jit-${company_id}-${i}`,
          company_id,
          mapping_source: m.mapping_source,
          mapping_value:  m.mapping_value || null,
          role_id:        m.zdna_role,
          priority:       i + 1,
          status:         DEFAULTS.SSO_STATUS,
        });
      });
  }

  await fsp.writeFile(CONFIG_PATH, JSON.stringify(data, null, 2), 'utf8');
  logger.debug(`[SAVE-SSO] Persisted to ssoConfig.json | company_id: ${company_id}`);
};

// Persist to PostgreSQL via the data layer; returns the actual company_id used
// (may differ from the proposed one if the domain already existed). If the DB
// is unavailable, fall back to the JSON store so the save is not lost.
//
// NOTE: the data-layer require stays lazy (inside this function) on purpose —
// it pulls in Sequelize models, and hoisting it to module scope would load the
// ORM even on the JSON-only path. It is only reached when usePostgres is true.
const saveToPostgres = async (proposedCompanyId, fields) => {
  try {
    const { saveSsoConfig: pgSave, getSsoIntegrationByDomain } = require('../db/postgresSSO.service');
    await pgSave({ company_id: proposedCompanyId, ...fields });
    const saved = await getSsoIntegrationByDomain(fields.domains);
    const company_id = saved ? saved.company_id : proposedCompanyId;
    logger.debug(`[SAVE-SSO] Persisted to PostgreSQL | company_id: ${company_id}`);
    return company_id;
  } catch (pgErr) {
    logger.error('[SAVE-SSO] PostgreSQL unavailable — falling back to JSON store', {
      action: 'save_sso_pg_fallback', error: pgErr.message,
    });
    await saveToJson({ company_id: proposedCompanyId, ...fields });
    return proposedCompanyId;
  }
};

/**
 * Validates, derives, and persists an SSO configuration to PostgreSQL (when a
 * database is configured) or the local JSON store.
 *
 * @param {Object} payload
 * @param {'oidc'|'saml'} payload.protocol
 * @param {string}  payload.domains            Company email domain (e.g. zebra.com)
 * @param {string}  [payload.idp]
 * @param {string}  [payload.tenant_id]        Azure tenant GUID (required for OIDC)
 * @param {string}  [payload.owner_tenant_id]
 * @param {string}  [payload.owner_company_name]
 * @param {string}  [payload.client_id]
 * @param {string}  [payload.auth_method]      client_secret_post | private_key_jwt | certificate
 * @param {string}  [payload.client_secret]
 * @param {string}  [payload.redirect_uri]
 * @param {string}  [payload.sso_url]          IdP SSO URL (required for SAML)
 * @param {string}  [payload.entity_id]
 * @param {string}  [payload.acs_url]
 * @param {string}  [payload.certificate]      base64 .pfx/.p12 for cert auth, or SAML IdP cert
 * @param {string}  [payload.certificate_password]
 * @param {boolean} [payload.jit_enabled]
 * @param {Array}   [payload.jit_mappings]
 * @returns {Promise<{ success: boolean, company_id: string, message: string }>}
 * @throws {Error} statusCode:400 — MISSING_PROTOCOL | MISSING_DOMAINS | INVALID_PROTOCOL |
 *                 INVALID_DOMAINS | MISSING_TENANT_ID | INVALID_TENANT_ID | MISSING_SSO_URL |
 *                 INVALID_SSO_URL | INVALID_PKCS12 | NO_PRIVATE_KEY
 * @throws {Error} statusCode:500 — CONFIG_READ_ERROR
 */
const saveSsoConfig = async (payload) => {
  const {
    protocol, idp, domains, tenant_id,
    owner_tenant_id, owner_company_name,
    client_id, auth_method, client_secret, redirect_uri,
    sso_url, entity_id, acs_url, certificate, certificate_password,
    jit_enabled, jit_mappings,
  } = payload;

  validateRequiredFields(payload);

  const entraTenantId = deriveEntraTenantId(tenant_id, sso_url);
  const { private_key_b64, client_cert_thumbprint } =
    extractCert(protocol, auth_method, certificate, certificate_password);

  const proposedCompanyId = `zdna-${domains.replace(/[.\s]/g, '-')}-${Date.now()}`;

  const fields = {
    protocol, idp, domains,
    tenant_id, entra_tenant_id: entraTenantId, entraTenantId,
    owner_tenant_id, owner_company_name,
    client_id, auth_method, client_secret, redirect_uri,
    sso_url, entity_id, acs_url, certificate,
    private_key_b64, client_cert_thumbprint,
    jit_enabled, jit_mappings,
  };

  let company_id;
  if (usePostgres) {
    company_id = await saveToPostgres(proposedCompanyId, fields);
  } else {
    company_id = proposedCompanyId;
    await saveToJson({ company_id, ...fields });
  }

  return {
    success:    true,
    company_id,
    message:    'SSO configuration saved and activated successfully',
  };
};

module.exports = { saveSsoConfig };
