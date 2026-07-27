const { logger } = require('../../config/logger');
const { extractFromPkcs12 } = require('../../utils/oidc/pkcs12.util');

// Validation patterns/allow-lists.
const ALLOWED_PROTOCOLS = ['oidc', 'saml'];
const TENANT_ALIASES    = new Set(['common', 'consumers', 'organizations']);
const DOMAIN_RE = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const UUID_RE   = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const URL_RE    = /^https?:\/\/.+/;

const { isCertAuth } = require('../../utils/shared/authMethod.util');

const fieldError = (message, code = 'MISSING_REQUIRED_FIELDS') =>
  Object.assign(new Error(message), { statusCode: 400, code });

// Protocol-aware validation. Each failure gets a distinct code so logs/clients
// pinpoint the offending field without parsing the free-text message. Presence
// AND format are checked — invalid values must not reach the DB/URL-building
// layer. OIDC needs tenant_id (used to build the Microsoft token/authorize
// URLs); SAML has no Azure-tenant field, so it requires sso_url instead.
const validateRequiredFields = ({ protocol, domains, tenant_id, sso_url }) => {
  if (!protocol) throw fieldError('protocol is required', 'MISSING_PROTOCOL');
  const domainList = Array.isArray(domains) ? domains : (domains ? [domains] : []);
  if (domainList.length === 0) throw fieldError('domains is required', 'MISSING_DOMAINS');
  if (!ALLOWED_PROTOCOLS.includes(protocol)) {
    throw fieldError(`protocol must be one of: ${ALLOWED_PROTOCOLS.join(', ')}`, 'INVALID_PROTOCOL');
  }
  for (const d of domainList) {
    if (!DOMAIN_RE.test(d)) {
      throw fieldError('domains must be valid domain names (e.g. example.com)', 'INVALID_DOMAINS');
    }
  }
  if (protocol === 'oidc') {
    if (!tenant_id) throw fieldError('tenant_id is required for OIDC', 'MISSING_TENANT_ID');
    if (!UUID_RE.test(tenant_id) && !TENANT_ALIASES.has(tenant_id)) {
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

// mapping_source may be any Entra claim/attribute name — 'group', 'department',
// 'jobtitle', and 'role' get built-in normalisation and (for OIDC) Graph
// enrichment, but any other non-empty string is accepted too and matched
// directly against the raw token/assertion at login time (see
// matchesMapping's default case in userResolution.service.js). 'default' is
// reserved as the fallback-only keyword.
//
// Validates jit_mappings at save time:
//   - non-default mappings need a mapping_value to match against
// zdna_role is NOT validated against zdna_roles — RMS role names are defined
// per-tenant (each company manages its own custom roles) and are not
// enumerable from this backend, so whatever the console's RMS-fed Role
// dropdown submits is stored as-is. Login-time resolution (resolveRoles in
// userResolution.service.js) passes through any role_id it doesn't recognise
// locally; real permissions for RMS-integrated companies come from
// permissionResolver's RMS-by-email lookup regardless of this label.
const validateJitMappings = (jit_enabled, jit_mappings) => {
  if (!jit_enabled || !Array.isArray(jit_mappings) || jit_mappings.length === 0) return;

  for (const m of jit_mappings) {
    if (!m.zdna_role || !m.mapping_source) continue; // dropped by the row builders anyway
    const source = String(m.mapping_source).trim().toLowerCase();
    if (source !== 'default' && !m.mapping_value) {
      throw fieldError(`mapping_value is required for '${source}' mappings`, 'MISSING_MAPPING_VALUE');
    }
  }
};

// Normalises validated mappings once for BOTH stores: lowercases the source
// and resolves priority — the frontend's explicit `order` wins when every row
// has a unique finite order; otherwise array position decides (as before).
const normalizeJitMappings = (jit_mappings) => {
  if (!Array.isArray(jit_mappings)) return jit_mappings;
  const rows = jit_mappings.filter(m => m.zdna_role && m.mapping_source);
  const orders   = rows.map(m => Number(m.order));
  const useOrder = rows.length > 0 && orders.every(Number.isFinite) && new Set(orders).size === rows.length;
  return rows.map((m, i) => ({
    ...m,
    mapping_source: String(m.mapping_source).trim().toLowerCase(),
    priority:       useOrder ? Number(m.order) : i + 1,
  }));
};

// SAML has no tenant_id field — derive the Azure tenant GUID from the IdP
// SSO URL (e.g. https://login.microsoftonline.com/<tenant-guid>/saml2).
const deriveEntraTenantId = (tenant_id, sso_url) => {
  const samlTenant = sso_url?.match(/login\.microsoftonline\.com\/([0-9a-fA-F-]+)\//)?.[1] || null;
  return tenant_id || samlTenant || null;
};

// For the OIDC Client Certificate (private_key_jwt) method, extract the private
// key + SHA-1 thumbprint from the uploaded .pfx/.p12 so they can be persisted.
const extractCert = async (protocol, auth_method, certificate, certificate_password) => {
  if (protocol !== 'oidc' || !isCertAuth(auth_method)) {
    return { private_key_b64: null, client_cert_thumbprint: null };
  }
  const { privateKeyB64, thumbprintHex } = await extractFromPkcs12(certificate, certificate_password);
  logger.debug('[SAVE-SSO] Extracted private key + thumbprint from PKCS#12');
  return { private_key_b64: privateKeyB64, client_cert_thumbprint: thumbprintHex };
};

// Admins may paste the SSO URL with ?appid=<application-id> — used by
// test-connection to verify the app's signing certificate ownership. The
// login redirect builder appends its own '?SAMLRequest=...' (hardcoded '?'),
// so the stored URL must carry no query string or fragment.
const stripUrlQuery = (url) => {
  if (!url) return url;
  try {
    const u = new URL(url);
    return u.origin + u.pathname;
  } catch {
    return url; // format already validated upstream
  }
};

// Persist to PostgreSQL via the data layer; returns the actual company_id used
// (may differ from the proposed one if the domain already existed).
//
// NOTE: the data-layer require stays lazy (inside this function) on purpose —
// it pulls in Sequelize models, and hoisting it to module scope would load the
// ORM at import time even for callers that never persist.
const saveToPostgres = async (company_id, fields) => {
  const { saveSsoConfig: pgSave, getSsoIntegrationByDomain } = require('../db/postgresSSO.service');
  await pgSave({ company_id: company_id, ...fields });
  // Re-read via any of the saved domains to learn the actual company_id used
  // (the store reuses an existing row's id when a domain already existed).
  const saved = await getSsoIntegrationByDomain(fields.domains[0]);
  const company_id = saved ? saved.company_id : company_id;
  logger.debug(`[SAVE-SSO] Persisted to PostgreSQL | company_id: ${company_id}`);
  return company_id;
};

/**
 * Validates, derives, and persists an SSO configuration to PostgreSQL.
 *
 * @param {Object} payload
 * @param {'oidc'|'saml'} payload.protocol
 * @param {string|string[]} payload.domains    Company email domain(s) (e.g. ["zebra.com"])
 * @param {string}  [payload.idp]
 * @param {string}  [payload.tenant_id]        Azure tenant GUID (required for OIDC)
 * @param {string}  [payload.company_id]       Configuring admin's tenant id — the sole
 *                                             owner key; falls back to zdna-<domain>-<ts>
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
 */
const saveSsoConfig = async (payload) => {
  const {
    protocol, idp, domains, tenant_id, company_id,
    client_id, auth_method, client_secret, redirect_uri,
    sso_url, entity_id, acs_url, certificate, certificate_password,
    sign_auth, keep_existing_cert,
    jit_enabled, jit_mappings,
  } = payload;

  validateRequiredFields(payload);
  validateJitMappings(jit_enabled, jit_mappings);
  const normalizedJitMappings = normalizeJitMappings(jit_mappings);

  const entraTenantId = deriveEntraTenantId(tenant_id, sso_url);
  const { private_key_b64: privateKeyB64, client_cert_thumbprint: clientCertThumbprint } =
    await extractCert(protocol, auth_method, certificate, certificate_password);

  const domainList = (Array.isArray(domains) ? domains : [domains]).map(d => d.toLowerCase());

  // company_id = the configuring admin's tenant id — the single key that
  // deactivate/delete/status/edit all use, so one stable id per organisation.
  // Fallback to the legacy zdna-<domain>-<ts> form when the caller supplies no
  // company_id (direct API use) so the Postgres PK can never be null.

  const fields = {
    protocol, idp, domains: domainList,
    tenant_id, entra_tenant_id: entraTenantId, entraTenantId,
    client_id, auth_method, client_secret, redirect_uri,
    // Strip ?appid=... (and any other query) here so the persisted URL carries
    // no query string — the login redirect builder appends its own
    // '?SAMLRequest=...' (a verbatim URL would double the '?' → AADSTS750054).
    sso_url: stripUrlQuery(sso_url), entity_id, acs_url, certificate,
    sign_auth: sign_auth || false,
    private_key_b64: privateKeyB64, client_cert_thumbprint: clientCertThumbprint,
    keep_existing_cert: !!keep_existing_cert,
    jit_enabled, jit_mappings: normalizedJitMappings,
  };

  const savedCompanyId = await saveToPostgres(company_id, fields);

  return {
    success:    true,
    company_id: savedCompanyId,
    message:    'SSO configuration saved and activated successfully',
  };
};

module.exports = { saveSsoConfig };
