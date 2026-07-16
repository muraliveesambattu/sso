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

// ── Row builders — each owns exactly one table's shape ────────────────────────

const buildIntegrationRow = ({ company_id, domains, protocol, idp, entraTenantId,
  owner_tenant_id, owner_company_name, jit_enabled }) => ({
  id:                 `${company_id}_${domains.replace(/\./g, '_')}`,
  company_id,
  domains:            domains.toLowerCase(),
  protocol,
  sso_status:         DEFAULTS.SSO_STATUS,
  idp:                idp || DEFAULTS.IDP,
  entra_tenant_id:    entraTenantId,
  owner_tenant_id:    owner_tenant_id || null,
  owner_company_name: owner_company_name || null,
  jit_enabled:        !!jit_enabled,
});

const buildOidcRow = ({ company_id, client_id, auth_method, client_secret,
  redirect_uri, private_key_b64, client_cert_thumbprint }) => ({
  id:                    company_id,
  company_id,
  client_id,
  client_auth_method:    auth_method,
  client_secret:         client_secret ? encrypt(client_secret) : null,
  // Client Certificate (private_key_jwt) — store encrypted base64(PEM) key + thumbprint
  private_key_enc:       private_key_b64 ? encrypt(private_key_b64) : null,
  client_cert_thumbprint: client_cert_thumbprint || null,
  scope:                 DEFAULTS.OIDC_SCOPE,
  redirect_uri:          redirect_uri || DEFAULTS.OIDC_REDIRECT_URI,
});

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

const buildSamlRow = ({ company_id, entity_id, sso_url, acs_url, certificate }) => ({
  id:         company_id,
  company_id,
  entity_id:  entity_id || DEFAULTS.SAML_ENTITY_ID,
  sso_url:    stripUrlQuery(sso_url),
  acs_url:    acs_url || DEFAULTS.SAML_ACS_URL,
  certificate: certificate || null,
});

const buildJitRows = (company_id, jit_mappings) =>
  jit_mappings
    .filter(m => m.zdna_role && m.mapping_source)
    .map((m, i) => ({
      id:             `jit-${company_id}-${i}`,
      company_id,
      mapping_source: m.mapping_source,
      mapping_value:  m.mapping_value || null,
      role_id:        m.zdna_role,
      priority:       m.priority ?? i + 1,   // normalised upstream (honours frontend `order`)
      status:         DEFAULTS.SSO_STATUS,
    }));

// JSON fallback — append to ssoConfig.json (used when no DB is configured, and
// as a safety net when PostgreSQL is unavailable). Fully async so it never
// blocks the event loop.
const saveToJson = async (params) => {
  const { company_id, protocol, domains, jit_enabled, jit_mappings } = params;

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

  data.sso_integrations = (data.sso_integrations || []).filter(r => r.domains !== domains.toLowerCase());
  data.sso_integrations.push(buildIntegrationRow(params));

  if (protocol === 'oidc') {
    data.oidc_configurations = (data.oidc_configurations || []).filter(r => r.company_id !== company_id);
    data.oidc_configurations.push(buildOidcRow(params));
  }

  if (protocol === 'saml') {
    data.saml_configurations = (data.saml_configurations || []).filter(r => r.company_id !== company_id);
    data.saml_configurations.push(buildSamlRow(params));
  }

  if (jit_enabled && Array.isArray(jit_mappings) && jit_mappings.length) {
    data.jit_mappings = (data.jit_mappings || []).filter(r => r.company_id !== company_id);
    data.jit_mappings.push(...buildJitRows(company_id, jit_mappings));
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
  const { saveSsoConfig: pgSave, getSsoIntegrationByDomain } = require('../db/postgresSSO.service');
  await pgSave({ company_id: proposedCompanyId, ...fields });
  const saved = await getSsoIntegrationByDomain(fields.domains);
  const company_id = saved ? saved.company_id : proposedCompanyId;
  logger.debug(`[SAVE-SSO] Persisted to PostgreSQL | company_id: ${company_id}`);
  return company_id;
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
    sign_auth, keep_existing_cert,
    jit_enabled, jit_mappings,
  } = payload;

  validateRequiredFields(payload);
  validateJitMappings(jit_enabled, jit_mappings);
  const normalizedJitMappings = normalizeJitMappings(jit_mappings);

  const entraTenantId = deriveEntraTenantId(tenant_id, sso_url);
  const { private_key_b64: privateKeyB64, client_cert_thumbprint: clientCertThumbprint } =
    await extractCert(protocol, auth_method, certificate, certificate_password);

  // company_id = the configuring admin's tenant id (owner_tenant_id) — the
  // same key deactivate/delete/status use, so one stable id per organisation.
  // Fallback to the legacy zdna-<domain>-<ts> form when no owner is supplied
  // (older callers / direct API use) so the Postgres PK can never be null.
  // NOTE: for domains that already exist, the store keeps the row's ORIGINAL
  // company_id regardless of this proposal (edit never re-keys a config).
  const proposedCompanyId =
    owner_tenant_id || `zdna-${domains.replace(/[.\s]/g, '-')}-${Date.now()}`;

  const fields = {
    protocol, idp, domains,
    tenant_id, entra_tenant_id: entraTenantId, entraTenantId,
    owner_tenant_id, owner_company_name,
    client_id, auth_method, client_secret, redirect_uri,
    // Strip ?appid=... (and any other query) here — once, for BOTH stores.
    // buildSamlRow also strips for the JSON path, but the Postgres path used
    // to persist the URL verbatim, which corrupted the login redirect
    // (double '?' → AADSTS750054).
    sso_url: stripUrlQuery(sso_url), entity_id, acs_url, certificate,
    sign_auth: sign_auth || false,
    private_key_b64: privateKeyB64, client_cert_thumbprint: clientCertThumbprint,
    keep_existing_cert: !!keep_existing_cert,
    jit_enabled, jit_mappings: normalizedJitMappings,
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
