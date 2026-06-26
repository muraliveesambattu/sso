/**
 * Local SSO Service
 *
 * JSON-backed SSO store. Reads all SSO config from src/data/ssoConfig.json.
 * sso_users are persisted back to the JSON file on create/update (JIT).
 *
 * To add a new company / domain — edit ssoConfig.json directly:
 *   - sso_integrations  : add a new entry with company_id, domains, protocol, entra_tenant_id
 *   - oidc_configurations or saml_configurations : add matching company_id entry
 *   - jit_mappings      : add group and default mapping rows for the new company
 *
 * Exported API matches the Postgres store, so callers (ssoDataService) can
 * switch backends without any code changes.
 */

const fs   = require('fs');
const { logger } = require('../../config/logger');
const path = require('path');
const crypto = require('crypto');

const { resolveSecret } = require('../../utils/crypto.util');

// Resolves "env:VAR_NAME" references — kept for backward compat with SAML fields
const resolveEnvRef = (val) => {
  if (typeof val === 'string' && val.startsWith('env:')) {
    return process.env[val.slice(4)] || null;
  }
  return val;
};

const CONFIG_PATH = path.join(__dirname, '../../data/ssoConfig.json');

// ── Load JSON ─────────────────────────────────────────────────────────────────

const loadData = () => JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));

// Load once at startup into memory
let data = loadData();

// Write the full data object back to disk (used after user mutations)
const persist = () => {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(data, null, 2), 'utf8');
};

// ── sso_integrations ──────────────────────────────────────────────────────────

const getSsoIntegrationByDomain = async (domain) => {
  logger.debug(`[LOCAL] Query sso_integrations | domain: ${domain}`);
  const result = data.sso_integrations.find(
    (r) => r.domains === domain.toLowerCase() && r.sso_status === 'active'
  ) || null;
  logger.debug(`[LOCAL] sso_integrations result | found: ${!!result} | protocol: ${result?.protocol || '-'}`);
  return result;
};

const getSsoIntegrationByCompanyId = async (companyId) => {
  logger.debug(`[LOCAL] Query sso_integrations | company_id: ${companyId}`);
  return data.sso_integrations.find((r) => r.company_id === companyId) || null;
};

// ── oidc_configurations ───────────────────────────────────────────────────────

const getOidcConfig = async (companyId) => {
  logger.debug(`[LOCAL] Query oidc_configurations | company_id: ${companyId}`);
  const raw = data.oidc_configurations.find((r) => r.company_id === companyId);
  if (!raw) return null;
  return {
    ...raw,
    // Decrypt if stored encrypted, resolve env refs, or return plain (legacy)
    client_secret: resolveSecret(raw.client_secret),
  };
};

// ── saml_configurations ───────────────────────────────────────────────────────

const getSamlConfig = async (companyId) => {
  logger.debug(`[LOCAL] Query saml_configurations | company_id: ${companyId}`);
  const raw = data.saml_configurations.find((r) => r.company_id === companyId);
  if (!raw) return null;
  return {
    ...raw,
    entity_id: resolveEnvRef(raw.entity_id),
    acs_url:   resolveEnvRef(raw.acs_url),
  };
};

const getSamlConfigByAcsUrl = async (acsUrl) => {
  logger.debug(`[LOCAL] Query saml_configurations | acs_url: ${acsUrl}`);
  // Resolve env refs before comparing so "env:SAML_ACS_URL" matches the real URL
  const raw = data.saml_configurations.find(
    (r) => resolveEnvRef(r.acs_url) === acsUrl
  );
  if (!raw) return null;
  return {
    ...raw,
    entity_id: resolveEnvRef(raw.entity_id),
    acs_url:   resolveEnvRef(raw.acs_url),
  };
};

// ── jit_mappings ──────────────────────────────────────────────────────────────

const getJitMappings = async (companyId) => {
  logger.debug(`[LOCAL] Query jit_mappings | company_id: ${companyId}`);
  return data.jit_mappings.filter(
    (r) => r.company_id === companyId && r.status === 'active'
  );
};

// ── zdna_roles ────────────────────────────────────────────────────────────────

const getRolesByIds = async (roleIds) => {
  if (!roleIds || roleIds.length === 0) return [];
  logger.debug(`[LOCAL] Query zdna_roles | role_ids: ${roleIds.join(', ')}`);
  return data.zdna_roles.filter((r) => roleIds.includes(r.role_id));
};

// ── sso_users ─────────────────────────────────────────────────────────────────

const findUserByOid = async (companyId, oid) => {
  logger.debug(`[LOCAL] Query sso_users | company_id: ${companyId} | oid: ${oid}`);
  return data.sso_users.find(
    (u) => u.company_id === companyId && u.oid === oid
  ) || null;
};

const findUserByEmail = async (companyId, email) => {
  logger.debug(`[LOCAL] Query sso_users | company_id: ${companyId} | email: ${email}`);
  return data.sso_users.find(
    (u) => u.company_id === companyId && u.email === email.toLowerCase()
  ) || null;
};

const createUser = async (userData) => {
  const newUser = {
    id:        crypto.randomUUID(),
    ...userData,
    email:     userData.email?.toLowerCase(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  logger.debug(`[LOCAL] Creating sso_users entry | email: ${newUser.email}`);
  data.sso_users.push(newUser);
  persist();
  return newUser;
};

const updateUser = async (userId, updates) => {
  logger.debug(`[LOCAL] Updating sso_users entry | id: ${userId}`);
  const idx = data.sso_users.findIndex((u) => u.id === userId);
  if (idx === -1) {
    logger.warn(`[LOCAL] updateUser: no user found with id: ${userId}`);
    return;
  }
  data.sso_users[idx] = {
    ...data.sso_users[idx],
    ...updates,
    updatedAt: new Date().toISOString(),
  };
  persist();
};

// ── Admin: retrieve full SSO config (secrets masked) ─────────────────────────

const getSsoConfigDetails = async ({ company_id, domain }) => {
  const integration = company_id
    ? data.sso_integrations.find((r) => r.company_id === company_id)
    : data.sso_integrations.find((r) => r.domains === domain.toLowerCase());
  if (!integration) return null;

  const cid  = integration.company_id;
  const oidcRaw = data.oidc_configurations.find((r) => r.company_id === cid) || null;
  const samlRaw = data.saml_configurations.find((r) => r.company_id === cid) || null;

  let oidc = null;
  if (oidcRaw) {
    // Never expose secrets — only indicate whether one is configured
    const { client_secret, client_cert_enc, ...rest } = oidcRaw;
    oidc = { ...rest, client_secret_set: !!client_secret };
  }
  let saml = null;
  if (samlRaw) {
    const { sp_private_key_enc, ...rest } = samlRaw;
    saml = rest;
  }

  return {
    integration,
    oidc_config:  oidc,
    saml_config:  saml,
    jit_mappings: data.jit_mappings.filter((m) => m.company_id === cid),
  };
};

// ── Admin: activate / deactivate SSO for a company ───────────────────────────

const setSsoStatus = async (companyId, status) => {
  const idx = data.sso_integrations.findIndex((r) => r.company_id === companyId);
  if (idx === -1) return false;
  data.sso_integrations[idx].sso_status = status;
  persist();
  logger.info(`[LOCAL] SSO status updated | company_id: ${companyId} | status: ${status}`);
  return true;
};

// ── Admin: delete SSO config (integration + protocol config + JIT mappings) ──

const deleteSsoConfig = async (companyId) => {
  const exists = data.sso_integrations.some((r) => r.company_id === companyId);
  if (!exists) return false;

  data.sso_integrations     = data.sso_integrations.filter((r) => r.company_id !== companyId);
  data.oidc_configurations  = data.oidc_configurations.filter((r) => r.company_id !== companyId);
  data.saml_configurations  = data.saml_configurations.filter((r) => r.company_id !== companyId);
  data.jit_mappings         = data.jit_mappings.filter((r) => r.company_id !== companyId);

  persist();
  logger.info(`[LOCAL] SSO config deleted | company_id: ${companyId}`);
  return true;
};

// ── Cache Invalidation (no-op — data is in-memory) ───────────────────────────

const invalidateDomainCache = (domain) => {
  // In the local JSON service, data is already in memory.
  // Call this to reload the JSON from disk if you've edited the file manually
  // while the server is running.
  logger.debug(`[LOCAL] Reloading ssoConfig.json from disk | triggered by: ${domain}`);
  data = loadData();
};

// ── Exports (match the Postgres store) ────────────────────────────────────────

module.exports = {
  // SSO integrations
  getSsoIntegrationByDomain,
  getSsoIntegrationByCompanyId,
  // OIDC
  getOidcConfig,
  // SAML
  getSamlConfig,
  getSamlConfigByAcsUrl,
  // JIT
  getJitMappings,
  getRolesByIds,
  // Users
  findUserByOid,
  findUserByEmail,
  createUser,
  updateUser,
  // Admin
  getSsoConfigDetails,
  setSsoStatus,
  deleteSsoConfig,
  // Cache / reload
  invalidateDomainCache,
};
