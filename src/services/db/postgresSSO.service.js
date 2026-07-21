/**
 * PostgreSQL SSO Service
 *
 * The sole data backend for all SSO configuration and user data.
 *
 * Tables: sso_integrations, oidc_configurations, saml_configurations,
 *         jit_mappings, zdna_roles, sso_users
 */

const crypto    = require('crypto');
const { Op }    = require('sequelize');
const { logger } = require('../../config/logger');
const { defaults } = require('../../config/constants');
const {
  SsoIntegration,
  OidcConfiguration,
  SamlConfiguration,
  ZdnaRole,
  JitMapping,
  SsoUser,
} = require('../../models');
const { encrypt, resolveSecret } = require('../../utils/crypto.util');

// Resolve "env:VAR_NAME" references to their environment value; pass through
// plain strings unchanged. Used for SAML entity_id / acs_url (which may be
// stored as env: refs).
const resolveEnvRef = (val) => {
  if (typeof val === 'string' && val.startsWith('env:')) {
    return process.env[val.slice(4)] || null;
  }
  return val;
};

// ── sso_integrations ──────────────────────────────────────────────────────────

const getSsoIntegrationByDomain = async (domain) => {
  logger.debug(`[POSTGRES] Query sso_integrations | domain: ${domain}`);
  const row = await SsoIntegration.findOne({
    where: { domains: domain.toLowerCase(), sso_status: 'active' },
  });
  logger.debug(`[POSTGRES] sso_integrations result | found: ${!!row} | protocol: ${row?.protocol || '-'}`);
  return row ? row.toJSON() : null;
};

// One Entra tenant should not be claimed by two different organisations —
// used at save time to reject a tenant_id already registered elsewhere.
const getSsoIntegrationByEntraTenantId = async (entraTenantId) => {
  logger.debug(`[POSTGRES] Query sso_integrations | entra_tenant_id: ${entraTenantId}`);
  const row = await SsoIntegration.findOne({ where: { entra_tenant_id: entraTenantId } });
  return row ? row.toJSON() : null;
};

const getSsoIntegrationByCompanyId = async (companyId) => {
  logger.debug(`[POSTGRES] Query sso_integrations | company_id: ${companyId}`);
  const row = await SsoIntegration.findOne({ where: { company_id: companyId } });
  return row ? row.toJSON() : null;
};

// ── oidc_configurations ───────────────────────────────────────────────────────

const getOidcConfig = async (companyId) => {
  logger.debug(`[POSTGRES] Query oidc_configurations | company_id: ${companyId}`);
  const row = await OidcConfiguration.findOne({ where: { company_id: companyId } });
  if (!row) return null;
  const data = row.toJSON();
  return {
    ...data,
    // Decrypt at runtime — never stored or returned as plain text.
    // client_cert_enc resolves to base64(PEM), which generateJwtAssertion base64-decodes.
    client_secret:   resolveSecret(data.client_secret_enc),
    client_cert_enc: resolveSecret(data.private_key_enc),
  };
};

// ── saml_configurations ───────────────────────────────────────────────────────

const getSamlConfig = async (companyId) => {
  logger.debug(`[POSTGRES] Query saml_configurations | company_id: ${companyId}`);
  const row = await SamlConfiguration.findOne({ where: { company_id: companyId } });
  if (!row) return null;
  const data = row.toJSON();
  return {
    ...data,
    entity_id: resolveEnvRef(data.entity_id),
    acs_url:   resolveEnvRef(data.acs_url),
  };
};

const getSamlConfigByAcsUrl = async (acsUrl) => {
  logger.debug(`[POSTGRES] Query saml_configurations | acs_url: ${acsUrl}`);
  const rows = await SamlConfiguration.findAll();
  const match = rows.map(r => r.toJSON()).find(r => resolveEnvRef(r.acs_url) === acsUrl);
  if (!match) return null;
  return { ...match, entity_id: resolveEnvRef(match.entity_id), acs_url: resolveEnvRef(match.acs_url) };
};

// ── jit_mappings ──────────────────────────────────────────────────────────────

const getJitMappings = async (companyId) => {
  logger.debug(`[POSTGRES] Query jit_mappings | company_id: ${companyId}`);
  const rows = await JitMapping.findAll({
    where:   { company_id: companyId, status: 'active' },
    order:   [['priority', 'ASC']],
  });
  return rows.map(r => r.toJSON());
};

// ── zdna_roles ────────────────────────────────────────────────────────────────

const getRolesByIds = async (roleIds) => {
  if (!roleIds || roleIds.length === 0) return [];
  logger.debug(`[POSTGRES] Query zdna_roles | role_ids: ${roleIds.join(', ')}`);
  const rows = await ZdnaRole.findAll({ where: { role_id: { [Op.in]: roleIds } } });
  return rows.map(r => r.toJSON());
};

const getAllRoles = async () => {
  logger.debug('[POSTGRES] Query zdna_roles | all');
  const rows = await ZdnaRole.findAll({ order: [['role_id', 'ASC']] });
  return rows.map(r => r.toJSON());
};

// ── sso_users ─────────────────────────────────────────────────────────────────

// Normalize user row — adds `id` alias for user_id so callers work
// with both the JSON service (uses `id`) and Postgres (uses `user_id`)
const normalizeUser = (row) => {
  if (!row) return null;
  const data = row.toJSON ? row.toJSON() : row;
  return { ...data, id: data.user_id };  // id alias for backward compat
};

const findUserByOid = async (companyId, oid) => {
  logger.debug(`[POSTGRES] Query sso_users | company_id: ${companyId} | oid: ${oid}`);
  const row = await SsoUser.findOne({ where: { company_id: companyId, oid } });
  return normalizeUser(row);
};

const findUserByEmail = async (companyId, email) => {
  logger.debug(`[POSTGRES] Query sso_users | company_id: ${companyId} | email: ${email}`);
  const row = await SsoUser.findOne({ where: { company_id: companyId, email: email.toLowerCase() } });
  return normalizeUser(row);
};

const createUser = async (userData) => {
  logger.debug(`[POSTGRES] Creating sso_users entry | email: ${userData.email}`);
  const row = await SsoUser.create({
    ...userData,
    email: userData.email?.toLowerCase(),
  });
  return normalizeUser(row);
};

const updateUser = async (userId, updates) => {
  logger.debug(`[POSTGRES] Updating sso_users entry | user_id: ${userId}`);
  await SsoUser.update(updates, { where: { user_id: userId } });
};

const findUserById = async (userId) => {
  logger.debug(`[POSTGRES] Query sso_users | user_id: ${userId}`);
  const row = await SsoUser.findByPk(userId);
  return normalizeUser(row);
};

const listUsersByCompany = async (companyId) => {
  logger.debug(`[POSTGRES] Query sso_users | company_id: ${companyId} | all`);
  const rows = await SsoUser.findAll({
    where: { company_id: companyId },
    order: [['created_at', 'ASC']],
  });
  return rows.map(normalizeUser);
};

const deleteUser = async (userId) => {
  logger.debug(`[POSTGRES] Deleting sso_users entry | user_id: ${userId}`);
  const deleted = await SsoUser.destroy({ where: { user_id: userId } });
  return deleted > 0;
};

// ── Save SSO Config (write path) ──────────────────────────────────────────────

// 1a — one SSO config per owner_tenant_id: if this owner already has a config on
// a DIFFERENT domain, delete it first (prevents ghost rows where the same admin
// owns multiple tenants after re-configuring).
const removeStaleOwnerConfig = async (owner_tenant_id, newDomain, tx) => {
  if (!owner_tenant_id) return;
  const ownerExisting = await SsoIntegration.findOne({ where: { owner_tenant_id }, transaction: tx });
  if (!ownerExisting || ownerExisting.domains === newDomain) return;
  const oldCid = ownerExisting.company_id;
  logger.info(`[POSTGRES] Owner already has config on ${ownerExisting.domains} — removing before save | old_company_id: ${oldCid}`, { action: 'owner_config_replaced' });
  await JitMapping.destroy({ where: { company_id: oldCid }, transaction: tx });
  await OidcConfiguration.destroy({ where: { company_id: oldCid }, transaction: tx });
  await SamlConfiguration.destroy({ where: { company_id: oldCid }, transaction: tx });
  await SsoIntegration.destroy({ where: { company_id: oldCid }, transaction: tx });
};

// Encrypts the client secret + private key (or reuses the stored key when
// keep_existing_cert is set and no new key was uploaded), then upserts the row.
const upsertOidcConfig = async (company_id, fields, tx) => {
  const { client_id, auth_method, client_secret, redirect_uri, private_key_b64, client_cert_thumbprint, keep_existing_cert } = fields;

  // Encrypt the client secret before storing — never stored as plain text
  const encryptedSecret = client_secret ? encrypt(client_secret) : null;
  logger.debug(`[POSTGRES] Client secret encrypted for storage | company_id: ${company_id}`);

  // Client Certificate (private_key_jwt) — encrypt the base64(PEM) key at rest.
  let encryptedPrivateKey = private_key_b64 ? encrypt(private_key_b64) : null;
  let resolvedThumbprint  = client_cert_thumbprint || null;
  if (keep_existing_cert && !private_key_b64) {
    const existingOidc = await OidcConfiguration.findOne({ where: { company_id }, transaction: tx });
    if (existingOidc) {
      encryptedPrivateKey = existingOidc.private_key_enc;
      resolvedThumbprint  = existingOidc.client_cert_thumbprint;
      logger.debug(`[POSTGRES] Reusing existing private key for company_id: ${company_id}`);
    }
  } else if (encryptedPrivateKey) {
    logger.debug(`[POSTGRES] Private key encrypted for storage | company_id: ${company_id}`);
  }

  await OidcConfiguration.upsert({
    company_id,
    client_id,
    client_auth_method:     auth_method,
    client_secret_enc:      encryptedSecret,
    private_key_enc:        encryptedPrivateKey,
    client_cert_thumbprint: resolvedThumbprint,
    scope:                  defaults.OIDC_SCOPE,
    redirect_uri:           redirect_uri || defaults.OIDC_REDIRECT_URI,
  }, { transaction: tx });
};

// Upserts the SAML config, reusing the stored IdP cert when keep_existing_cert
// is set and no new cert was uploaded.
const upsertSamlConfig = async (company_id, fields, tx) => {
  const { entity_id, sso_url, acs_url, certificate, cert_expiry, sign_auth, keep_existing_cert } = fields;

  let resolvedCert = certificate || null;
  if (keep_existing_cert && !certificate) {
    const existingSaml = await SamlConfiguration.findOne({ where: { company_id }, transaction: tx });
    if (existingSaml) {
      resolvedCert = existingSaml.certificate;
      logger.debug(`[POSTGRES] Reusing existing SAML cert for company_id: ${company_id}`);
    }
  }
  await SamlConfiguration.upsert({
    company_id,
    entity_id:   entity_id || defaults.SAML_ENTITY_ID,
    sso_url,
    acs_url:     acs_url   || defaults.SAML_ACS_URL,
    certificate: resolvedCert,
    cert_expiry: cert_expiry || null,
    sign_auth:   sign_auth  || false,
  }, { transaction: tx });
};

// Replaces all JIT mappings for a company (delete-then-insert within the tx).
const replaceJitMappings = async (company_id, jit_enabled, jit_mappings, tx) => {
  await JitMapping.destroy({ where: { company_id }, transaction: tx });
  if (!jit_enabled || !jit_mappings?.length) return;
  const rows = jit_mappings
    .filter(m => m.zdna_role && m.mapping_source)
    .map((m, i) => ({
      company_id,
      mapping_source: m.mapping_source,
      mapping_value:  m.mapping_value || null,
      role_id:        m.zdna_role,
      priority:       m.priority ?? i + 1,   // normalised upstream (honours frontend `order`)
      status:         'active',
    }));
  await JitMapping.bulkCreate(rows, { transaction: tx });
};

const saveSsoConfig = async ({
  company_id: proposed_company_id, protocol, idp, domains, tenant_id, entra_tenant_id,
  owner_tenant_id, owner_company_name,
  client_id, auth_method, client_secret, redirect_uri,
  sso_url, entity_id, acs_url, certificate, cert_expiry,
  sign_auth,
  private_key_b64, client_cert_thumbprint,
  keep_existing_cert,
  jit_enabled, jit_mappings,
}) => {
  const sequelize = require('../../config/db');
  const tx = await sequelize.transaction();
  try {
    const newDomain = domains.toLowerCase();

    // 1a — enforce one SSO config per owner (delete a prior config on another domain)
    await removeStaleOwnerConfig(owner_tenant_id, newDomain, tx);

    // 1b — reject if a DIFFERENT owner already owns this domain
    const existing = await SsoIntegration.findOne({ where: { domains: newDomain }, transaction: tx });
    if (existing && owner_tenant_id && existing.owner_tenant_id && existing.owner_tenant_id !== owner_tenant_id) {
      const conflictErr = new Error('Domain is already configured by another organisation');
      conflictErr.statusCode = 409;
      conflictErr.code = 'DOMAIN_ALREADY_EXISTS';
      throw conflictErr;
    }
    const company_id = existing ? existing.company_id : proposed_company_id;

    // upsert sso_integrations (update if exists, insert if not)
    await SsoIntegration.upsert({
      company_id,
      idp:             idp || 'microsoft_entra',
      entra_tenant_id: entra_tenant_id || tenant_id || null,
      owner_tenant_id:    owner_tenant_id || null,
      owner_company_name: owner_company_name || null,
      domains:         newDomain,
      protocol,
      sso_status:      'active',
      jit_enabled:     !!jit_enabled,
    }, { transaction: tx });

    // 2 — protocol-specific config
    if (protocol === 'oidc') {
      await upsertOidcConfig(company_id, { client_id, auth_method, client_secret, redirect_uri, private_key_b64, client_cert_thumbprint, keep_existing_cert }, tx);
    }
    if (protocol === 'saml') {
      await upsertSamlConfig(company_id, { entity_id, sso_url, acs_url, certificate, cert_expiry, sign_auth, keep_existing_cert }, tx);
    }

    // 3 — replace jit_mappings
    await replaceJitMappings(company_id, jit_enabled, jit_mappings, tx);

    await tx.commit();
    logger.debug(`[POSTGRES] SSO config saved | company_id: ${company_id}`);
  } catch (err) {
    await tx.rollback();
    throw err;
  }
};

// ── Admin: retrieve full SSO config (secrets masked) ─────────────────────────

const getSsoConfigDetails = async ({ company_id, domain, owner_tenant_id }) => {
  let integration = null;
  if (company_id) {
    integration = await SsoIntegration.findOne({ where: { company_id } });
  } else if (domain) {
    integration = await SsoIntegration.findOne({ where: { domains: domain.toLowerCase() } });
  } else if (owner_tenant_id) {
    // Look up the config the given admin (tenant) configured, so on next login
    // we can show them their own SSO setup.
    integration = await SsoIntegration.findOne({ where: { owner_tenant_id } });
  }
  if (!integration) return null;

  const intData = integration.toJSON();
  const cid     = intData.company_id;

  const [oidcRow, samlRow, jitRows] = await Promise.all([
    OidcConfiguration.findOne({ where: { company_id: cid } }),
    SamlConfiguration.findOne({ where: { company_id: cid } }),
    JitMapping.findAll({ where: { company_id: cid }, order: [['priority', 'ASC']] }),
  ]);

  const oidc = oidcRow ? oidcRow.toJSON() : null;
  if (oidc) {
    // Never expose secrets — only indicate whether one is configured
    oidc.client_secret_set = !!oidc.client_secret_enc;
    delete oidc.client_secret_enc;
    delete oidc.private_key_enc;
  }
  const saml = samlRow ? samlRow.toJSON() : null;
  if (saml) delete saml.sp_private_key_enc;

  // Enrich each mapping with role_name — the console's JIT Role dropdown is
  // fed by RMS role names (not zdna_roles.role_id), so the edit view needs
  // the name to pre-select the right option.
  const jitMappingRows = jitRows.map(r => r.toJSON());
  const roleIds       = [...new Set(jitMappingRows.map(m => m.role_id).filter(Boolean))];
  const roles         = await getRolesByIds(roleIds);
  const roleNameById  = new Map(roles.map(r => [r.role_id, r.role_name]));

  return {
    integration:  intData,
    oidc_config:  oidc,
    saml_config:  saml,
    jit_mappings: jitMappingRows.map(m => ({ ...m, role_name: roleNameById.get(m.role_id) || null })),
  };
};

// ── Admin: activate / deactivate SSO for a company ───────────────────────────

const setSsoStatus = async (companyId, status) => {
  const [count] = await SsoIntegration.update(
    { sso_status: status },
    { where: { company_id: companyId } },
  );
  logger.info(`[POSTGRES] SSO status updated | company_id: ${companyId} | status: ${status} | rows: ${count}`);
  return count > 0;
};

// ── Admin: delete SSO config (integration + protocol config + JIT mappings) ──

const deleteSsoConfig = async (companyId) => {
  const sequelize = require('../../config/db');
  const tx = await sequelize.transaction();
  try {
    // Child rows first — manual tables have no DB-level ON DELETE CASCADE
    await OidcConfiguration.destroy({ where: { company_id: companyId }, transaction: tx });
    await SamlConfiguration.destroy({ where: { company_id: companyId }, transaction: tx });
    await JitMapping.destroy({ where: { company_id: companyId }, transaction: tx });
    const count = await SsoIntegration.destroy({ where: { company_id: companyId }, transaction: tx });
    await tx.commit();
    logger.info(`[POSTGRES] SSO config deleted | company_id: ${companyId} | found: ${count > 0}`);
    return count > 0;
  } catch (err) {
    await tx.rollback();
    throw err;
  }
};

// ── Cache invalidation (no-op — Postgres is always fresh) ────────────────────

const invalidateDomainCache = (domain) => {
  logger.debug(`[POSTGRES] invalidateDomainCache called for ${domain} — no-op`);
};

module.exports = {
  getSsoIntegrationByDomain,
  getSsoIntegrationByCompanyId,
  getSsoIntegrationByEntraTenantId,
  getOidcConfig,
  getSamlConfig,
  getSamlConfigByAcsUrl,
  getJitMappings,
  getRolesByIds,
  getAllRoles,
  findUserByOid,
  findUserByEmail,
  findUserById,
  listUsersByCompany,
  createUser,
  updateUser,
  deleteUser,
  saveSsoConfig,
  getSsoConfigDetails,
  setSsoStatus,
  deleteSsoConfig,
  invalidateDomainCache,
};
