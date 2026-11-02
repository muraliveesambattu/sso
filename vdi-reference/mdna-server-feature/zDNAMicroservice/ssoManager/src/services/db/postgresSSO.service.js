const crypto = require('node:crypto');
const { Op } = require('sequelize');
const { logger } = require('../../config/logger');
const { defaults } = require('../../config/constants');
const { maskInput } = require('../../utils/shared/maskId.util');
const {
  SsoIntegration,
  SsoDomain,
  OidcConfiguration,
  SamlConfiguration,
  JitMapping,
  SsoUser,
} = require('../../models');
const { encrypt, resolveSecret, decrypt } = require('../../utils/crypto.util');

const resolveEnvRef = (val) => {
  if (typeof val === 'string' && val.startsWith('env:')) {
    return process.env[val.slice(4)] || null;
  }
  return val;
};

// ── sso_integrations ──────────────────────────────────────────────────────────

const getSsoIntegrationByDomain = async (domain) => {
  logger.debug(`[POSTGRES] Query sso_domains | domain: ${domain}`);
  const domainRow = await SsoDomain.findOne({ where: { domain: domain.toLowerCase() } });
  if (!domainRow) {
    logger.debug('[POSTGRES] sso_domains result | found: false');
    return null;
  }
  const row = await SsoIntegration.findOne({
    where: { company_id: domainRow.company_id, sso_status: 'active' },
  });
  logger.debug('[POSTGRES] sso_integrations result', {
    found: !!row,
    protocol: row?.protocol || '-',
    companyIdMasked: maskInput(String(domainRow.company_id)),
  });
  return row ? row.toJSON() : null;
};

const getDomainsByCompanyId = async (companyId) => {
  logger.debug('[POSTGRES] Query sso_domains by companyId', {
    companyIdMasked: maskInput(String(companyId)),
  });
  const rows = await SsoDomain.findAll({
    where: { company_id: companyId },
    order: [['id', 'ASC']],
  });
  return rows.map(r => r.domain);
};

const getSsoIntegrationByEntraTenantId = async (entraTenantId) => {
  logger.debug('[POSTGRES] Query sso_integrations by entra_tenant_id', {
    entraTenantIdMasked: maskInput(String(entraTenantId)),
  });
  const row = await SsoIntegration.findOne({ where: { entra_tenant_id: entraTenantId } });
  return row ? row.toJSON() : null;
};

const getSsoIntegrationByCompanyId = async (companyId) => {
  logger.debug('[POSTGRES] Query sso_integrations by company_id', {
    companyIdMasked: maskInput(String(companyId)),
  });
  const row = await SsoIntegration.findOne({ where: { company_id: companyId } });
  return row ? row.toJSON() : null;
};

// ── oidc_configurations ───────────────────────────────────────────────────────

const getOidcConfig = async (companyId) => {
  logger.debug('[POSTGRES] Query OIDC Config', {
    companyIdMasked: maskInput(String(companyId)),
  });
  const row = await OidcConfiguration.findOne({ where: { company_id: companyId } });
  if (!row) return null;
  const data = row.toJSON();
  return {
    ...data,
    client_secret: resolveSecret(data.client_secret_enc),
    client_cert_enc: resolveSecret(data.private_key_enc),
  };
};

// ── saml_configurations ───────────────────────────────────────────────────────

const getSamlConfig = async (companyId) => {
  logger.debug('[POSTGRES] Query SAML Config', {
    companyIdMasked: maskInput(String(companyId)),
  });
  const row = await SamlConfiguration.findOne({ where: { company_id: companyId } });
  if (!row) return null;
  const data = row.toJSON();
  return {
    ...data,
    entity_id: resolveEnvRef(data.entity_id),
    acs_url: resolveEnvRef(data.acs_url),
    client_secret: data.client_secret_enc ? decrypt(data.client_secret_enc) : null,
    certificate: resolveSecret(data.certificate),
  };
};

const getSamlConfigByAcsUrl = async (acsUrl) => {
  logger.debug('[POSTGRES] Query SAML Config by ACS URL');
  const rows = await SamlConfiguration.findAll();
  const match = rows.map(r => r.toJSON()).find(r => resolveEnvRef(r.acs_url) === acsUrl);
  if (!match) return null;
  return {
    ...match,
    entity_id: resolveEnvRef(match.entity_id),
    acs_url: resolveEnvRef(match.acs_url),
  };
};

// ── jit_mappings ──────────────────────────────────────────────────────────────

const getJitMappings = async (companyId) => {
  logger.debug('[POSTGRES] Query JIT Mapping', {
    companyIdMasked: maskInput(String(companyId)),
  });
  const rows = await JitMapping.findAll({
    where: { company_id: companyId, status: 'active' },
    order: [['priority', 'ASC']],
  });
  return rows.map(r => r.toJSON());
};

// ── sso_users ─────────────────────────────────────────────────────────────────

const normalizeUser = (row) => {
  if (!row) return null;
  const data = row.toJSON ? row.toJSON() : row;
  return { ...data, id: data.user_id };
};

const findUserByOid = async (companyId, oid) => {
  logger.debug('[POSTGRES] Query sso_users by oid', {
    companyIdMasked: maskInput(String(companyId)),
  });
  const row = await SsoUser.findOne({ where: { company_id: companyId, oid } });
  return normalizeUser(row);
};

const findUserByEmail = async (companyId, email) => {
  logger.debug('[POSTGRES] Query sso_users by email', {
    companyIdMasked: maskInput(String(companyId)),
  });
  const row = await SsoUser.findOne({ where: { company_id: companyId, email: email.toLowerCase() } });
  return normalizeUser(row);
};

const createUser = async (userData) => {
  logger.debug('[POSTGRES] Creating sso_users entry', {
    companyIdMasked: maskInput(String(userData.company_id)),
  });
  const row = await SsoUser.create({
    ...userData,
    email: userData.email?.toLowerCase(),
  });
  return normalizeUser(row);
};

const updateUser = async (userId, updates) => {
  logger.debug('[POSTGRES] Updating sso_users entry', {
    userIdMasked: maskInput(String(userId)),
  });
  await SsoUser.update(updates, { where: { user_id: userId } });
};

const findUserById = async (userId) => {
  logger.debug('[POSTGRES] Query sso_users by userId', {
    userIdMasked: maskInput(String(userId)),
  });
  const row = await SsoUser.findByPk(userId);
  return normalizeUser(row);
};

const listUsersByCompany = async (companyId) => {
  logger.debug('[POSTGRES] Query sso_users by company', {
    companyIdMasked: maskInput(String(companyId)),
  });
  const rows = await SsoUser.findAll({
    where: { company_id: companyId },
    order: [['created_at', 'ASC']],
  });
  return rows.map(normalizeUser);
};

const deleteUser = async (userId) => {
  logger.debug('[POSTGRES] Deleting sso_users entry', {
    userIdMasked: maskInput(String(userId)),
  });
  const deleted = await SsoUser.destroy({ where: { user_id: userId } });
  return deleted > 0;
};

// ── Save SSO Config (write path) ──────────────────────────────────────────────

const assertDomainsAvailable = async (domainList, company_id, tx) => {
  const existingDomain = await SsoDomain.findOne({
    where: { domain: { [Op.in]: domainList } },
    transaction: tx,
  });
  if (existingDomain && existingDomain.company_id !== company_id) {
    const conflictErr = new Error('Domain is already configured by another organisation');
    conflictErr.statusCode = 409;
    conflictErr.code = 'DOMAIN_ALREADY_EXISTS';
    throw conflictErr;
  }
};

const replaceDomains = async (company_id, domainList, tx) => {
  logger.debug('[POSTGRES] Replacing domains', {
    companyIdMasked: maskInput(String(company_id)),
    domainCount: domainList.length,
  });
  await SsoDomain.destroy({ where: { company_id }, transaction: tx });
  await SsoDomain.bulkCreate(
    domainList.map(domain => ({ company_id, domain })),
    { transaction: tx },
  );
};

const resolveEncryptedSecret = (client_secret, existingOidc, company_id) => {
  if (client_secret !== undefined) {
    const enc = client_secret ? encrypt(client_secret) : null;
    if (enc) logger.debug('[POSTGRES] Client secret encrypted for storage', { companyIdMasked: maskInput(String(company_id)) });
    return enc;
  }
  if (existingOidc?.client_secret_enc) {
    logger.debug('[POSTGRES] Reusing existing client secret', { companyIdMasked: maskInput(String(company_id)) });
    return existingOidc.client_secret_enc;
  }
  return null;
};

const resolveEncryptedPrivateKey = (private_key_b64, keep_existing_cert, client_cert_thumbprint, existingOidc, company_id) => {
  if ((private_key_b64 === undefined || keep_existing_cert) && !private_key_b64 && existingOidc?.private_key_enc) {
    logger.debug('[POSTGRES] Reusing existing private key', { companyIdMasked: maskInput(String(company_id)) });
    return { encryptedPrivateKey: existingOidc.private_key_enc, resolvedThumbprint: existingOidc.client_cert_thumbprint };
  }
  const encryptedPrivateKey = private_key_b64 ? encrypt(private_key_b64) : null;
  if (encryptedPrivateKey) logger.debug('[POSTGRES] Private key encrypted for storage', { companyIdMasked: maskInput(String(company_id)) });
  return { encryptedPrivateKey, resolvedThumbprint: client_cert_thumbprint || null };
};

const upsertOidcConfig = async ({
  company_id, client_id, auth_method, client_secret, redirect_uri,
  private_key_b64, client_cert_thumbprint, keep_existing_cert,
}, tx) => {
  const needsExisting = client_secret === undefined || private_key_b64 === undefined || keep_existing_cert;
  const existingOidc = needsExisting
    ? await OidcConfiguration.findOne({ where: { company_id }, transaction: tx })
    : null;

  const encryptedSecret = resolveEncryptedSecret(client_secret, existingOidc, company_id);
  const { encryptedPrivateKey, resolvedThumbprint } = resolveEncryptedPrivateKey(
    private_key_b64, keep_existing_cert, client_cert_thumbprint, existingOidc, company_id,
  );

  await OidcConfiguration.upsert({
    company_id,
    client_id,
    client_auth_method: auth_method,
    client_secret_enc: encryptedSecret,
    private_key_enc: encryptedPrivateKey,
    client_cert_thumbprint: resolvedThumbprint,
    scope: defaults.OIDC_SCOPE,
    redirect_uri: redirect_uri || defaults.OIDC_REDIRECT_URI,
  }, { transaction: tx });

  logger.debug('[POSTGRES] OIDC config upserted', {
    companyIdMasked: maskInput(String(company_id)),
  });
};

const upsertSamlConfig = async ({
  company_id, entity_id, sso_url, acs_url, client_secret, certificate,
  cert_expiry, app_id, sign_auth, keep_existing_cert, keep_existing_signing_cert, sp_private_key_b64,
}, tx) => {
  logger.debug('[POSTGRES] upsertSamlConfig', {
    companyIdMasked: maskInput(String(company_id)),
    has_certificate: !!certificate,
    keep_existing_cert,
  });

  let resolvedCert = certificate ? encrypt(certificate) : null;
  if (keep_existing_cert && !certificate) {
    const existingSaml = await SamlConfiguration.findOne({ where: { company_id }, transaction: tx });
    if (existingSaml) {
      resolvedCert = existingSaml.certificate;
      logger.debug('[POSTGRES] Reusing existing SAML cert', { companyIdMasked: maskInput(String(company_id)) });
    } else {
      logger.debug('[POSTGRES] keep_existing_cert=true but no existing SAML row found', { companyIdMasked: maskInput(String(company_id)) });
    }
  }

  logger.debug('[POSTGRES] Upserting saml_configurations', {
    companyIdMasked: maskInput(String(company_id)),
    resolved_cert: !!resolvedCert,
  });

  let resolvedPrivateKey = sp_private_key_b64 ? encrypt(sp_private_key_b64) : null;
  if (keep_existing_signing_cert && !sp_private_key_b64) {
    const existingSaml = await SamlConfiguration.findOne({ where: { company_id }, transaction: tx });
    if (existingSaml?.sp_private_key_enc) resolvedPrivateKey = existingSaml.sp_private_key_enc;
  }
  if (!sign_auth) resolvedPrivateKey = null;

  const existingSaml = await SamlConfiguration.findOne({ where: { company_id }, transaction: tx });
  const encryptedClientSecret = client_secret
    ? encrypt(client_secret)
    : existingSaml?.client_secret_enc || null;

  await SamlConfiguration.upsert({
    company_id,
    entity_id: entity_id || defaults.SAML_ENTITY_ID,
    sso_url,
    app_id,
    client_secret_enc: encryptedClientSecret,
    acs_url: acs_url || defaults.SAML_ACS_URL,
    certificate: resolvedCert,
    cert_expiry: cert_expiry || null,
    sign_authn_request: sign_auth || false,
    sp_private_key_enc: resolvedPrivateKey,
  }, { transaction: tx });

  logger.debug('[POSTGRES] saml_configurations upserted', {
    companyIdMasked: maskInput(String(company_id)),
  });
};

const replaceJitMappings = async (company_id, jit_enabled, jit_mappings, tx) => {
  logger.debug('[POSTGRES] Replacing JIT mappings', {
    companyIdMasked: maskInput(String(company_id)),
    jit_enabled,
    mappingCount: jit_mappings?.length || 0,
  });
  await JitMapping.destroy({ where: { company_id }, transaction: tx });
  if (jit_enabled && jit_mappings?.length) {
    const rows = jit_mappings
      .filter(m => m.zdna_role && m.mapping_source)
      .map((m, i) => ({
        company_id,
        mapping_source: m.mapping_source,
        mapping_value: m.mapping_value || null,
        role_id: m.zdna_role,
        role_name: m.role_name || m.zdna_role,
        priority: m.priority ?? i + 1,
        status: 'active',
      }));
    await JitMapping.bulkCreate(rows, { transaction: tx });
  }
};

const saveSsoConfig = async ({
  company_id, protocol, idp, domains, tenant_id, entra_tenant_id,
  client_id, auth_method, client_secret, redirect_uri,
  sso_url, app_id, entity_id, acs_url, certificate, cert_expiry,
  sign_auth, private_key_b64, client_cert_thumbprint, keep_existing_cert,
  jit_enabled, jit_mappings, keep_existing_signing_cert, sp_private_key_b64, existing_sso_status,
}) => {
  const domainList = (Array.isArray(domains) ? domains : [domains])
    .map(d => String(d).toLowerCase());

  logger.debug('[POSTGRES] saveSsoConfig', {
    companyIdMasked: maskInput(String(company_id)),
    entraTenantIdMasked: maskInput(String(entra_tenant_id || tenant_id)),
    protocol,
    jit_enabled,
  });

  const sequelize = require('../../config/db');
  const tx = await sequelize.transaction();
  try {
    await assertDomainsAvailable(domainList, company_id, tx);
    await SsoIntegration.upsert({
      company_id,
      idp: idp || 'microsoft_entra',
      entra_tenant_id: entra_tenant_id || tenant_id || null,
      protocol,
      sso_status: existing_sso_status ? 'active' : 'inactive',
      jit_status: !!jit_enabled,
    }, { transaction: tx });
    await replaceDomains(company_id, domainList, tx);
    if (protocol === 'oidc') {
      await upsertOidcConfig({
        company_id, client_id, auth_method, client_secret, redirect_uri,
        private_key_b64, client_cert_thumbprint, keep_existing_cert,
      }, tx);
    }
    if (protocol === 'saml') {
      logger.debug('[POSTGRES] saveSsoConfig SAML branch', {
        companyIdMasked: maskInput(String(company_id)),
        entraTenantIdMasked: maskInput(String(entra_tenant_id || tenant_id)),
      });
      await upsertSamlConfig({
        company_id, entity_id, sso_url, acs_url, certificate, cert_expiry, client_secret,
        app_id, sign_auth, keep_existing_cert, keep_existing_signing_cert, sp_private_key_b64,
      }, tx);
    }
    await replaceJitMappings(company_id, jit_enabled, jit_mappings, tx);
    await tx.commit();
    logger.debug('[POSTGRES] SSO config saved successfully', {
      companyIdMasked: maskInput(String(company_id)),
      entraTenantIdMasked: maskInput(String(entra_tenant_id || tenant_id)),
      protocol,
    });
  } catch (err) {
    await tx.rollback();
    throw err;
  }
};

// ── Admin: retrieve full SSO config (secrets masked) ─────────────────────────

const resolveIntegration = async ({ company_id, domain }) => {
  if (company_id) {
    logger.debug('[POSTGRES] resolveIntegration by company_id', {
      companyIdMasked: maskInput(String(company_id)),
    });
    return SsoIntegration.findOne({ where: { company_id } });
  }
  if (domain) {
    logger.debug(`[POSTGRES] resolveIntegration by domain: ${domain}`);
    const domainRow = await SsoDomain.findOne({ where: { domain: domain.toLowerCase() } });
    if (domainRow) {
      return SsoIntegration.findOne({ where: { company_id: domainRow.company_id } });
    }
  }
  return null;
};

const sanitiseOidcRow = (oidcRow, cid) => {
  if (!oidcRow) return null;
  const oidc = oidcRow.toJSON();
  if (oidc.client_secret_enc) {
    try {
      oidc.client_secret = decrypt(oidc.client_secret_enc);
    } catch (e) {
      logger.warn('[POSTGRES] Failed to decrypt client_secret_enc', {
        companyIdMasked: maskInput(String(cid)),
        error: e.message,
      });
      oidc.client_secret = null;
    }
  }
  delete oidc.client_secret_enc;
  delete oidc.private_key_enc;
  return oidc;
};

const sanitiseSamlRow = (samlRow, cid) => {
  if (!samlRow) return null;
  const saml = samlRow.toJSON();
  saml.has_certificate = !!saml.certificate;
  saml.has_signing_certificate = !!saml.sp_private_key_enc;
  delete saml.client_secret_enc;
  delete saml.certificate;
  delete saml.sp_private_key_enc;
  return saml;
};

const getSsoConfigDetails = async ({ company_id, domain }) => {
  logger.debug('[POSTGRES] getSsoConfigDetails', {
    companyIdMasked: maskInput(String(company_id)),
  });

  const integration = await resolveIntegration({ company_id, domain });
  if (!integration) return null;

  const intData = integration.toJSON();
  const cid = intData.company_id;

  logger.debug('[POSTGRES] getSsoConfigDetails integration found', {
    companyIdMasked: maskInput(String(cid)),
    entraTenantIdMasked: maskInput(String(intData.entra_tenant_id)),
    protocol: intData.protocol,
  });

  const [oidcRow, samlRow, jitRows, domainRows] = await Promise.all([
    OidcConfiguration.findOne({ where: { company_id: cid } }),
    SamlConfiguration.findOne({ where: { company_id: cid } }),
    JitMapping.findAll({ where: { company_id: cid }, order: [['priority', 'ASC']] }),
    SsoDomain.findAll({ where: { company_id: cid }, order: [['id', 'ASC']] }),
  ]);

  intData.domains = domainRows.map(d => d.domain);

  return {
    integration: intData,
    oidc_config: sanitiseOidcRow(oidcRow, cid),
    saml_config: sanitiseSamlRow(samlRow, cid),
    jit_mappings: jitRows.map(r => r.toJSON()),
  };
};

// ── Admin: activate / deactivate SSO for a company ───────────────────────────

const setSsoStatus = async (companyId, status) => {
  logger.debug('[POSTGRES] setSsoStatus', {
    companyIdMasked: maskInput(String(companyId)),
    status,
  });
  const [count] = await SsoIntegration.update(
    { sso_status: status },
    { where: { company_id: companyId } },
  );
  logger.info('[POSTGRES] SSO status updated', {
    companyIdMasked: maskInput(String(companyId)),
    status,
    rows: count,
  });
  return count > 0;
};

// ── Admin: delete SSO config (integration + protocol config + JIT mappings) ──

const deleteSsoConfig = async (companyId) => {
  logger.debug('[POSTGRES] deleteSsoConfig', {
    companyIdMasked: maskInput(String(companyId)),
  });
  const sequelize = require('../../config/db');
  const tx = await sequelize.transaction();
  try {
    await OidcConfiguration.destroy({ where: { company_id: companyId }, transaction: tx });
    await SamlConfiguration.destroy({ where: { company_id: companyId }, transaction: tx });
    await JitMapping.destroy({ where: { company_id: companyId }, transaction: tx });
    await SsoDomain.destroy({ where: { company_id: companyId }, transaction: tx });
    const count = await SsoIntegration.destroy({ where: { company_id: companyId }, transaction: tx });
    await tx.commit();
    logger.info('[POSTGRES] SSO config deleted', {
      companyIdMasked: maskInput(String(companyId)),
      found: count > 0,
    });
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
  getDomainsByCompanyId,
  getSsoIntegrationByCompanyId,
  getSsoIntegrationByEntraTenantId,
  getOidcConfig,
  getSamlConfig,
  getSamlConfigByAcsUrl,
  getJitMappings,
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
