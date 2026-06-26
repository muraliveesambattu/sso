/**
 * User Resolution Service
 *
 * Post-authentication layer that runs after SAML/OIDC token validation.
 * Handles two modes based on the company's jit_enabled flag:
 *
 *   JIT ON  → auto-create user on first login; re-sync roles on every login
 *   JIT OFF → verify user is pre-provisioned; allow or deny with 403
 */

const crypto = require('crypto');
const { logger }    = require('../../config/logger');
const { isEnabled } = require('../featureFlag.service');
const {
  getSsoIntegrationByCompanyId,
  getJitMappings,
  getRolesByIds,
  findUserByOid,
  findUserByEmail,
  createUser,
  updateUser,
} = require('../db/ssoDataService');

// ── Claim Extractors ──────────────────────────────────────────────────────────

/**
 * Normalises identity claims from either SAML attributes or OIDC id_token claims
 * into a consistent shape: { email, oid, displayName, groups }
 */
// Normalize a SAML groups attribute (which may be an array, a single value,
// or absent) into an array.
const toGroupArray = (value) => {
  if (Array.isArray(value)) return value;
  return value ? [value] : [];
};

const extractIdentity = (claims, protocol) => {
  if (protocol === 'saml') {
    const a = claims; // SAML attributes object (already extracted)
    return {
      email: a.emailaddress || a.email || a['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] || null,
      oid: a.objectidentifier || a['http://schemas.microsoft.com/identity/claims/objectidentifier'] || null,
      displayName: a.name || a.displayname || a.givenname || null,
      groups: toGroupArray(a.groups)
    };
  }

  // OIDC
  return {
    email: claims.email || claims.preferred_username || claims.upn || null,
    oid: claims.oid || claims.sub || null,
    displayName: claims.name || claims.preferred_username || null,
    groups: Array.isArray(claims.groups) ? claims.groups : []
  };
};

// ── Role Resolution ───────────────────────────────────────────────────────────

/**
 * Maps Entra group memberships to internal role_ids using jit_mappings.
 * Runs on EVERY login to keep roles in sync.
 *
 * Mapping priority (lower number = higher priority):
 *   mapping_source = 'group'   → matched by group ID/name
 *   mapping_source = 'default' → fallback if no group matches
 */
const resolveRoles = async (companyId, groups) => {
  const mappings = await getJitMappings(companyId);
  const sorted   = mappings.sort((a, b) => a.priority - b.priority);

  const assignedRoleIds = new Set();

  // Pass 1 — match by group membership
  for (const mapping of sorted) {
    if (mapping.mapping_source === 'group' && groups.includes(mapping.mapping_value)) {
      assignedRoleIds.add(mapping.role_id);
    }
  }

  // Pass 2 — fallback to default mapping if no group matched
  if (assignedRoleIds.size === 0) {
    const defaultMapping = sorted.find(m => m.mapping_source === 'default');
    if (defaultMapping) assignedRoleIds.add(defaultMapping.role_id);
  }

  const roleIds = [...assignedRoleIds];
  return getRolesByIds(roleIds);
};

// User store helpers delegate to localSSO.service.js (reads/writes src/data/ssoConfig.json)

// ── Main Export ───────────────────────────────────────────────────────────────

/**
 * Resolves a user after successful SAML/OIDC authentication.
 *
 * @param {string} companyId      - company_id from SSO integration
 * @param {object} claims         - raw claims from SAML attributes or OIDC id_token
 * @param {string} protocol       - 'saml' | 'oidc'
 * @returns {{ user, roles, action }} - resolved user, assigned roles, and action taken
 */
const resolveUser = async (companyId, claims, protocol) => {
  // Step 1: Get jit_enabled for this company
  const integration = await getSsoIntegrationByCompanyId(companyId);

  if (!integration) {
    const err = new Error(`SSO integration not found for company: ${companyId}`);
    err.statusCode = 404;
    err.code = 'INTEGRATION_NOT_FOUND';
    throw err;
  }

  // ── Feature flag: jit_enabled overrides DB setting ──────────────────────────
  // Flag takes priority over sso_integrations.jit_enabled column.
  // This lets admins disable JIT without changing the SSO config record.
  const jitFlag    = await isEnabled(companyId, 'jit_enabled');
  const jitEnabled = integration.jit_enabled === true && jitFlag;

  if (integration.jit_enabled && !jitFlag) {
    logger.info('JIT provisioning disabled by feature flag', {
      action: 'jit_flag_blocked', company_id: companyId,
    });
  }

  // Step 2: Extract normalised identity
  const identity = extractIdentity(claims, protocol);

  if (!identity.oid || !identity.email) {
    const err = new Error('Identity claims missing required fields: oid and email');
    err.statusCode = 400;
    err.code = 'MISSING_IDENTITY_CLAIMS';
    throw err;
  }

  // ── JIT ENABLED ────────────────────────────────────────────────────────────
  if (jitEnabled) {
    const roles = await resolveRoles(companyId, identity.groups);

    let user = await findUserByOid(companyId, identity.oid);
    let action;

    if (!user) {
      // First login — create user
      user = await createUser({
        user_id:         crypto.randomUUID(),
        company_id:      companyId,
        email:           identity.email,
        oid:             identity.oid,
        display_name:    identity.displayName,
        roles:           roles.map(r => r.role_id),
        login_method:    'sso',   // records that this user authenticates via SSO
        jit_provisioned: true,
        last_login:      new Date().toISOString(),
      });
      action = 'created';
      logger.debug('[JIT] User created:', identity.email, '| roles:', roles.map(r => r.role_id));
    } else {
      // Re-login — sync roles + update last_login
      await updateUser(user.user_id || user.id, {
        roles:        roles.map(r => r.role_id),
        display_name: identity.displayName || user.display_name,
        last_login:   new Date().toISOString(),
      });
      action = 'updated';
      logger.debug('[JIT] User updated:', identity.email, '| roles:', roles.map(r => r.role_id));
    }

    return { user, roles, action };
  }

  // ── JIT DISABLED (non-JIT) ─────────────────────────────────────────────────
  // Step A: Find user by OID first (most reliable), then fall back to email
  let user = await findUserByOid(companyId, identity.oid);
  if (!user) user = await findUserByEmail(companyId, identity.email);

  // Step B: User not found — not provisioned for this company
  if (!user) {
    const err = new Error('You Are not allowed to login using SSO');
    err.statusCode = 403;
    err.code = 'USER_NOT_PROVISIONED';
    throw err;
  }

  // Step C: Verify user's login method is SSO.
  // If the user was created via a different auth method (e.g. password),
  // deny SSO login to prevent auth method bypass.
  if (user.login_method && user.login_method !== 'sso') {
    const err = new Error('You Are not allowed to login using SSO');
    err.statusCode = 403;
    err.code = 'LOGIN_METHOD_NOT_ALLOWED';
    throw err;
  }

  // Step D: Collect role name and id, then trigger login
  const roles = await getRolesByIds(user.roles || []);
  logger.debug('[NON-JIT] User login:', identity.email, '| login_method:', user.login_method || 'sso', '| roles:', user.roles);

  // Update last_login — roles unchanged for non-JIT users
  await updateUser(user.user_id || user.id, { last_login: new Date().toISOString() });

  return { user, roles, action: 'login' };
};

module.exports = { resolveUser };
