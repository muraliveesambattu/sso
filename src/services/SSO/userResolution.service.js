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
    const attrs = claims; // SAML attributes object (already extracted)
    return {
      email: attrs.emailaddress || attrs.email || attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] || null,
      oid: attrs.objectidentifier || attrs['http://schemas.microsoft.com/identity/claims/objectidentifier'] || null,
      displayName: attrs.name || attrs.displayname || attrs.givenname || null,
      groups: toGroupArray(attrs.groups),
      // Optional mapping attributes — present only when the Entra admin adds
      // them to the SAML claim configuration (user.department / user.jobtitle
      // / app roles). Absent attributes simply never match a mapping.
      department: attrs.department || attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department'] || null,
      jobTitle:   attrs.jobtitle || attrs.jobTitle || attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/jobtitle'] || null,
      appRoles:   toGroupArray(attrs.role || attrs.roles),
      // Full attribute bag — lets JIT mappings match on ANY Entra claim name,
      // not just the 4 named ones above (see matchesMapping's default case).
      raw: attrs,
    };
  }

  // OIDC — department/jobTitle are enriched from Graph by the token-exchange
  // step (the id_token itself never carries them); `roles` is Entra app roles.
  return {
    email: claims.email || claims.preferred_username || claims.upn || null,
    oid: claims.oid || claims.sub || null,
    displayName: claims.name || claims.preferred_username || null,
    groups: Array.isArray(claims.groups) ? claims.groups : [],
    department: claims.department || null,
    jobTitle:   claims.jobTitle || claims.jobtitle || null,
    appRoles:   Array.isArray(claims.roles) ? claims.roles : [],
    // Full claims bag (id_token + any Graph enrichment already merged in by
    // the caller) — lets JIT mappings match on ANY claim name, not just the
    // 4 named ones above.
    raw: claims,
  };
};

// ── Role Resolution ───────────────────────────────────────────────────────────

/**
 * Maps the user's Entra attributes to internal role_ids using jit_mappings.
 * Runs on EVERY login to keep roles in sync.
 *
 * Named mapping sources (checked in priority order, lower = higher):
 *   'group'      → mapping_value matched against Entra group IDs (exact)
 *   'department' → matched against the user's department (case-insensitive)
 *   'jobtitle'   → matched against the user's job title (case-insensitive)
 *   'role'       → matched against Entra APP roles claim (case-insensitive)
 *   'default'    → fallback when nothing above matched
 * Anything else is treated as a raw Entra claim/attribute name and looked up
 * directly against the token/assertion (identity.raw) — this is what lets an
 * admin key JIT off any claim they've configured in Entra, not just the 4
 * named ones above (which exist because they're the common case and get
 * normalisation + Graph enrichment for OIDC).
 *
 * Semantics: ALL matching mappings accumulate (a user in two mapped groups
 * gets both roles); 'default' applies only when no other source matched.
 */
const norm = (v) => (typeof v === 'string' ? v.trim().toLowerCase() : v);

const matchesMapping = (mapping, identity) => {
  switch (mapping.mapping_source) {
    case 'group':
      // Group object-IDs are exact identifiers — no case folding
      return identity.groups.includes(mapping.mapping_value);
    case 'department':
      return !!identity.department && norm(identity.department) === norm(mapping.mapping_value);
    case 'jobtitle':
      return !!identity.jobTitle && norm(identity.jobTitle) === norm(mapping.mapping_value);
    case 'role':
      return identity.appRoles.some(r => norm(r) === norm(mapping.mapping_value));
    case 'default':
      return false; // 'default' is handled as the fallback pass
    default: {
      // Claim keys as Entra actually sends them are case-sensitive (e.g.
      // 'employeeType'), but mapping_source is normalised to lowercase at
      // save time — so the lookup itself must be case-insensitive.
      const rawKeys   = identity.raw ? Object.keys(identity.raw) : [];
      const matchedKey = rawKeys.find(k => norm(k) === norm(mapping.mapping_source));
      const raw = matchedKey !== undefined ? identity.raw[matchedKey] : undefined;
      if (raw === undefined || raw === null) {
        // The claim name itself isn't present in this token/assertion at
        // all — most likely a typo'd or misconfigured claim name, since a
        // legitimate value mismatch would still have the key present.
        logger.warn('JIT mapping references a claim not present in the token — check the claim name spelling', {
          action: 'jit_unknown_claim', mapping_source: mapping.mapping_source,
        });
        return false;
      }
      const rawValues = Array.isArray(raw) ? raw : [raw];
      return rawValues.some(v => norm(v) === norm(mapping.mapping_value));
    }
  }
};

const resolveRoles = async (companyId, identity) => {
  const mappings = await getJitMappings(companyId);
  const sorted   = mappings.sort((a, b) => a.priority - b.priority);

  const assignedRoleIds = new Set();

  // Pass 1 — match by attribute (group / department / jobtitle / app role)
  for (const mapping of sorted) {
    if (matchesMapping(mapping, identity)) {
      assignedRoleIds.add(mapping.role_id);
    }
  }

  // Pass 2 — fallback to default mapping if nothing matched
  if (assignedRoleIds.size === 0) {
    const defaultMapping = sorted.find(m => m.mapping_source === 'default');
    if (defaultMapping) assignedRoleIds.add(defaultMapping.role_id);
  }

  // Per LLD 8.2 §7c: a JIT user who matches no mapping AND has no 'default'
  // mapping is denied login — rather than admitted with an empty role set,
  // which the console's deny-list enforcement would treat as default-allow.
  // Tenants can add a 'default' mapping to admit unmatched users with a floor role.
  if (assignedRoleIds.size === 0) {
    const err = new Error('No JIT role mapping matched this user and no default mapping is configured');
    err.statusCode = 403;
    err.code = 'JIT_NO_MATCHING_ROLE';
    throw err;
  }

  const roleIds = [...assignedRoleIds];
  const known   = await getRolesByIds(roleIds);

  // jit_mappings.role_id may hold a role name from the tenant's own RMS
  // catalog rather than a local zdna_roles id (RMS roles are per-tenant and
  // not enumerable here — see saveSsoConfig.service.js). Any id not found
  // locally is passed through as-is so the user still gets a role label;
  // real permissions for RMS-integrated companies come from
  // permissionResolver's RMS-by-email lookup regardless of this value.
  const knownIds    = new Set(known.map(r => r.role_id));
  const passthrough = roleIds
    .filter(id => !knownIds.has(id))
    .map(id => ({ role_id: id, role_name: id, permissions: [] }));

  return [...known, ...passthrough];
};

// User store helpers delegate to the PostgreSQL data layer (postgresSSO.service.js)

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
  // Step 1: Load the integration and the jit_enabled flag in parallel — they're
  // independent reads, so awaiting them sequentially just adds login latency.
  const [integration, jitFlag] = await Promise.all([
    getSsoIntegrationByCompanyId(companyId),
    isEnabled(companyId, 'jit_enabled'),
  ]);

  if (!integration) {
    const err = new Error(`SSO integration not found for company: ${companyId}`);
    err.statusCode = 404;
    err.code = 'INTEGRATION_NOT_FOUND';
    throw err;
  }

  // ── Feature flag: jit_enabled overrides DB setting ──────────────────────────
  // Flag takes priority over sso_integrations.jit_enabled column.
  // This lets admins disable JIT without changing the SSO config record.
  const jitEnabled = integration.jit_enabled === true && jitFlag;

  if (integration.jit_enabled && !jitFlag) {
    logger.info('JIT provisioning disabled by feature flag', {
      action: 'jit_flag_blocked', company_id: companyId,
    });
  }

  // Step 2: Extract normalised identity
  const identity = extractIdentity(claims, protocol);

  // Require oid and email to be non-empty STRINGS. A malformed SAML/OIDC
  // assertion can yield a nested object/array that is truthy but unusable — and
  // oid is used downstream as a DB key / Firebase UID.
  const isNonEmptyString = (v) => typeof v === 'string' && v.trim().length > 0;
  if (!isNonEmptyString(identity.oid) || !isNonEmptyString(identity.email)) {
    const err = new Error('Identity claims missing required fields: oid and email');
    err.statusCode = 400;
    err.code = 'MISSING_IDENTITY_CLAIMS';
    throw err;
  }

  // ── JIT ENABLED ────────────────────────────────────────────────────────────
  if (jitEnabled) {
    const roles = await resolveRoles(companyId, identity);

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
      logger.info('[JIT] User created', { action: 'jit_user_created', email: identity.email, roles: roles.map(r => r.role_id) });
    } else {
      // Re-login — sync roles + update last_login
      const updates = {
        roles:        roles.map(r => r.role_id),
        display_name: identity.displayName || user.display_name,
        last_login:   new Date().toISOString(),
      };
      await updateUser(user.user_id || user.id, updates);
      user = { ...user, ...updates }; // reflect the freshly-saved fields, not the stale row
      action = 'updated';
      logger.info('[JIT] User updated', { action: 'jit_user_updated', email: identity.email, roles: updates.roles });
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
  logger.info('[NON-JIT] User login', { action: 'non_jit_user_login', email: identity.email, login_method: user.login_method || 'sso' });

  // Update last_login — roles unchanged for non-JIT users. Pre-provisioned
  // users are created with a `pending:` oid placeholder (the real Entra oid
  // is unknown until first login) — backfill it here so future logins match
  // by oid instead of falling through to the email lookup.
  const nonJitUpdates = { last_login: new Date().toISOString() };
  if (!user.oid || user.oid.startsWith('pending:')) {
    nonJitUpdates.oid = identity.oid;
  }
  await updateUser(user.user_id || user.id, nonJitUpdates);
  user = { ...user, ...nonJitUpdates }; // reflect the freshly-saved fields, not the stale row

  return { user, roles, action: 'login' };
};

module.exports = { resolveUser };
