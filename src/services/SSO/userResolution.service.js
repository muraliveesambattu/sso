/**
 * User Resolution Service
 *
 * Post-authentication layer that runs after SAML/OIDC token validation.
 * Handles two modes based on the company's jit_enabled flag:
 *
 *   JIT ON  → auto-create user on first login; re-sync roles on every login
 *   JIT OFF → verify user is pre-provisioned; allow or deny with 403
 *
 * Both modes deny the login with 403 NO_ROLE_ASSIGNED when the user ends up
 * with no role — an unmatched JIT user (and no 'default' mapping), or a
 * pre-provisioned user whose record carries no roleId.
 */

const crypto = require('node:crypto');
const { logger } = require('../../config/logger');
const { isEnabled } = require('../featureFlag.service');
const admin = require('firebase-admin');

const {
  getSsoIntegrationByCompanyId,
  getJitMappings,
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
      groups: toGroupArray(a.groups),
      // Optional mapping attributes — present only when the Entra admin adds
      // them to the SAML claim configuration (user.department / user.jobtitle
      // / app roles). Absent attributes simply never match a mapping.
      department: a.department || a['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department'] || null,
      jobTitle: a.jobtitle || a.jobTitle || a['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/jobtitle'] || null,
      appRoles: toGroupArray(a.role || a.roles),
      // Full attribute bag — lets JIT mappings match on ANY Entra claim name,
      // not just the 4 named ones above (see matchesMapping's default case).
      raw: a,
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
    jobTitle: claims.jobTitle || claims.jobtitle || null,
    appRoles: Array.isArray(claims.roles) ? claims.roles : [],
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
      const rawKeys = identity.raw ? Object.keys(identity.raw) : [];
      const matchedKey = rawKeys.find(k => norm(k) === norm(mapping.mapping_source));
      const raw = matchedKey === undefined ? undefined : identity.raw[matchedKey];
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
  const sorted = mappings.sort((a, b) => a.priority - b.priority);

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

  const roleIds = [...assignedRoleIds];

  // role_name is stored on the mapping itself — no zdna_roles JOIN in the JIT
  // flow. Permissions for JIT/SSO users come from permissionResolver (RMS →
  // tenant roleConfig), not zdna_roles, so each row carries an empty
  // permissions array here.
  const nameById = new Map(sorted.map(m => [m.role_id, m.role_name]));
  return roleIds.map(id => ({
    role_id: id,
    role_name: nameById.get(id) || id,
    permissions: [],
  }));
};

// ── Role Denial ───────────────────────────────────────────────────────────────

// Shared denial for both modes — a login that resolves to no role would sign
// the user in with no permissions, so refuse it instead. The email/oid are
// logged so support can tell WHO was blocked without reproducing the login.
const denyNoRole = (companyId, protocol, identity, reason) => {
  logger.warn('Login denied — no role resolved for this user', {
    action: 'login_denied_no_role',
    company_id: companyId,
    protocol,
    email: identity.email,
    oid: identity.oid,
    reason,
  });
  const err = new Error('No role assigned to this user');
  err.statusCode = 403;
  err.code = 'NO_ROLE_ASSIGNED';
  throw err;
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
  // Step 1: Get jit_enabled for this company
  const integration = await getSsoIntegrationByCompanyId(companyId);

  if (!integration) {
    const err = new Error(`SSO integration not found for company: ${companyId}`);
    err.statusCode = 404;
    err.code = 'INTEGRATION_NOT_FOUND';
    throw err;
  }

  // ── Feature flag: jit_enabled overrides DB setting ──────────────────────────
  // Flag takes priority over the sso_integrations.jit_status column.
  // This lets admins disable JIT without changing the SSO config record.
  const jitFlag = await isEnabled(companyId, 'jit_enabled');
  const jitEnabled = integration.jit_status === true && jitFlag;

  if (integration.jit_status && !jitFlag) {
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
    const roles = await resolveRoles(companyId, identity);

    // No mapping matched and no 'default' mapping exists. Checked BEFORE any
    // create/update so a denied attempt leaves no orphan user row behind and
    // does not wipe an existing user's stored roles.
    if (roles.length === 0) {
      denyNoRole(companyId, protocol, identity, 'no_jit_mapping_matched');
    }

    let user = await findUserByOid(companyId, identity.oid);
    let action;

    if (user) {
      // Re-login — sync roles + update last_login
      await updateUser(user.user_id || user.id, {
        roles: roles.map(r => r.role_id),
        display_name: identity.displayName || user.display_name,
        last_login: new Date().toISOString(),
      });
      action = 'updated';
      logger.debug('[JIT] User updated:', identity.email, '| roles:', roles.map(r => r.role_id));
    } else {
      // First login — create user
      user = await createUser({
        user_id: crypto.randomUUID(),
        company_id: companyId,
        email: identity.email,
        oid: identity.oid,
        display_name: identity.displayName,
        roles: roles.map(r => r.role_id),
        login_method: 'sso',   // records that this user authenticates via SSO
        jit_provisioned: true,
        last_login: new Date().toISOString(),
      });
      action = 'created';
      logger.debug('[JIT] User created:', identity.email, '| roles:', roles.map(r => r.role_id));
    }

    return { user, roles, action };
  }

  // ── JIT DISABLED (non-JIT) ─────────────────────────────────────────────────
  // Step A — Firestore lookup by email under tenant
  logger.debug('[NON-JIT] Looking up user | companyId:', companyId, '| email:', identity.email);

  const snapshot = await admin.firestore()
    .collection('tenants')
    .doc(companyId)
    .collection('users')
    .where('email', '==', identity.email)
    .limit(1)
    .get()

  const user = snapshot.empty ? null : snapshot.docs[0].data()

  // Step B — Not provisioned
  if (!user) {
    logger.warn('[NON-JIT] User not found in Firestore | email:', identity.email, '| companyId:', companyId);
    const err = new Error('You are not allowed to login using SSO');
    err.statusCode = 403;
    err.code = 'USER_NOT_PROVISIONED';
    throw err;
  }

  // Step C — Wrong login method
  if (user.loginMethod !== 'Entra SSO') {
    logger.warn('[NON-JIT] Login method mismatch | loginMethod:', user.loginMethod);
    const err = new Error('You are not allowed to login using zDNA SSO');
    err.statusCode = 403;
    err.code = 'LOGIN_METHOD_NOT_ALLOWED';
    throw err;
  }

  // Step D — Expired
  if (user.status === 'expired') {
    const err = new Error('Your account has expired. Please contact your administrator');
    err.statusCode = 403;
    err.code = 'USER_EXPIRED';
    throw err;
  }

  // Step E — Resolve role
  const roleId = user.roleId || user.role_id;

  // Step E.1 — Deny when the provisioned user carries no role. Placed BEFORE
  // Step F so a denied attempt is not recorded as a successful login and does
  // not flip an invited user's status to "Joined".
  if (!roleId) {
    denyNoRole(companyId, protocol, identity, 'user_has_no_role_id');
  }

  const roles = [{ role_id: roleId }];

  // Step F — Update lastLoginAt + invited → joined
  const currentTime = Date.now();
  const usersSnapshot = await admin.firestore()
    .collection("tenants")
    .doc(companyId)
    .collection("users")
    .where("UUID", "==", user?.userUUID)
    .get();
  if (!usersSnapshot.empty) {
    const userDoc = usersSnapshot.docs[0];
    const userData = userDoc.data();
    if (userData.loginMethod === "Entra SSO") {
      // Update user document
      await userDoc.ref.update({
        status: "Joined",
        lastLoginTime: currentTime,
        updatedDateTime: currentTime,
      });
      // Update tenant document
      await admin.firestore().collection("tenants").doc(companyId).update({
        lastLoginTime: currentTime,
        updatedDateTime: currentTime,
      });
    }
  }

  logger.debug('[NON-JIT] User login success | email:', identity.email, '| loginMethod:', user.loginMethod, '| roleId:', roleId);

  return { user, roles, action: 'login' };
};

module.exports = { resolveUser };