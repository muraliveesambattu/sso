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

const crypto = require("node:crypto");
const { logger } = require("../../config/logger");
const { isEnabled } = require("../featureFlag.service");
const admin = require("firebase-admin");
const {
  getSsoIntegrationByCompanyId,
  getJitMappings,
  findUserByOid,
  findUserByEmail,
  createUser,
  updateUser,
} = require("../db/ssoDataService");
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
const normEmail = (v) => (typeof v === "string" ? v.trim().toLowerCase() : v);
const SAML_EMAIL_URI =
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
// Email exactly as the IdP sent it — lookup fallback for Firestore users
// stored with mixed case.
const rawEmail = (claims) =>
  claims?.emailaddress ||
  claims?.email ||
  claims?.[SAML_EMAIL_URI] ||
  claims?.preferred_username ||
  claims?.upn ||
  null;
const extractIdentity = (claims, protocol) => {
  if (protocol === "saml") {
    const a = claims; // SAML attributes object (already extracted)
    return {
      email: normEmail(a.emailaddress || a.email || a[SAML_EMAIL_URI]) || null,
      oid:
        a.objectidentifier ||
        a["http://schemas.microsoft.com/identity/claims/objectidentifier"] ||
        null,
      displayName: a.name || a.displayname || a.givenname || null,
      groups: toGroupArray(a.groups),
      department:
        a.department ||
        a["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department"] ||
        null,
      jobTitle:
        a.jobtitle ||
        a.jobTitle ||
        a["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/jobtitle"] ||
        null,
      appRoles: toGroupArray(a.role || a.roles),
      raw: a,
    };
  }
  // OIDC — department/jobTitle are enriched from Graph by the token-exchange
  // step (the id_token itself never carries them); `roles` is Entra app roles.
  return {
    email: normEmail(claims.email || claims.preferred_username || claims.upn) || null,
    oid: claims.oid || claims.sub || null,
    displayName: claims.name || claims.preferred_username || null,
    groups: Array.isArray(claims.groups) ? claims.groups : [],
    department: claims.department || null,
    jobTitle: claims.jobTitle || claims.jobtitle || null,
    appRoles: Array.isArray(claims.roles) ? claims.roles : [],
    raw: claims,
  };
};
// ── Role Resolution ───────────────────────────────────────────────────────────
const norm = (v) => (typeof v === "string" ? v.trim().toLowerCase() : v);
const matchesMapping = (mapping, identity) => {
  switch (mapping.mapping_source) {
    case "group":
      return identity.groups.includes(mapping.mapping_value);
    case "department":
      return (
        !!identity.department &&
        norm(identity.department) === norm(mapping.mapping_value)
      );
    case "jobtitle":
      return (
        !!identity.jobTitle &&
        norm(identity.jobTitle) === norm(mapping.mapping_value)
      );
    case "role":
      return (identity.appRoles || []).some(
        (r) => norm(r) === norm(mapping.mapping_value),
      );
    case "default":
      return false;
    default: {
      const rawKeys = identity.raw ? Object.keys(identity.raw) : [];
      const matchedKey = rawKeys.find(
        (k) => norm(k) === norm(mapping.mapping_source),
      );
      const raw =
        matchedKey === undefined ? undefined : identity.raw[matchedKey];
      if (raw === undefined || raw === null) {
        logger.warn(
          "JIT mapping references a claim not present in the token — check the claim name spelling",
          {
            action: "jit_unknown_claim",
            mapping_source: mapping.mapping_source,
          },
        );
        return false;
      }
      const rawValues = Array.isArray(raw) ? raw : [raw];
      return rawValues.some((v) => norm(v) === norm(mapping.mapping_value));
    }
  }
};
const resolveRoles = async (companyId, identity) => {
  const mappings = await getJitMappings(companyId);
  const sorted = mappings.sort((a, b) => a.priority - b.priority);
  const assignedRoleIds = new Set();
  for (const mapping of sorted) {
    if (matchesMapping(mapping, identity)) {
      assignedRoleIds.add(mapping.role_id);
    }
  }
  if (assignedRoleIds.size === 0) {
    const defaultMapping = sorted.find((m) => m.mapping_source === "default");
    if (defaultMapping) assignedRoleIds.add(defaultMapping.role_id);
  }
  const roleIds = [...assignedRoleIds];
  const nameById = new Map(sorted.map((m) => [m.role_id, m.role_name]));
  return roleIds.map((id) => ({
    role_id: id,
    role_name: nameById.get(id) || id,
    permissions: [],
  }));
};
// ── Role Denial ───────────────────────────────────────────────────────────────
const denyNoRole = (companyId, protocol, identity, reason) => {
  logger.warn("Login denied — no role resolved for this user", {
    action: "login_denied_no_role",
    company_id: companyId,
    protocol,
    email: identity.email,
    oid: identity.oid,
    reason,
  });
  const err = new Error("No role assigned to this user");
  err.statusCode = 403;
  err.code = "NO_ROLE_ASSIGNED";
  throw err;
};
function BuildCondition(user, claims) {
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (user?.UUID) {
    return { condition: "UUID", value: user?.UUID };
  }
  if (EMAIL_RE.test(claims?.preferred_username)) {
    return { condition: "email", value: normEmail(claims?.preferred_username) };
  }
  if (EMAIL_RE.test(user?.email)) {
    return { condition: "email", value: normEmail(user?.email) };
  }
  return { condition: "email", value: "" };
}
// ── Main Export ───────────────────────────────────────────────────────────────
/**
 * Resolves a user after successful SAML/OIDC authentication.
 *
 * @param {string} companyId     - company_id from SSO integration
 * @param {object} claims        - raw claims from SAML attributes or OIDC id_token
 * @param {string} protocol      - 'saml' | 'oidc'
 * @returns {{ user, roles, action }} - resolved user, assigned roles, and action taken
 */
const resolveUser = async (companyId, claims, protocol) => {
  const [integration, jitFlag] = await Promise.all([
    getSsoIntegrationByCompanyId(companyId),
    isEnabled(companyId, "jit_enabled").catch(() => false),
  ]);
  if (!integration) {
    const err = new Error(`SSO integration not found for company: ${companyId}`);
    err.statusCode = 404;
    err.code = "INTEGRATION_NOT_FOUND";
    throw err;
  }
  const jitEnabled = integration.jit_status === true && jitFlag;
  if (integration.jit_status && !jitFlag) {
    logger.info("JIT provisioning disabled by feature flag", {
      action: "jit_flag_blocked",
      company_id: companyId,
    });
  }
  // Step 2: Extract normalised identity
  const identity = extractIdentity(claims, protocol);
  if (!identity.oid || !identity.email) {
    const err = new Error("Identity claims missing required fields: oid and email");
    err.statusCode = 400;
    err.code = "MISSING_IDENTITY_CLAIMS";
    throw err;
  }
  // ── JIT ENABLED ──────────────────────────────────────────────────────────
  if (jitEnabled) {
    const roles = await resolveRoles(companyId, identity);
    if (roles.length === 0) {
      return denyNoRole(companyId, protocol, identity, "no_jit_mapping_matched");
    }
    let user = await findUserByOid(companyId, identity.oid);
    let action;
    if (user) {
      await updateUser(user.user_id || user.id, {
        roles: roles.map((r) => r.role_id),
        display_name: identity.displayName || user.display_name,
        last_login: new Date().toISOString(),
      });
      action = "updated";
      logger.debug("[JIT] User updated:", identity.email, "| roles:", roles.map((r) => r.role_id));
    } else {
      user = await createUser({
        user_id: crypto.randomUUID(),
        company_id: companyId,
        email: identity.email,
        oid: identity.oid,
        display_name: identity.displayName,
        roles: roles.map((r) => r.role_id),
        login_method: "sso",
        jit_provisioned: true,
        last_login: new Date().toISOString(),
      });
      action = "created";
      logger.debug("[JIT] User created:", identity.email, "| roles:", roles.map((r) => r.role_id));
    }
    return { user, roles, action };
  }
  // ── JIT DISABLED (non-JIT) ───────────────────────────────────────────────
  logger.debug("[NON-JIT] Looking up user | companyId:", companyId, "| email:", identity.email);
  const usersRef = admin
    .firestore()
    .collection("tenants")
    .doc(companyId)
    .collection("users");
  let snapshot = await usersRef
    .where("email", "==", identity.email)
    .limit(1)
    .get();
  const original = rawEmail(claims);
  if (snapshot.empty && original && original !== identity.email) {
    snapshot = await usersRef.where("email", "==", original).limit(1).get();
  }
  const user = snapshot.empty ? null : snapshot.docs[0].data();
  if (!user) {
    logger.warn("[NON-JIT] User not found in Firestore | email:", identity.email, "| companyId:", companyId);
    const err = new Error("You are not allowed to login using SSO");
    err.statusCode = 403;
    err.code = "USER_NOT_PROVISIONED";
    throw err;
  }
  if (user.loginMethod !== "Entra SSO") {
    logger.warn("[NON-JIT] Login method mismatch | loginMethod:", user.loginMethod);
    const err = new Error("You are not allowed to login using zDNA SSO");
    err.statusCode = 403;
    err.code = "LOGIN_METHOD_NOT_ALLOWED";
    throw err;
  }
  if (user.status === "expired") {
    const err = new Error("Your account has expired. Please contact your administrator");
    err.statusCode = 403;
    err.code = "USER_EXPIRED";
    throw err;
  }
  const roleId = user.roleId || user.role_id;
  if (!roleId) {
    return denyNoRole(companyId, protocol, identity, "user_has_no_role_id");
  }
  const roles = [{ role_id: roleId, role_name: user.roleName || roleId, permissions: [] }];
  // Step F — Update lastLoginAt + invited → joined
  const con = BuildCondition(user, claims);
  const currentTime = Date.now();
  const usersSnapshot = await admin
    .firestore()
    .collection("tenants")
    .doc(companyId)
    .collection("users")
    .where(con.condition, "==", con.value)
    .limit(1)
    .get();
  if (!usersSnapshot.empty && con.value) {
    const userDoc = usersSnapshot.docs[0];
    const userData = userDoc.data();
    if (userData.loginMethod === "Entra SSO") {
      const update = {
        status: "Joined",
        lastLoginTime: currentTime,
        updatedDateTime: currentTime,
      };
      if (userData.firstName === "") {
        if (claims?.preferred_username?.includes("@")) {
          update["firstName"] = claims.preferred_username.split("@")[0];
        }
        if (user?.email?.includes("@") && !update["firstName"]) {
          update["firstName"] = user.email.split("@")[0];
        }
      }
      try {
        await Promise.all([
          userDoc.ref.update(update),
          admin.firestore().collection("tenants").doc(companyId).update({
            lastLoginTime: currentTime,
            updatedDateTime: currentTime,
          }),
        ]);
      } catch (e) {
        logger.warn("[NON-JIT] Failed to update Firestore login metadata", {
          company_id: companyId,
          email: identity.email,
          error: e.message,
        });
      }
    }
  }
  logger.debug(
    "[NON-JIT] User login success | email:",
    identity.email,
    "| loginMethod:",
    user.loginMethod,
    "| roleId:",
    roleId,
  );
  user["company_id"] = companyId;
  return { user, roles, action: "login" };
};
module.exports = { resolveUser };
