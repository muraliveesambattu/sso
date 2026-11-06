/**
 * User Resolution Service
 */
const crypto = require("node:crypto");
const { logger } = require("../../config/logger");
const { isEnabled } = require("../featureFlag.service");
const { SAML_CLAIMS } = require('../../config/constants');
const admin = require("firebase-admin");
const { maskInput } = require("../../utils/shared/maskId.util");
const {
  getSsoIntegrationByCompanyId,
  getJitMappings,
  findUserByOid,
  findUserByEmail,
  createUser,
  updateUser,
} = require("../db/ssoDataService");

const toGroupArray = (value) => {
  if (Array.isArray(value)) return value;
  return value ? [value] : [];
};

// Email exactly as the IdP sent it — lookup fallback for Firestore users
// stored with mixed case.
const rawEmail = (claims) =>
  claims?.emailaddress ||
  claims?.email ||
  claims?.[SAML_CLAIMS.EMAIL] ||
  claims?.preferred_username ||
  claims?.upn ||
  null;

const extractIdentity = (claims, protocol) => {
  if (protocol === "saml") {
    const a = claims;
    const email =
      (a[SAML_CLAIMS.EMAIL] ||
        a.emailaddress ||
        a.email ||
        a.nameId?.value ||
        a.name ||
        null).toLowerCase().trim();

    logger.debug("[SAML] extractIdentity | claim resolution", {
      has_schema_email: !!a[SAML_CLAIMS.EMAIL],
      has_emailaddress: !!a.emailaddress,
      has_email: !!a.email,
      has_nameId: !!a.nameId?.value,
      hasResolvedEmail: !!email,
      hasOid: !!(a.objectidentifier || a[SAML_CLAIMS.OID]),
    });

    return {
      email,
      oid: a.objectidentifier || a[SAML_CLAIMS.OID] || null,
      displayName: a.name || a.displayname || a.givenname || null,
      groups: toGroupArray(a.groups || a[SAML_CLAIMS.GROUPS]),
      department: a.department || a[SAML_CLAIMS.DEPARTMENT] || null,
      jobTitle: a.jobtitle || a.jobTitle || a[SAML_CLAIMS.JOB_TITLE] || null,
      appRoles: toGroupArray(a.role || a.roles || a[SAML_CLAIMS.ROLE]),
      raw: a,
    };
  }

  return {
    email: (claims.email || claims.preferred_username || claims.upn || '').toLowerCase() || null,
    oid: claims.oid || claims.sub || null,
    displayName: claims.name || claims.preferred_username || null,
    groups: Array.isArray(claims.groups) ? claims.groups : [],
    department: claims.department || null,
    jobTitle: claims.jobTitle || claims.jobtitle || null,
    appRoles: Array.isArray(claims.roles) ? claims.roles : [],
    raw: claims,
  };
};

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
      const raw = matchedKey === undefined ? undefined : identity.raw[matchedKey];
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

const denyNoRole = (companyId, protocol, identity, reason) => {
  logger.warn("Login denied — no role resolved for this user", {
    action: "login_denied_no_role",
    companyIdMasked: maskInput(String(companyId)),
    protocol,
    hasemail: !!identity.email,
    hasoid: !!identity.oid,
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

  const email =
    (claims?.preferred_username ||
      claims?.[SAML_CLAIMS.EMAIL] ||
      claims?.emailaddress ||
      claims?.email ||
      claims?.nameId?.value)?.trim().toLowerCase();

  if (EMAIL_RE.test(email)) {
    return { condition: "email", value: email };
  }

  if (EMAIL_RE.test(user?.email)) {
    return { condition: "email", value: user?.email };
  }

  return { condition: "email", value: "" };
}

const buildFirstNameUpdate = (update, userData, claims, user) => {
  if (userData.firstName !== "") return;
  if (claims?.preferred_username?.includes("@")) {
    update["firstName"] = claims.preferred_username.split("@")[0];
  }
  if (user?.email?.includes("@") && !update["firstName"]) {
    update["firstName"] = user.email.split("@")[0];
  }
};

const resolveUser = async (companyId, claims, protocol) => {
  const [integration, jitFlag] = await Promise.all([
    getSsoIntegrationByCompanyId(companyId),
    isEnabled(companyId, "jit_enabled").catch(() => false),
  ]);

  logger.debug("[claims] SAML callback service received claims", {
    companyIdMasked: maskInput(String(companyId)),
    protocol,
  });

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
      companyIdMasked: maskInput(String(companyId)),
    });
  }

  const identity = extractIdentity(claims, protocol);

  logger.debug('[SAML] Identity resolved', {
    companyIdMasked: maskInput(String(companyId)),
    protocol,
    hasEmail: !!identity.email,
    hasOid: !!identity.oid,
  });

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
      logger.debug("[JIT] User updated", {
        companyIdMasked: maskInput(String(companyId)),
        protocol,
        action,
      });
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
      logger.debug("[JIT] User created", {
        companyIdMasked: maskInput(String(companyId)),
        protocol,
        action,
      });
    }
    return { user, roles, action };
  }

  // ── JIT DISABLED (non-JIT) ───────────────────────────────────────────────
  logger.debug("[NON-JIT] Starting user resolution", {
    companyIdMasked: maskInput(String(companyId)),
    protocol,
  });

  const usersRef = admin
    .firestore()
    .collection("tenants")
    .doc(companyId)
    .collection("users");
  let snapshot;
  try {
    snapshot = await usersRef
      .where("email", "==", identity.email)
      .limit(1)
      .get();
    const original = rawEmail(claims);
    if (snapshot.empty && original && original !== identity.email) {
      snapshot = await usersRef.where("email", "==", original).limit(1).get();
    }
  } catch (fsErr) {
    logger.error("[NON-JIT] Firestore user lookup failed", {
      companyIdMasked: maskInput(String(companyId)),
      protocol,
      error: fsErr.message,
    });
    const err = new Error("User lookup temporarily unavailable. Please try again.");
    err.statusCode = 503;
    err.code = "FIRESTORE_UNAVAILABLE";
    throw err;
  }

  logger.debug("[NON-JIT] Firestore user lookup result", {
    companyIdMasked: maskInput(String(companyId)),
    protocol,
    found: !snapshot.empty,
  });

  const user = snapshot.empty ? null : snapshot.docs[0].data();

  if (!user) {
    logger.warn("[NON-JIT] User not found in Firestore", {
      companyIdMasked: maskInput(String(companyId)),
      protocol,
    });
    const err = new Error("You are not allowed to login using SSO");
    err.statusCode = 403;
    err.code = "USER_NOT_PROVISIONED";
    throw err;
  }

  logger.debug("[NON-JIT] User found in Firestore", {
    companyIdMasked: maskInput(String(companyId)),
    protocol,
    loginMethod: user.loginMethod,
    status: user.status,
  });

  if (user.loginMethod !== "Entra SSO") {
    logger.warn("[NON-JIT] Login method mismatch", {
      companyIdMasked: maskInput(String(companyId)),
      protocol,
      expected: "Entra SSO",
      actual: user.loginMethod,
    });
    const err = new Error("You are not allowed to login using zDNA SSO");
    err.statusCode = 403;
    err.code = "LOGIN_METHOD_NOT_ALLOWED";
    throw err;
  }

  if (user.status === "expired") {
    logger.warn("[NON-JIT] User account expired", {
      companyIdMasked: maskInput(String(companyId)),
      protocol,
      hasemail: !!identity.email,
    });
    const err = new Error("Your account has expired. Please contact your administrator");
    err.statusCode = 403;
    err.code = "USER_EXPIRED";
    throw err;
  }

  const roleId = user.roleId || user.role_id;
  if (!roleId) {
    return denyNoRole(companyId, protocol, identity, "user_has_no_role_id");
  }

  logger.debug("[NON-JIT] Role resolved", {
    companyIdMasked: maskInput(String(companyId)),
    protocol,
    hasemail: !!identity.email,
    hasroleId: !!roleId,
  });

  const roles = [{ role_id: roleId, role_name: user.roleName || roleId, permissions: [] }];
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
      buildFirstNameUpdate(update, userData, claims, user);

      logger.debug("[NON-JIT] Updating Firestore login metadata", {
        companyIdMasked: maskInput(String(companyId)),
        protocol,
        update,
      });

      try {
        await Promise.all([
          userDoc.ref.update(update),
          admin.firestore().collection("tenants").doc(companyId).update({
            lastLoginTime: currentTime,
            updatedDateTime: currentTime,
          }),
        ]);
        logger.debug("[NON-JIT] Firestore login metadata updated successfully", {
          companyIdMasked: maskInput(String(companyId)),
          protocol,
        });
      } catch (e) {
        logger.warn("[NON-JIT] Failed to update Firestore login metadata", {
          companyIdMasked: maskInput(String(companyId)),
          protocol,
          error: e.message,
        });
      }
    }
  }

  logger.debug("[NON-JIT] Login success", {
    companyIdMasked: maskInput(String(companyId)),
    protocol,
    loginMethod: user.loginMethod,
  });

  user["company_id"] = companyId;
  return { user, roles, action: "login" };
};

module.exports = { resolveUser };