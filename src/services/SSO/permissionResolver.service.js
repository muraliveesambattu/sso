/**
 * Permission Resolver
 *
 * Single place that answers "what permissions does this user's login carry?".
 * Used by token minting (zdnaPermissions claim) and GET /sso/me.
 *
 * Source priority:
 *   1. RMS (Role Management System) — when configured (see rmsClient.service).
 *      User-centric, same authority the Phoenix login path uses: the user is
 *      looked up by email/zuid and their permissionsArr is returned.
 *   2. zdna_roles.permissions union — when RMS is unconfigured, doesn't know
 *      the user, or the call fails. A login must never be blocked by an
 *      auxiliary service outage; we degrade to local permissions instead.
 *
 * NOTE: the admin-API middleware (userAuth.middleware) deliberately does NOT
 * use this resolver — our own API's authorization stays on local zdna_roles
 * so it cannot depend on another service's uptime.
 */

const { logger } = require('../../config/logger');
const { isRmsConfigured, fetchUserPermissionsFromRms } = require('./rmsClient.service');

// zdna_roles.permissions is JSONB in Postgres but may arrive as a string from
// the raw driver — normalise to an array.
const toPermissionArray = (value) => {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
};

const localPermissions = (roles) =>
  [...new Set(roles.flatMap(r => toPermissionArray(r.permissions)))];

/**
 * @param {Array<{role_id: string, permissions?: Array|string}>} roles - resolved zdna_roles rows
 * @param {{ email?: string, oid?: string, user_id?: string, id?: string }|null} user
 *        the resolved SSO user — required for the RMS (user-centric) source
 * @returns {Promise<{permissions: string[], source: 'rms'|'zdna_roles', roleName?: string}>}
 */
// Fallback when RMS can't supply per-user permissions (unconfigured, doesn't
// know the user, or errored): derive permissions from the user's JIT-assigned
// role's own definition in the tenant's Firestore roleConfig. This is the
// correct model for SSO/JIT users — permissions follow the assigned ROLE
// (Entra app-role → ZDNA role), so they don't need to be individually
// provisioned in RMS. Falls through to the local zdna_roles union only when the
// role has no Firestore config either.
const roleConfigFallback = async (roleRows, user, local) => {
  const roleName  = roleRows?.[0]?.role_name;
  const companyId = user?.company_id;
  if (roleName && companyId) {
    // Lazy require — avoids initialising the Admin SDK on module load (tests,
    // JSON-store mode).
    const { getRolePermissionStrings } = require('../../utils/firebase/firebaseAdmin.util');
    const rolePerms = await getRolePermissionStrings(companyId, roleName);
    if (rolePerms.length) {
      return { permissions: rolePerms, source: 'role_config', roleName };
    }
  }
  return { permissions: local, source: 'zdna_roles' };
};

const resolvePermissions = async (roles, user = null) => {
  const roleRows = Array.isArray(roles) ? roles : [];
  const local    = localPermissions(roleRows);

  if (!isRmsConfigured() || !user?.email) {
    return roleConfigFallback(roleRows, user, local);
  }

  try {
    const rms = await fetchUserPermissionsFromRms({
      email:   user.email,
      // Pending RMS confirmation of the key for Entra-born users (Phoenix
      // resolves zuid by email via LGE) — until then, oid → user_id → id.
      userKey: user.oid || user.user_id || user.id || '',
    });
    if (rms.found) {
      return { permissions: rms.permissions, source: 'rms', roleName: rms.roleName };
    }
    // RMS reachable but doesn't know the user — use the assigned role's config.
    return roleConfigFallback(roleRows, user, local);
  } catch (err) {
    logger.warn('RMS permission fetch failed — falling back to role config', {
      action: 'rms_fallback', error: err.message,
    });
    return roleConfigFallback(roleRows, user, local);
  }
};

module.exports = { resolvePermissions };
