/**
 * Permission Resolver
 *
 * Single place that answers "what permissions does this user's login carry?".
 * Used by token minting (zdnaPermissions claim), GET /sso/me, and the admin-API
 * authorization middleware — so all three agree on one source.
 *
 * Source priority:
 *   1. RMS (Role Management System) — when configured (see rmsClient.service).
 *      User-centric, same authority the Phoenix login path uses: the user is
 *      looked up by email/zuid and their permissionsArr is returned.
 *   2. Firestore roleConfig — permissions for the user's assigned role name,
 *      per tenant (see getRolePermissionStrings). Used when RMS is unconfigured,
 *      doesn't know the user, or the call fails.
 *   3. None — if neither source has anything, permissions are empty (there is
 *      no local role table).
 */

const { logger } = require('../../config/logger');
const { isRmsConfigured, fetchUserPermissionsFromRms } = require('./rmsClient.service');

/**
 * @param {Array<{role_id: string, role_name?: string}>} roles - the user's assigned roles
 * @param {{ email?: string, oid?: string, user_id?: string, id?: string }|null} user
 *        the resolved SSO user — required for the RMS (user-centric) source
 * @returns {Promise<{permissions: string[], source: 'rms'|'role_config'|'none', roleName?: string}>}
 */
// Fallback when RMS can't supply per-user permissions (unconfigured, doesn't
// know the user, or errored): derive permissions from the user's assigned
// role's own definition in the tenant's Firestore roleConfig. Permissions
// follow the assigned ROLE, so they don't need per-user RMS provisioning. If
// the role has no Firestore config either, permissions are empty — there is no
// local role table to fall back to.
const roleConfigFallback = async (roleRows, user) => {
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
  return { permissions: [], source: 'none', roleName };
};

const resolvePermissions = async (roles, user = null) => {
  const roleRows = Array.isArray(roles) ? roles : [];

  if (!isRmsConfigured() || !user?.email) {
    return roleConfigFallback(roleRows, user);
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
    return roleConfigFallback(roleRows, user);
  } catch (err) {
    logger.warn('RMS permission fetch failed — falling back to role config', {
      action: 'rms_fallback', error: err.message,
    });
    return roleConfigFallback(roleRows, user);
  }
};

module.exports = { resolvePermissions };
