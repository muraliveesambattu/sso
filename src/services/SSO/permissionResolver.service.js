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

// zdna_roles.permissions is JSON in Postgres but may arrive as a string from
// the JSON store — normalise to an array.
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
const resolvePermissions = async (roles, user = null) => {
  const roleRows = Array.isArray(roles) ? roles : [];
  const local    = localPermissions(roleRows);

  if (!isRmsConfigured() || !user?.email) {
    return { permissions: local, source: 'zdna_roles' };
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
    // RMS reachable but doesn't know the user (not provisioned there yet —
    // auto-creating SSO users in RMS is a pending team decision)
    return { permissions: local, source: 'zdna_roles' };
  } catch (err) {
    logger.warn('RMS permission fetch failed — falling back to zdna_roles', {
      action: 'rms_fallback', error: err.message,
    });
    return { permissions: local, source: 'zdna_roles' };
  }
};

module.exports = { resolvePermissions };
