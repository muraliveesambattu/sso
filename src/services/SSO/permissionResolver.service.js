/**
 * Permission Resolver
 *
 * Single place that answers "what permissions do these roles grant?".
 * Used by token minting (zdnaPermissions claim) and GET /sso/me.
 *
 * Source priority:
 *   1. Role-management microservice — when ROLE_MGMT_URL is configured.
 *      This is the org's designated permission authority (RBAC phase 2).
 *   2. zdna_roles.permissions union — fallback when unconfigured OR when the
 *      role-management call fails. A login must never be blocked by an
 *      auxiliary service outage; we degrade to local permissions instead.
 *
 * NOTE: the admin-API middleware (userAuth.middleware) deliberately does NOT
 * use this resolver — our own API's authorization stays on local zdna_roles
 * so it cannot depend on another service's uptime.
 *
 * Env:
 *   ROLE_MGMT_URL         — base URL of the role-management microservice
 *   ROLE_MGMT_API_KEY     — optional service credential (X-Api-Key header)
 *   ROLE_MGMT_TIMEOUT_MS  — request timeout (default 3000)
 */

const { logger } = require('../../config/logger');

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

// ── ADAPTER ───────────────────────────────────────────────────────────────────
// The role-management service's API contract is not final. This function is
// the ONLY place that knows the request/response shape — adjust it here when
// the contract lands; nothing else in the codebase cares.
// Current assumption: POST {ROLE_MGMT_URL}/permissions/resolve
//   body     { role_ids: ["role-analyst", ...] }
//   response { permissions: ["...", ...] }
const fetchPermissionsFromRoleMgmt = async (roleIds) => {
  const baseUrl   = process.env.ROLE_MGMT_URL.replace(/\/$/, '');
  const timeoutMs = parseInt(process.env.ROLE_MGMT_TIMEOUT_MS || '3000', 10);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${baseUrl}/permissions/resolve`, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(process.env.ROLE_MGMT_API_KEY ? { 'X-Api-Key': process.env.ROLE_MGMT_API_KEY } : {}),
      },
      body:   JSON.stringify({ role_ids: roleIds }),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`role-management service responded HTTP ${res.status}`);
    const data = await res.json();
    if (!Array.isArray(data.permissions)) throw new Error('role-management response missing permissions array');
    return data.permissions;
  } finally {
    clearTimeout(timer);
  }
};

/**
 * @param {Array<{role_id: string, permissions?: Array|string}>} roles - resolved zdna_roles rows
 * @returns {Promise<{permissions: string[], source: 'role_mgmt'|'zdna_roles'}>}
 */
const resolvePermissions = async (roles) => {
  const roleRows = Array.isArray(roles) ? roles : [];
  if (roleRows.length === 0) return { permissions: [], source: 'zdna_roles' };

  if (!process.env.ROLE_MGMT_URL) {
    return { permissions: localPermissions(roleRows), source: 'zdna_roles' };
  }

  try {
    const permissions = await fetchPermissionsFromRoleMgmt(roleRows.map(r => r.role_id));
    return { permissions, source: 'role_mgmt' };
  } catch (err) {
    logger.warn('Role-management permission fetch failed — falling back to zdna_roles', {
      action: 'role_mgmt_fallback', error: err.message,
    });
    return { permissions: localPermissions(roleRows), source: 'zdna_roles' };
  }
};

module.exports = { resolvePermissions };
