/**
 * User Auth Middleware (RBAC)
 *
 * Identity-based authorization for admin endpoints, alongside the existing
 * X-Admin-API-Key service credential:
 *
 *   - X-Admin-API-Key present  → delegated to requireAdminKey (service path,
 *     full access — Postman / server-to-server / break-glass).
 *   - Otherwise                → Firebase ID token from `Authorization: Bearer`.
 *     The caller's roles are loaded FRESH from sso_users → zdna_roles (not from
 *     token claims), so role changes take effect immediately, and the request
 *     is scoped to the caller's own company_id.
 *
 * On the token path, `req.user` is set to:
 *   { uid, email, companyId, roles: [...zdna_roles rows], permissions: [...] }
 */

const { logger } = require('../config/logger');
const { verifyIdToken } = require('../utils/firebase/firebaseAdmin.util');
const { requireAdminKey } = require('./adminAuth.middleware');

const authError = (message, statusCode, code) =>
  Object.assign(new Error(message), { statusCode, code });

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

// Lazy require — pulls in the data layer (and possibly Sequelize) only when a
// Bearer-authenticated request actually arrives.
const dataService = () => require('../services/db/ssoDataService');

const authenticateBearer = async (req) => {
  const [scheme, idToken] = (req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !idToken) {
    throw authError('Firebase ID token required in Authorization: Bearer header', 401, 'MISSING_ID_TOKEN');
  }

  let decoded;
  try {
    decoded = await verifyIdToken(idToken);
  } catch (err) {
    if (err.code === 'AUTH_NOT_CONFIGURED') throw err;
    logger.warn('ID token verification failed', { action: 'user_auth_invalid_token', path: req.path, ip: req.ip });
    throw authError('Invalid or expired ID token', 401, 'INVALID_ID_TOKEN');
  }

  return { uid: decoded.uid, email: decoded.email || null, companyId: decoded.companyId || null };
};

// Roles/permissions come from the DB (sso_users.roles → zdna_roles), NOT from
// token claims — claims are frozen at custom-token mint time; the DB is live.
const loadUserAccess = async (identity) => {
  const record = await dataService().findUserById(identity.uid);
  if (!record) {
    throw authError('User is not provisioned for SSO administration', 403, 'USER_NOT_PROVISIONED');
  }
  const roles = await dataService().getRolesByIds(record.roles || []);
  const permissions = [...new Set(roles.flatMap(r => toPermissionArray(r.permissions)))];
  return {
    uid:         identity.uid,
    email:       identity.email || record.email,
    companyId:   record.company_id || identity.companyId,
    roles,
    permissions,
  };
};

// The company a request targets, wherever the existing routes carry it.
const extractTargetCompanyId = (req) =>
  req.params?.company_id || req.query?.company_id || req.body?.company_id || null;

/**
 * Authorizes via admin key (full access) OR a Firebase ID token whose user
 * holds `permission` in zdna_roles AND is acting on their own company.
 */
const requireAdminKeyOrPermission = (permission) => async (req, res, next) => {
  if (req.headers['x-admin-api-key']) return requireAdminKey(req, res, next);

  try {
    const identity = await authenticateBearer(req);
    const user = await loadUserAccess(identity);

    if (!user.permissions.includes(permission)) {
      logger.warn('Permission denied', {
        action: 'user_auth_forbidden', uid: user.uid, required: permission, path: req.path,
      });
      throw authError(`This action requires the '${permission}' permission`, 403, 'INSUFFICIENT_PERMISSIONS');
    }

    const targetCompanyId = extractTargetCompanyId(req);
    if (targetCompanyId && user.companyId && targetCompanyId !== user.companyId) {
      logger.warn('Cross-company access blocked', {
        action: 'user_auth_scope_violation', uid: user.uid, target: targetCompanyId, own: user.companyId, path: req.path,
      });
      throw authError('You may only manage your own organisation', 403, 'COMPANY_SCOPE_VIOLATION');
    }

    req.user = user;
    logger.info('User authenticated', { action: 'user_auth_ok', uid: user.uid, path: req.path });
    next();
  } catch (err) {
    next(err);
  }
};

/**
 * Authenticates a Firebase ID token without any permission requirement.
 * Used by GET /sso/me — every signed-in SSO user may read their own access.
 */
const requireUser = async (req, res, next) => {
  try {
    req.user = await authenticateBearer(req);
    next();
  } catch (err) {
    next(err);
  }
};

module.exports = { requireAdminKeyOrPermission, requireUser, toPermissionArray };
