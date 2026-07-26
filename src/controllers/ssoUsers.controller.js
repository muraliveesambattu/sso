/**
 * SSO Users & Roles Controller
 *
 * RBAC management endpoints:
 *
 *   GET    /sso/me              → caller's fresh roles + permissions (Bearer only)
 *   GET    /sso/users?company_id=… → list a company's provisioned users
 *   POST   /sso/users           → pre-provision a user (required for non-JIT mode)
 *   PATCH  /sso/users/:user_id  → update roles / display_name
 *   DELETE /sso/users/:user_id  → remove a provisioned user
 *
 * Company scoping: X-Admin-API-Key callers may act on any company;
 * Bearer-token callers are limited to their own (middleware checks the
 * request's company_id, and handlers re-check against the target row).
 */

const crypto = require('crypto');
const ssoDataService = require('../services/db/ssoDataService');
const { resolvePermissions } = require('../services/SSO/permissionResolver.service');
const { logger } = require('../config/logger');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const httpError = (message, statusCode, code) =>
  Object.assign(new Error(message), { statusCode, code });

// Roles are not validated against a local catalog — they're per-tenant RMS /
// Firestore role names (same as jit_mappings), resolved at login. We only
// require that at least one role is assigned.
const validateRoleIds = (roleIds) => {
  if (!Array.isArray(roleIds) || roleIds.length === 0) {
    throw httpError('roles must be a non-empty array of role names', 400, 'MISSING_ROLES');
  }
};

// Bearer callers may only touch rows in their own company (admin key: any).
const assertRowInCallerCompany = (req, row) => {
  if (req.user?.companyId && row.company_id !== req.user.companyId) {
    throw httpError('You may only manage your own organisation', 403, 'COMPANY_SCOPE_VIOLATION');
  }
};

// GET /sso/me — roles/permissions read fresh from the DB, not token claims,
// so the frontend can escape claim staleness without forcing a re-login.
const handleGetMe = async (req, res, next) => {
  try {
    const record = await ssoDataService.findUserById(req.user.uid);
    if (!record) {
      return res.status(404).json({
        success: false,
        error: { code: 'USER_NOT_FOUND', message: 'No SSO user record for this account.' },
      });
    }
    const roles = (record.roles || []).map(r => ({ role_id: r, role_name: r, permissions: [] }));
    // Same source the login token uses (RMS → Firestore roleConfig) — /me and
    // the token can't disagree.
    const { permissions, source } = await resolvePermissions(roles, record);
    return res.status(200).json({
      success: true,
      data: {
        user: {
          user_id:      record.user_id || record.id,
          company_id:   record.company_id,
          email:        record.email,
          display_name: record.display_name || null,
          last_login:   record.last_login || null,
        },
        roles,
        permissions,
        permissions_source: source,
      },
    });
  } catch (err) {
    next(err);
  }
};

// GET /sso/users?company_id=…
const handleListUsers = async (req, res, next) => {
  try {
    const company_id = req.query.company_id || req.user?.companyId;
    if (!company_id) {
      return res.status(400).json({
        success: false,
        error: { code: 'MISSING_REQUIRED_FIELDS', message: 'company_id query parameter is required' },
      });
    }
    const users = await ssoDataService.listUsersByCompany(company_id);
    return res.status(200).json({ success: true, data: users });
  } catch (err) {
    next(err);
  }
};

// POST /sso/users — pre-provision for non-JIT companies. `oid` is unknown
// until the user's first Entra login, so a pending placeholder is stored;
// the non-JIT login path matches by email and backfills the real oid.
const handleCreateUser = async (req, res, next) => {
  try {
    const { company_id, email, roles, display_name, oid } = req.body;

    if (!company_id || !email) {
      throw httpError('company_id and email are required', 400, 'MISSING_REQUIRED_FIELDS');
    }
    if (!EMAIL_RE.test(email)) throw httpError('Invalid email format', 400, 'INVALID_EMAIL');

    const integration = await ssoDataService.getSsoIntegrationByCompanyId(company_id);
    if (!integration) {
      throw httpError(`SSO integration not found for company: ${company_id}`, 404, 'INTEGRATION_NOT_FOUND');
    }

    validateRoleIds(roles);

    const existing = await ssoDataService.findUserByEmail(company_id, email);
    if (existing) {
      throw httpError('A user with this email already exists for this company', 409, 'USER_ALREADY_EXISTS');
    }

    const user = await ssoDataService.createUser({
      user_id:         crypto.randomUUID(),
      company_id,
      email,
      oid:             oid || `pending:${crypto.randomUUID()}`,
      display_name:    display_name || null,
      roles,
      login_method:    'sso',
      jit_provisioned: false,
      last_login:      null,
    });

    logger.info('SSO user provisioned', {
      action: 'sso_user_created', company_id, by: req.user?.uid || 'admin-key',
    });
    return res.status(201).json({ success: true, data: user });
  } catch (err) {
    next(err);
  }
};

// PATCH /sso/users/:user_id — body: { roles?, display_name? }
const handleUpdateUser = async (req, res, next) => {
  try {
    const { user_id } = req.params;
    const { roles, display_name } = req.body;

    const record = await ssoDataService.findUserById(user_id);
    if (!record) {
      return res.status(404).json({
        success: false,
        error: { code: 'USER_NOT_FOUND', message: `No SSO user found for user_id: ${user_id}` },
      });
    }
    assertRowInCallerCompany(req, record);

    const updates = {};
    if (roles !== undefined) {
      validateRoleIds(roles);
      updates.roles = roles;
    }
    if (display_name !== undefined) updates.display_name = display_name;
    if (Object.keys(updates).length === 0) {
      throw httpError('Provide roles and/or display_name to update', 400, 'MISSING_REQUIRED_FIELDS');
    }

    await ssoDataService.updateUser(record.user_id || record.id, updates);

    logger.info('SSO user updated', {
      action: 'sso_user_updated', user_id, company_id: record.company_id, by: req.user?.uid || 'admin-key',
    });
    return res.status(200).json({ success: true, data: { ...record, ...updates } });
  } catch (err) {
    next(err);
  }
};

// DELETE /sso/users/:user_id
const handleDeleteUser = async (req, res, next) => {
  try {
    const { user_id } = req.params;

    const record = await ssoDataService.findUserById(user_id);
    if (!record) {
      return res.status(404).json({
        success: false,
        error: { code: 'USER_NOT_FOUND', message: `No SSO user found for user_id: ${user_id}` },
      });
    }
    assertRowInCallerCompany(req, record);

    await ssoDataService.deleteUser(record.user_id || record.id);

    logger.info('SSO user deleted', {
      action: 'sso_user_deleted', user_id, company_id: record.company_id, by: req.user?.uid || 'admin-key',
    });
    return res.status(200).json({ success: true, data: { user_id } });
  } catch (err) {
    next(err);
  }
};

module.exports = {
  handleGetMe,
  handleListUsers,
  handleCreateUser,
  handleUpdateUser,
  handleDeleteUser,
};
