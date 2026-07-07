
const express = require('express');
const router  = express.Router();

const { domainCheck }           = require('../controllers/domianCheck.Controller');
const { samlCallbackController } = require('../controllers/samlCallback.Controller');
const { handleOidcCallback }    = require('../controllers/oidcTokenExchange.controller');
const { handleOidcRedirect }    = require('../controllers/oidcRedirect.controller');
const { handleTestConnection }  = require('../controllers/testConnection.controller');
const { oidcTestCallbackController } = require('../controllers/oidcTestCallback.controller');
const { handleSaveSsoConfig }   = require('../controllers/saveSsoConfig.controller');
const { handleGetSsoConfig, handleSetSsoStatus, handleDeleteSsoConfig } = require('../controllers/ssoAdmin.controller');
const {
  handleListRoles, handleGetMe, handleListUsers,
  handleCreateUser, handleUpdateUser, handleDeleteUser,
} = require('../controllers/ssoUsers.controller');
const { getFlags, updateFlag }  = require('../controllers/featureFlag.controller');
const { domainCheckLimiter, samlCallbackLimiter } = require('../middlewares/rateLimiter');
const { requireAdminKey } = require('../middlewares/adminAuth.middleware');
const { requireAdminKeyOrPermission, requireUser } = require('../middlewares/userAuth.middleware');

// Admin endpoints accept either X-Admin-API-Key (service path, any company) or
// a Firebase ID token whose zdna_roles grant the named permission — token
// callers are scoped to their own company_id (userAuth.middleware).

// ── Feature Flags (platform admin only — never tenant-scoped) ─────────────────
router.get('/admin/flags/:company_id', requireAdminKey, getFlags);
router.post('/admin/flags',            requireAdminKey, updateFlag);

// ── RBAC: roles, current user, user provisioning ──────────────────────────────

// Role catalogue — every role can read it (feeds the JIT-mapping dropdown)
router.get('/sso/roles', requireAdminKeyOrPermission('read'), handleListRoles);

// Caller's own roles + permissions, fresh from the DB (Bearer token only)
router.get('/sso/me', requireUser, handleGetMe);

// Pre-provisioning CRUD — required for non-JIT companies
router.get('/sso/users',             requireAdminKeyOrPermission('manage_users'), handleListUsers);
router.post('/sso/users',            requireAdminKeyOrPermission('manage_users'), handleCreateUser);
router.patch('/sso/users/:user_id',  requireAdminKeyOrPermission('manage_users'), handleUpdateUser);
router.delete('/sso/users/:user_id', requireAdminKeyOrPermission('manage_users'), handleDeleteUser);

// ── SSO configuration ─────────────────────────────────────────────────────────

// SSO configuration test — Phase 1: verifies credentials against Microsoft Entra,
// returns { config, sessionRef } for the browser popup flow (secrets stay in tcStore)
// Protected: admin key or 'write' permission
router.post('/test-connection', requireAdminKeyOrPermission('write'), handleTestConnection);

// SSO configuration test — Phase 2: parent window posts { code, state, sessionRef }
// after the Azure popup returns. No admin key — single-use sessionRef is the credential.
router.post('/test-connection/oidc/callback', oidcTestCallbackController);

// Save & activate SSO configuration with optional JIT mappings
// Protected: admin key or 'write' permission
router.post('/sso/save', requireAdminKeyOrPermission('write'), handleSaveSsoConfig);

// Retrieve full SSO config by company_id or domain (secrets masked)
// Protected: admin key or 'read' permission (token callers get their own company)
router.get('/sso/config', requireAdminKeyOrPermission('read'), handleGetSsoConfig);

// Activate / deactivate SSO for a company
// Protected: admin key or 'write' permission
router.patch('/sso/config/:company_id/status', requireAdminKeyOrPermission('write'), handleSetSsoStatus);

// Delete SSO configuration (integration + OIDC/SAML + JIT mappings)
// Protected: admin key or 'delete' permission
router.delete('/sso/config/:company_id', requireAdminKeyOrPermission('delete'), handleDeleteSsoConfig);

// Domain check — entry point for both SAML and OIDC flows
// Rate limited to 10 req/IP/min to prevent domain enumeration
router.post('/domain-check', domainCheckLimiter, domainCheck);

// SAML ACS (Assertion Consumer Service) callback from Microsoft Entra
router.post('/callback', samlCallbackLimiter, samlCallbackController);

// OIDC Step 1 — Entra redirects browser here with authorization code
// Relays code + state to frontend, frontend then calls /oidc/token-exchange
router.get('/oidc/callback', handleOidcRedirect);

// OIDC Step 2 — Frontend sends code here for server-to-server token exchange
router.post('/oidc/token-exchange', handleOidcCallback);

module.exports = router;
