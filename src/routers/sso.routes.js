
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
const { getFlags, updateFlag }  = require('../controllers/featureFlag.controller');
const { domainCheckLimiter, samlCallbackLimiter } = require('../middlewares/rateLimiter');
const { requireAdminKey } = require('../middlewares/adminAuth.middleware');

// ── Feature Flags (admin only) ────────────────────────────────────────────────
router.get('/admin/flags/:company_id', requireAdminKey, getFlags);
router.post('/admin/flags',            requireAdminKey, updateFlag);

// SSO configuration test — Phase 1: verifies credentials against Microsoft Entra,
// returns { config, sessionRef } for the browser popup flow (secrets stay in tcStore)
// Protected: requires X-Admin-API-Key header
router.post('/test-connection', requireAdminKey, handleTestConnection);

// SSO configuration test — Phase 2: parent window posts { code, state, sessionRef }
// after the Azure popup returns. No admin key — single-use sessionRef is the credential.
router.post('/test-connection/oidc/callback', oidcTestCallbackController);

// Save & activate SSO configuration with optional JIT mappings
// Protected: requires X-Admin-API-Key header
router.post('/sso/save', requireAdminKey, handleSaveSsoConfig);

// Retrieve full SSO config by company_id or domain (secrets masked)
// Protected: requires X-Admin-API-Key header
router.get('/sso/config', requireAdminKey, handleGetSsoConfig);

// Activate / deactivate SSO for a company
// Protected: requires X-Admin-API-Key header
router.patch('/sso/config/:company_id/status', requireAdminKey, handleSetSsoStatus);

// Delete SSO configuration (integration + OIDC/SAML + JIT mappings)
// Protected: requires X-Admin-API-Key header
router.delete('/sso/config/:company_id', requireAdminKey, handleDeleteSsoConfig);

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
