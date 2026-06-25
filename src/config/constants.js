/**
 * Application Constants — single source of truth for external endpoints and
 * default service URLs. No endpoint/URL literals should live anywhere else in
 * the codebase; import from here instead.
 *
 *   const { microsoft, defaults } = require('../config/constants');
 *   const url = microsoft.tokenUrl(tenantId);
 *   const redirect = defaults.OIDC_REDIRECT_URI;
 */

// ── Microsoft Entra / Azure AD base hosts ─────────────────────────────────────
const MS_LOGIN_BASE = 'https://login.microsoftonline.com';
const MS_GRAPH_BASE = 'https://graph.microsoft.com';
const MS_STS_BASE   = 'https://sts.windows.net';

// Microsoft endpoints are constant; only the tenant id varies. Builders take the
// tenant (GUID or alias like 'common'/'consumers') and return the full URL.
const microsoft = {
  loginBase: MS_LOGIN_BASE,
  graphBase: MS_GRAPH_BASE,
  stsBase:   MS_STS_BASE,

  // OAuth2 / OIDC
  tokenUrl:     (tenant) => `${MS_LOGIN_BASE}/${tenant}/oauth2/v2.0/token`,
  authorizeUrl: (tenant) => `${MS_LOGIN_BASE}/${tenant}/oauth2/v2.0/authorize`,
  discoveryUrl: (tenant) => `${MS_LOGIN_BASE}/${tenant}/v2.0/.well-known/openid-configuration`,
  jwksUrl:      (tenant) => `${MS_LOGIN_BASE}/${tenant}/discovery/v2.0/keys`,
  issuer:       (tenant) => `${MS_LOGIN_BASE}/${tenant}/v2.0`,

  // SAML
  samlMetadataUrl: (tenant) => `${MS_LOGIN_BASE}/${tenant}/federationmetadata/2007-06/federationmetadata.xml`,
  samlSsoUrl:      (tenant) => `${MS_LOGIN_BASE}/${tenant}/saml2`,
  samlIssuer:      (tenant) => `${MS_STS_BASE}/${tenant}/`,

  // Microsoft Graph
  graphMemberOf: `${MS_GRAPH_BASE}/v1.0/me/memberOf?$select=id,securityEnabled`,
  graphScope:    `${MS_GRAPH_BASE}/.default`,

  // Issuer validation pattern for the OIDC `iss` claim (tenant-bound v2.0 issuer)
  issuerPattern: /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/v2\.0$/,
};

// ── Default service URLs / values (env-overridable) ───────────────────────────
// Each environment can override via the matching env var; the literal is only
// the local-dev / fallback default.
const defaults = {
  SSO_STATUS:        'active',
  IDP:               'microsoft_entra',
  OIDC_SCOPE:        'openid profile email offline_access',
  OIDC_REDIRECT_URI: process.env.OIDC_REDIRECT_URI || 'http://localhost:3000/auth/oidc/callback',
  SAML_ENTITY_ID:    process.env.SAML_ENTITY_ID    || 'https://zdna-sso.web.app/auth/metadata2',
  SAML_ACS_URL:      process.env.SAML_ACS_URL      || 'https://zdna-sso.web.app/auth/callback',
  FRONTEND_URL:      process.env.FRONTEND_URL      || 'http://localhost:3000',
};

module.exports = { microsoft, defaults, MS_LOGIN_BASE, MS_GRAPH_BASE, MS_STS_BASE };
