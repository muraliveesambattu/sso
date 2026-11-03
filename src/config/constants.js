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

// SSRF allowlist: outbound request targets are built from tenant-controlled
// config (tenant_id, sso_url), so every outbound host is restricted to the
// Microsoft endpoints above, HTTPS only — a tenant cannot redirect the service
// to an internal or arbitrary host.
const MS_ALLOWED_HOSTS = [MS_LOGIN_BASE, MS_GRAPH_BASE, MS_STS_BASE].map((b) => new URL(b).hostname);

// Microsoft endpoints are constant; only the tenant id varies. Builders take the
// tenant (GUID or alias like 'common'/'consumers') and return the full URL.
const microsoft = {
  loginBase: MS_LOGIN_BASE,
  graphBase: MS_GRAPH_BASE,
  stsBase:   MS_STS_BASE,

  // OAuth2 / OIDC
  //
  // `tenant` is caller-supplied (tenant_id from a request body), so every builder
  // percent-encodes it before interpolation: encodeURIComponent escapes '/' to
  // '%2F', which collapses any traversal attempt ("common/../x") into a single
  // inert path segment. Valid Entra tenants — a GUID or common/consumers/
  // organizations — contain no encodable characters, so this is a no-op for every
  // legitimate value. Prevents CWE-22 path traversal at the point of construction
  // rather than relying only on the upstream format check (S7044).
  tokenUrl:     (tenant) => `${MS_LOGIN_BASE}/${encodeURIComponent(tenant)}/oauth2/v2.0/token`,
  authorizeUrl: (tenant) => `${MS_LOGIN_BASE}/${encodeURIComponent(tenant)}/oauth2/v2.0/authorize`,
  discoveryUrl: (tenant) => `${MS_LOGIN_BASE}/${encodeURIComponent(tenant)}/v2.0/.well-known/openid-configuration`,
  jwksUrl:      (tenant) => `${MS_LOGIN_BASE}/${encodeURIComponent(tenant)}/discovery/v2.0/keys`,
  issuer:       (tenant) => `${MS_LOGIN_BASE}/${encodeURIComponent(tenant)}/v2.0`,

  // SAML
  samlMetadataUrl: (tenant) => `${MS_LOGIN_BASE}/${encodeURIComponent(tenant)}/federationmetadata/2007-06/federationmetadata.xml`,
  samlSsoUrl:      (tenant) => `${MS_LOGIN_BASE}/${encodeURIComponent(tenant)}/saml2`,
  samlIssuer:      (tenant) => `${MS_STS_BASE}/${encodeURIComponent(tenant)}/`,

  // ZDNA connector app — admin consent for a customer tenant (one-time, per tenant)
  adminConsentUrl: (tenant) => `${MS_LOGIN_BASE}/${encodeURIComponent(tenant)}/v2.0/adminconsent`,

  // Microsoft Graph
  graphMemberOf: `${MS_GRAPH_BASE}/v1.0/me/memberOf?$select=id,securityEnabled`,
  graphMe:       `${MS_GRAPH_BASE}/v1.0/me?$select=department,jobTitle`,
  graphScope:    `${MS_GRAPH_BASE}/.default`,
  graphV1:       `${MS_GRAPH_BASE}/v1.0`,
  graphBeta:     `${MS_GRAPH_BASE}/beta`,

  // Issuer validation pattern for the OIDC `iss` claim (tenant-bound v2.0 issuer)
  issuerPattern: /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/v2\.0$/,

  // SSRF guard — only the Microsoft hosts in MS_ALLOWED_HOSTS, HTTPS only.
  allowedHosts: MS_ALLOWED_HOSTS,
  isAllowedUrl: (rawUrl) => {
    let u;
    try { u = new URL(rawUrl); } catch { return false; }
    return u.protocol === 'https:' && MS_ALLOWED_HOSTS.includes(u.hostname.toLowerCase());
  },
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
  // Where Entra sends the admin back after consenting to the ZDNA connector app.
  // Must be registered as a redirect URI on that app.
  ENTRA_CONNECTOR_REDIRECT_URI: process.env.ENTRA_CONNECTOR_REDIRECT_URI || 'http://localhost:5000/auth/entra-connector/callback',
};

const SAML_CLAIMS = {
  EMAIL:     'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
  OID:       'http://schemas.microsoft.com/identity/claims/objectidentifier',
  DEPARTMENT:'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department',
  JOB_TITLE: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/jobtitle',
  ROLE:      'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
  GROUPS:    'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
};


const CONSUMER_MSA_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad';


module.exports = { microsoft, defaults, MS_LOGIN_BASE, MS_GRAPH_BASE, MS_STS_BASE,SAML_CLAIMS ,CONSUMER_MSA_TENANT};
