// Must be registered in Entra — sent as redirect_uri and matched byte-for-byte.
export const REDIRECT_URI   = `${window.location.origin}/auth/oidc/callback`;
export const SAML_ACS_URL   = process.env.REACT_APP_SAML_ACS_URL;
export const SAML_ENTITY_ID = process.env.REACT_APP_SAML_ENTITY_ID;

// Same-origin; Hosting rewrites route each path. Keep separate — API_BASE_GATEWAY
// reaches ssoGateway, API_BASE reaches the sso service directly.
export const API_BASE       = '';
export const API_BASE_GATEWAY = '';

export const AUTH_METHOD_MAP = {
  secret:      'client_secret_post',
  certificate: 'private_key_jwt',
  none:        'none',
};
export const FILE_FIELDS = ['certificate', 'saml_cert', 'saml_signing_cert'];

export const PROTOCOL_RESET_FIELDS = [
  'auth_method', 'client_id', 'tenant_id', 'client_secret', 'entra_domain',
  'certificate', 'certificate_password', 'entity_id', 'acs_url', 'sso_url',
  'saml_cert', 'sign_auth', 'saml_signing_cert', 'saml_signing_cert_password',
];
export const IDP_RESET_FIELDS = [
  'protocol', 'auth_method', 'client_id', 'tenant_id', 'client_secret',
  'entra_domain', 'certificate', 'certificate_password', 'entity_id',
  'acs_url', 'sso_url', 'saml_cert', 'sign_auth',
];

 export const ZDNA_ROLES = [
  { role_id: 'role-admin',   role_name: 'Administrator' },
  { role_id: 'role-analyst', role_name: 'Analyst' },
  { role_id: 'role-viewer',  role_name: 'Viewer' },
];

// SSO field format validators
export const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const FQDN =
  /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z]{2,})+$/;
export const HTTPS =  /^https:\/\/.+/;
export const PEM_BODY =
  /^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/;
