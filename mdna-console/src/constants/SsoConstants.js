export const REDIRECT_URI   = process.env.REACT_APP_OIDC_REDIRECT_URI;
export const SAML_ACS_URL   = process.env.REACT_APP_SAML_ACS_URL;
export const SAML_ENTITY_ID = process.env.REACT_APP_SAML_ENTITY_ID;

export const API_BASE         = '';
export const API_BASE_GATEWAY = process.env.REACT_APP_SSO_API_BASE_GATEWAY ?? '';

export const AUTH_METHOD_MAP = {
  secret:      'client_secret_post',
  certificate: 'private_key_jwt',
  none:        'none',
};
export const FILE_FIELDS = ['certificate', 'saml_cert', 'saml_signing_cert'];

export const PROTOCOL_RESET_FIELDS = [
  'auth_method', 'client_id', 'tenant_id','app_id', 'client_secret', 'entra_domain',
  'certificate', 'certificate_password', 'entity_id', 'acs_url', 'sso_url',
  'saml_cert', 'sign_auth', 'saml_signing_cert', 'saml_signing_cert_password',
];
export const IDP_RESET_FIELDS = [
  'protocol', 'auth_method', 'client_id', 'tenant_id', 'client_secret',
  'entra_domain', 'certificate', 'certificate_password', 'entity_id',
  'acs_url', 'sso_url', 'saml_cert', 'sign_auth',
];

// SSO field format validators
export const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const FQDN =
  /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z]{2,})+$/;
export const HTTPS =  /^https:\/\/.+/;
export const PEM_BODY =
  /^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/;

export const SAML_SSO_URL_PATTERN =
  /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/saml2$/i;

export const OIDC_SSO_URL_PATTERN =
  /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/oauth2\/v2\.0\/authorize$/i;

export const SAML_SSO_URL_EXAMPLE =
  'https://login.microsoftonline.com/{uuid}/saml2';

export const OIDC_SSO_URL_EXAMPLE =
  'https://login.microsoftonline.com/{uuid}/oauth2/v2.0/authorize';

export const CLIENT_SECRET_RE = /^[\x21-\x7E]+$/;

// ── Entra claims check (DLM-100021) ──────────────────────────────────────────
// jit_mappings.mapping_source is VARCHAR(30)
export const MAX_CLAIM_NAME_LENGTH = 30;
export const ROLE_CLAIMS = new Set(['role', 'roles']);
export const GROUP_CLAIMS = new Set(['group', 'groups']);
// Free-text user attributes: the value must be one some user in the tenant has.
export const USER_ATTRIBUTE_CLAIMS = {
  department: { key: 'departments', label: 'department' },
  jobtitle: { key: 'jobTitles', label: 'job title' },
};

export const ENTRA_CLAIM_ERRORS = {
  claimNameTooLong: (max) => `Claim name must be ${max} characters or fewer`,
  claimNotConfigured: (name) => `Claim "${name}" is not configured for this app in Microsoft Entra`,
  roleNotFound: (value) => `"${value}" is not an app role of this app in Microsoft Entra`,
  groupNotFound: (value) => `"${value}" is not a group assigned to this app in Microsoft Entra`,
  attributeNotFound: (label, value) => `No user in Microsoft Entra has ${label} "${value}"`,
};

// useEntraClaims: catalog loading
export const ENTRA_GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const ENTRA_SAML_TENANT_RE = /login\.microsoftonline\.com\/[0-9a-f-]{36}\//i;
export const ENTRA_CLAIMS_LOAD_DELAY_MS = 400;
export const ENTRA_CLAIMS_FAILED_MESSAGE = 'Could not load claims from Microsoft Entra. Please try again.';
export const ENTRA_CLAIMS_INCOMPLETE_MESSAGE = 'Microsoft Entra claims cannot be checked: the SSO configuration has no valid tenant or app ID.';
