const https  = require('https');
const http   = require('http');
const crypto = require('crypto');
const { extractFromPkcs12 } = require('../../utils/oidc/pkcs12.util');
const { microsoft } = require('../../config/constants');
const { isCertAuth }        = require('../../utils/shared/authMethod.util');

const fetchJson = (url, options) =>
  new Promise((resolve, reject) => {
    const lib     = url.startsWith('https') ? https : http;
    const body    = options.body || null;
    const headers = { ...(options.headers || {}) };
    if (body) headers['Content-Length'] = Buffer.byteLength(body);

    const reqOptions = {
      method: options.method || 'GET',
      headers,
      ...(lib === https && options.rejectUnauthorized === false
        ? { agent: new https.Agent({ rejectUnauthorized: false }) }
        : {}),
    };

    const req = lib.request(url, reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });

const testOidcClientSecret = async ({ tenant_id, client_id, client_secret }) => {
  const tokenUrl = microsoft.tokenUrl(tenant_id);
  const params   = new URLSearchParams({
    grant_type:    'client_credentials',
    client_id,
    client_secret,
    scope:         microsoft.graphScope,
  });

  const res = await fetchJson(tokenUrl, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    params.toString(),
  });

  if (res.status === 200 && res.body.access_token) {
    return { success: true, message: 'Connection successful — credentials verified with Microsoft Entra' };
  }

  const errCode = res.body.error || 'unknown_error';
  const errDesc = res.body.error_description?.split('\r\n')[0] || 'Authentication failed';
  return { success: false, message: `${errCode}: ${errDesc}` };
};

const testOidcDiscovery = async ({ tenant_id }) => {
  const discoveryUrl = microsoft.discoveryUrl(tenant_id);
  const res = await fetchJson(discoveryUrl, { method: 'GET' });
  if (res.status === 200 && res.body.issuer) {
    return { success: true, message: 'Tenant reachable — PKCE flow ready' };
  }
  return { success: false, message: 'Tenant not found or unreachable' };
};

// Extracts ALL X509Certificate values from Azure federation metadata XML.
// Azure metadata contains multiple signing certs — must check all, not just the first.
// Returns array of raw base64 strings (whitespace stripped).
const extractCertsFromMetadata = (xmlString) => {
  if (typeof xmlString !== 'string') return [];
  const matches = [...xmlString.matchAll(/<X509Certificate[^>]*>([\s\S]+?)<\/X509Certificate>/gi)];
  return matches.map(m => m[1].replace(/\s+/g, ''));
};

// Extracts tenant ID from the metadata entityID attribute.
// Azure sets entityID="https://sts.windows.net/{tenant-id}/"
const extractTenantFromMetadata = (xmlString) => {
  if (typeof xmlString !== 'string') return null;
  const match = xmlString.match(/entityID=["']https:\/\/sts\.windows\.net\/([0-9a-f-]{36})\//i);
  return match ? match[1].toLowerCase() : null;
};

// Extracts tenant ID from an Azure SSO URL.
// Handles: https://login.microsoftonline.com/{tenant-id}/saml2?appid=...
const extractTenantFromSsoUrl = (url) => {
  if (typeof url !== 'string') return null;
  const match = url.match(/login\.microsoftonline\.com\/([0-9a-f-]{36})\//i);
  return match ? match[1].toLowerCase() : null;
};

const testSamlDiscovery = async ({ tenant_id, sso_url, certificate }) => {
  // Validate tenant ID in SSO URL before fetching metadata
  if (sso_url) {
    const urlTenant = extractTenantFromSsoUrl(sso_url);
    if (!urlTenant) {
      return { success: false, message: 'Could not extract tenant ID from SSO URL. Ensure it matches https://login.microsoftonline.com/{tenant-id}/saml2?appid={app-id}' };
    }
  }

  const metadataUrl = sso_url
    ? sso_url.replace('/saml2', '/federationmetadata/2007-06/federationmetadata.xml')
    : microsoft.samlMetadataUrl(tenant_id);

  // TLS validation stays ON by default (Entra endpoints have valid certs); only
  // a test-connection against a self-signed / staging IdP may opt out explicitly.
  const res = await fetchJson(metadataUrl, {
    method: 'GET',
    ...(process.env.SSO_TEST_ALLOW_SELF_SIGNED === 'true' ? { rejectUnauthorized: false } : {}),
  });
  if (res.status !== 200) {
    return { success: false, message: `SAML metadata unreachable (HTTP ${res.status})` };
  }

  // Verify the metadata entityID tenant matches the SSO URL tenant
  if (sso_url) {
    const urlTenant      = extractTenantFromSsoUrl(sso_url);
    const metadataTenant = extractTenantFromMetadata(res.body);
    if (metadataTenant && urlTenant && metadataTenant !== urlTenant) {
      return { success: false, message: `SSO URL tenant does not match metadata tenant. Expected ${urlTenant}, got ${metadataTenant}` };
    }
  }

  if (certificate) {
    const azureCerts = extractCertsFromMetadata(res.body);
    if (azureCerts.length === 0) {
      return { success: false, message: 'Could not extract signing certificate from Azure metadata' };
    }
    // Frontend sends certificate as base64(PEM string) — decode first to get PEM, then strip headers
    const pemString = Buffer.from(certificate, 'base64').toString('utf8');
    const uploadedCert = pemString
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
    if (!azureCerts.includes(uploadedCert)) {
      return { success: false, message: 'Certificate does not match Azure tenant signing certificate' };
    }
  }

  return { success: true, message: 'Connection successful — SAML IdP metadata reachable and certificate verified' };
};

/**
 * Builds the browser-test session for OIDC.
 *
 * @param {Object} params
 * @param {string} params.tenant_id             - Azure AD tenant GUID
 * @param {string} params.client_id             - Azure app client ID
 * @param {string} [params.client_secret]       - required for client_secret_post
 * @param {string} params.auth_method           - none | client_secret_post | private_key_jwt | certificate
 * @param {string} [params.redirect_uri]        - OAuth2 redirect URI (falls back to OIDC_REDIRECT_URI)
 * @param {string} [params.scope]               - defaults to 'openid profile email'
 * @param {string} [params.certificate]         - base64 PKCS#12 (cert auth only)
 * @param {string} [params.certificate_password]- PKCS#12 password (cert auth only)
 * @returns {{ sessionRef: string, config: Object, _internal: Object }}
 *          config is frontend-safe; _internal holds secrets (stored server-side in tcStore).
 */
const buildOidcTestSession = async ({ tenant_id, client_id, client_secret, auth_method, redirect_uri, scope, certificate, certificate_password }) => {
  const sessionRef = crypto.randomUUID();
  const state      = crypto.randomUUID();
  const nonce      = crypto.randomUUID();

  // PKCE pair — only used when auth_method is 'none'
  const codeVerifier  = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  // Client Certificate (private_key_jwt) — extract key + thumbprint from the .pfx
  // so the callback can build the client_assertion (signed JWT) for Entra.
  let privateKeyB64          = null;
  let clientCertThumbprint   = null;
  if (isCertAuth(auth_method)) {
    const extracted        = await extractFromPkcs12(certificate, certificate_password);
    privateKeyB64          = extracted.privateKeyB64;
    clientCertThumbprint   = extracted.thumbprintHex;
  }

  const callbackUri = redirect_uri || process.env.OIDC_REDIRECT_URI;
  const ssoUrl      = microsoft.authorizeUrl(tenant_id);

  return {
    sessionRef,
    config: {
      client_id,
      sso_url:      ssoUrl,
      redirect_uri: callbackUri,
      scope:        scope || 'openid profile email',
      state,
      nonce,
      ...(auth_method === 'none' && { code_challenge: codeChallenge, code_challenge_method: 'S256' }),
    },
    _internal: {
      tenant_id,
      client_id,
      client_auth_method: auth_method,
      client_secret:      client_secret || null,
      code_verifier:      auth_method === 'none' ? codeVerifier : null,
      private_key_b64:         privateKeyB64,       // cert auth: base64(PEM) private key
      client_cert_thumbprint:  clientCertThumbprint, // cert auth: SHA-1 hex thumbprint
      redirect_uri:       callbackUri,
      state,
      nonce,
    },
  };
};

const testConnection = async (payload) => {
  const { protocol, auth_method, tenant_id, client_id, client_secret, certificate, certificate_password, sso_url, redirect_uri, scope } = payload;

  if (protocol === 'oidc') {
    // Phase 1 — server-side credential pre-check
    const check = (auth_method === 'client_secret_post' && client_id && client_secret)
      ? await testOidcClientSecret({ tenant_id, client_id, client_secret })
      : await testOidcDiscovery({ tenant_id });

    if (!check.success) return check;

    // Phase 2 prep — browser popup session (sessionRef + state/nonce)
    const session = await buildOidcTestSession({ tenant_id, client_id, client_secret, auth_method, redirect_uri, scope, certificate, certificate_password });

    return {
      success: true,
      message: check.message,
      data: {
        protocol:           'oidc',
        client_auth_method: auth_method,
        sessionRef:         session.sessionRef,
        config:             session.config,
        _internal:          session._internal,
      },
    };
  }

  if (protocol === 'saml') {
    return testSamlDiscovery({ tenant_id, sso_url, certificate });
  }

  return { success: false, message: 'Unknown protocol' };
};

module.exports = { testConnection };
