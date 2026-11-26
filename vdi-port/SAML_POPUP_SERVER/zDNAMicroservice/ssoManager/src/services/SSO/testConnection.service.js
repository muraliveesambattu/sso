const https = require('node:https');
const crypto = require('node:crypto');
const { extractFromPkcs12 } = require('../../utils/oidc/pkcs12.util');
const { microsoft, defaults } = require('../../config/constants');
const { isCertAuth } = require('../../utils/shared/authMethod.util');
const { maskInput } = require('../../utils/shared/maskId.util');
const ssoIntegration = require('../../models/ssoIntegration.model');
const OidcConfiguration = require("../../models/oidcConfig.model");
const SamlConfiguration = require("../../models/samlConfig.model");
const { getSamlConfig, getOidcConfig } = require('../db/postgresSSO.service');
const { logger } = require('../../config/logger');
const { resolveSecret, validatePrivateKey, decryptStoredPrivateKey, validateThumbprint } = require('../../utils/crypto.util');
const tcStore = require('../../utils/shared/testConnectionStore');
const { createSsoError } = require('../../utils/shared/responseHandler');
const { buildSamlRedirectUrl } = require('../Saml/samlAuthRequest.service');

// SSRF/traversal allowlist for fetchJson. Deliberately arrays checked with
// .includes(), NOT Sets with .has(): that is the form the security rules'
// (S5144/S7044) compliant solutions prescribe, and each list is tiny, so the
// O(n)-lookup rationale behind S7776 does not apply.
const ALLOWED_SCHEMES = new Set(['https:']);
const ALLOWED_HOSTS = microsoft.allowedHosts;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TENANT_SCOPES = new Set(['common', 'consumers', 'organizations']);


const blockedUrlError = () =>
  createSsoError(
    'OUTBOUND_HOST_NOT_ALLOWED',
    'Outbound request blocked — host not allowed'
  );


const fetchJson = (url, options) =>
  new Promise((resolve, reject) => {
    // SSRF/traversal guard: `url` derives from tenant-controlled config
    // (tenant_id, sso_url) — tenant_id is format-gated in testConnection and
    // SAML tenants come from a regex-validated GUID, so no user text can alter
    // the path. The scheme + host allowlist is asserted here, in the same scope
    // as the request, and the request is made ONLY inside that branch
    // (CWE-918/CWE-22 — S5144/S7044).
    let target;
    try { target = new URL(url); } catch { return reject(blockedUrlError()); }
    if (ALLOWED_SCHEMES.has(target.protocol) && ALLOWED_HOSTS.includes(target.hostname.toLowerCase())) {
      const body = options.body || null;
      const headers = { ...options.headers };
      if (body) headers['Content-Length'] = Buffer.byteLength(body);
      const reqOptions = {
        method: options.method || 'GET',
        headers,
      };
      const req = https.request(target, reqOptions, (res) => {
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
      return;
    }
    reject(blockedUrlError());
  });

const testOidcClientSecret = async ({ tenant_id, client_id, client_secret }) => {
  logger.debug('[OIDC] Testing client secret', {
    tenantIdMasked: maskInput(String(tenant_id)),
  });
  const tokenUrl = microsoft.tokenUrl(tenant_id);
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id,
    client_secret,
    scope: microsoft.graphScope,
  });
  const res = await fetchJson(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  if (res.status === 200 && res.body.access_token) {
    return { success: true, message: 'Connection successful — credentials verified with Microsoft Entra' };
  }
  const errCode = res.body.error || 'unknown_error';
  const errDesc = res.body.error_description?.split('\r\n')[0] || 'Authentication failed';
  return { success: false, message: `${errCode}: ${errDesc}` };
};

const testOidcDiscovery = async ({ tenant_id }) => {
  logger.debug('[OIDC] Testing discovery endpoint', {
    tenantIdMasked: maskInput(String(tenant_id)),
  });
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
  return matches.map(m => m[1].replaceAll(/\s+/g, ''));
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

// Extracts the per-app id from an Azure SSO URL query string.
// Azure sets ?appid={app-id} when the application has its own signing cert —
// that cert only appears in the appid-scoped metadata, never the tenant default.
const extractAppIdFromSsoUrl = (url) => {
  if (typeof url !== 'string') return null;
  const match = url.match(/[?&]appid=([0-9a-f-]{36})\b/i);
  return match ? match[1].toLowerCase() : null;
};

const buildSamlMetadataUrl = (sso_url, tenant_id) => {
  logger.debug('Building SAML metadata URL', {
    ssoUrlConfigured: !!sso_url,
    tenantIdMasked: maskInput(String(tenant_id)),
  });
  const tenant = sso_url ? extractTenantFromSsoUrl(sso_url) : tenant_id;
  const base = microsoft.samlMetadataUrl(tenant);
  const url = new URL(base);
  const appId = extractAppIdFromSsoUrl(sso_url);
  if (appId) url.searchParams.set('appid', appId);
  return url.toString();
};

const validateSigningCertificate = async ({
  sign_authn_request, use_existing_signing_cert, signing_certificate, signing_certificate_password,
}) => {
  if (!sign_authn_request) return null;
  try {
    if (!use_existing_signing_cert) {
      await extractFromPkcs12(signing_certificate, signing_certificate_password);
    }
    return null;
  } catch {
    return { success: false, message: 'Invalid signing certificate or certificate password.' };
  }
};

const validateMetadataTenant = (sso_url, metadataXml) => {
  if (!sso_url) return null;
  const urlTenant = extractTenantFromSsoUrl(sso_url);
  const metadataTenant = extractTenantFromMetadata(metadataXml);
  if (metadataTenant && urlTenant && metadataTenant !== urlTenant) {
    return {
      success: false,
      message: `SSO URL tenant does not match metadata tenant. Expected ${urlTenant}, got ${metadataTenant}`,
    };
  }
  return null;
};

const validateAzureCertificate = (certificate, metadataXml) => {
  if (!certificate) {
    logger.debug('Azure certificate verification skipped — certificate not provided');
    return { success: false, message: 'Certificate not provided for validation.' };
  }
  logger.debug('Starting Azure certificate verification', {
    uploadedCertificateProvided: Boolean(certificate),
    encodedCertificateLength: certificate.length,
  });
  const azureCerts = extractCertsFromMetadata(metadataXml);
  if (azureCerts.length === 0) {
    return { success: false, message: 'Could not extract signing certificate from Azure metadata' };
  }
  const pemString = Buffer.from(certificate, 'base64').toString('utf8');
  const uploadedCert = pemString
    .replaceAll('-----BEGIN CERTIFICATE-----', '')
    .replaceAll('-----END CERTIFICATE-----', '')
    .replaceAll(/\s+/g, '');
  if (!azureCerts.includes(uploadedCert)) {
    logger.debug('[Azure certificate] verification failed', {
      azureCertificateCount: azureCerts.length,
      uploadedCertificateLength: uploadedCert.length,
    });
    return { success: false, message: 'Certificate does not match Azure tenant signing certificate' };
  }
  return { success: true };
};

const getExistingSamlSigningCertificate = async (company_id, signing_certificate) => {
  if (!company_id || signing_certificate) return signing_certificate;
  const saml = await getSamlConfig(company_id);
  return saml?.sp_private_key_enc || undefined;
};

const testSamlDiscovery = async ({
  tenant_id, sso_url,
  certificate, sign_authn_request, signing_certificate,
  signing_certificate_password, use_existing_signing_cert,
}) => {
  logger.debug('SAML discovery test connection started', {
    tenantIdMasked: maskInput(String(tenant_id)),
    hasCertificate: Boolean(certificate),
    signAuthnRequest: sign_authn_request,
    hasSigningCertificate: Boolean(signing_certificate),
    hasSigningCertificatePassword: Boolean(signing_certificate_password),
    useExistingSigningCert: use_existing_signing_cert,
  });
  if (sso_url) {
    const urlTenant = extractTenantFromSsoUrl(sso_url);
    if (!urlTenant) {
      return {
        success: false,
        message: 'Could not extract tenant ID from SSO URL. Ensure it matches https://login.microsoftonline.com/{tenant-id}/saml2',
      };
    }
  }
  const signingValidation = await validateSigningCertificate({
    sign_authn_request, use_existing_signing_cert, signing_certificate, signing_certificate_password,
  });
  if (signingValidation) return signingValidation;
  const metadataUrl = buildSamlMetadataUrl(sso_url, tenant_id);
  const res = await fetchJson(metadataUrl, { method: 'GET' });
  logger.debug('SAML metadata response received', {
    tenantIdMasked: maskInput(String(tenant_id)),
    status: res.status,
    hasBody: Boolean(res.body),
    bodyType: typeof res.body,
    bodyLength: typeof res.body === 'string' ? res.body.length : JSON.stringify(res.body || '').length,
  });
  if (res.status !== 200) {
    logger.debug('SAML metadata request failed', {
      tenantIdMasked: maskInput(String(tenant_id)),
      status: res.status,
    });
    return { success: false, message: `SAML metadata unreachable (HTTP ${res.status})` };
  }
  const tenantValidation = validateMetadataTenant(sso_url, res.body);
  if (tenantValidation) return tenantValidation;
  if (!certificate) return { success: false, message: 'Certificate not provided for validation.' };
  // Tenant metadata doesn't list an app's own signing cert, so this match needs ?appid=.
  // Without it, the popup verifies the real response signature against this certificate.
  if (!extractAppIdFromSsoUrl(sso_url)) {
    return { success: true, message: 'Connection successful — SAML IdP metadata reachable' };
  }
  const certificateValidation = validateAzureCertificate(certificate, res.body);
  if (!certificateValidation.success) return certificateValidation;
  return { success: true, message: 'Connection successful — SAML IdP metadata reachable and certificate verified' };
};

// Builds the browser-test session for SAML: an Entra login (ForceAuthn) whose ACS callback is
// validated against the unsaved cert/sso_url held server-side in samlRequestStore.
const buildSamlTestSession = async ({ sso_url, certificate }) => {
  const sessionRef  = crypto.randomUUID();
  const entityId    = defaults.SAML_ENTITY_ID;
  const acsUrl      = defaults.SAML_ACS_URL;
  const redirectUrl = await buildSamlRedirectUrl(entityId, acsUrl, sso_url, {}, sessionRef, undefined, {
    forceAuthn:  true,
    testContext: { sessionRef, certificate, sso_url, entity_id: entityId, acs_url: acsUrl },
  });
  return { protocol: 'saml', sessionRef, redirectUrl };
};

// After the metadata check passes, adds the popup session the console opens to sign in.
// The popup is where the certificate is really checked (against the signed response), so
// failing to build it fails the test instead of passing without that check.
const withSamlTestSession = async (check, { sso_url, certificate }) => {
  if (!check.success || !sso_url || !certificate) return check;
  try {
    return { ...check, data: await buildSamlTestSession({ sso_url, certificate }) };
  } catch (err) {
    logger.warn('[SAML_TEST_SESSION_FAILED]', { error: err.message });
    return { success: false, message: 'Could not start the SAML test sign-in. Please try again.' };
  }
};

const resolveCertificateCredentials = async ({
  certificate,
  certificatePassword,
  encryptedPrivateKey,
  clientCertThumbprint,
  useExistingCert,
  isExistingTest,
}) => {
  if (useExistingCert || isExistingTest) {
    return {
      privateKeyB64: decryptStoredPrivateKey(encryptedPrivateKey),
      clientCertThumbprint: validateThumbprint(clientCertThumbprint),
    };
  }

  if (!certificate) {
    throw createSsoError(
      'SSO_CERTIFICATE_REQUIRED',
      'Certificate is required for certificate-based authentication.'
    );
  }

  try {
    const extracted = await extractFromPkcs12(
      certificate,
      certificatePassword
    );

    return {
      privateKeyB64: validatePrivateKey(extracted.privateKeyB64),
      clientCertThumbprint: validateThumbprint(extracted.thumbprintHex),
    };
  } catch (error) {
    if (error.code?.startsWith('SSO_')) {
      throw error;
    }

    logger.warn('[OIDC] Certificate extraction failed', {
      code: error.code || 'SSO_CERTIFICATE_EXTRACTION_FAILED',
    });

    throw createSsoError(
      'SSO_CERTIFICATE_INVALID',
      'Invalid certificate or certificate password.'
    );
  }
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
const buildOidcTestSession = async ({
  tenant_id: tenantId,
  client_id: clientId,
  client_secret: clientSecret,
  auth_method: authMethod,
  redirect_uri: redirectUri,
  scope,
  certificate,
  certificate_password: certificatePassword,
  encrypted_private_key: encryptedPrivateKey,
  client_cert_thumbprint: clientCertThumbprint,
  use_existing_cert: useExistingCert = false,
  is_existing_test: isExistingTest = false,
}) => {
    if (typeof useExistingCert !== 'boolean') {
    throw createSsoError(
      'SSO_USE_EXISTING_CERT_INVALID',
      'use_existing_cert must be a boolean.'
    );
  }

  if (typeof isExistingTest !== 'boolean') {
    throw createSsoError(
      'SSO_EXISTING_TEST_FLAG_INVALID',
      'is_existing_test must be a boolean.'
    );
  }
  // NOTE: certificate_password and private_key_b64 are secrets — never log, return, or persist in plaintext beyond this scope.
  const sessionRef = crypto.randomUUID();
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  // PKCE pair — only used when auth_method is 'none'
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  // Client Certificate (private_key_jwt) — extract key + thumbprint from the .pfx
  // so the callback can build the client_assertion (signed JWT) for Entra.
  let privateKeyB64 = null;
  let resolvedThumbprint = null;

  if (isCertAuth(authMethod)) {
     const resolvedCredentials = await resolveCertificateCredentials({
      certificate,
      certificatePassword,
      encryptedPrivateKey,
      clientCertThumbprint,
      useExistingCert,
      isExistingTest,
    });
    privateKeyB64 = resolvedCredentials.privateKeyB64;
    resolvedThumbprint = resolvedCredentials.clientCertThumbprint;
  }

  const callbackUri = redirectUri || process.env.OIDC_REDIRECT_URI;
  const ssoUrl = microsoft.authorizeUrl(tenantId);
    tcStore.set(sessionRef, {
    tenant_id: tenantId,
    client_id: clientId,
    client_auth_method: authMethod,
    client_secret: clientSecret || null,
    code_verifier: authMethod === 'none' ? codeVerifier : null,
    private_key_b64: privateKeyB64,
    client_cert_thumbprint: resolvedThumbprint,
    redirect_uri: callbackUri,
    state,
    nonce,
  });
  logger.debug('[OIDC] Test session built', {
    tenantIdMasked: maskInput(String(tenantId)),
    authMethod,
    hasCertificate: Boolean(certificate || encryptedPrivateKey),
    hasPrivateKey: Boolean(privateKeyB64),
    hasThumbprint: Boolean(resolvedThumbprint),
    sessionRef,
  });
  return {
    sessionRef,
    config: {
      client_id:clientId,
      sso_url: ssoUrl,
      redirect_uri: callbackUri,
      scope: scope || 'openid profile email',
      state,
      nonce,
      ...(authMethod === 'none' && { code_challenge: codeChallenge, code_challenge_method: 'S256' }),
    },
  };
};

// tenant_id gets interpolated into Microsoft URL PATHS (tokenUrl/discoveryUrl/
// authorizeUrl/samlMetadataUrl). Without a format check a value like
// "common/../x" would steer the request path anywhere on the (allowlisted)
// Microsoft host — S7044. Same vocabulary as saveSsoConfig's validation:
// an Entra tenant GUID or one of the documented aliases. After this check no
// path metacharacter can survive, so every URL built from tenant_id is inert.
const isValidTenantScope = (tenant_id) =>
  typeof tenant_id === 'string' && (UUID_RE.test(tenant_id) || TENANT_SCOPES.has(tenant_id));

const validateTenantOwnership = async (tenant_id, company_id) => {
  if (!tenant_id) return null;
  try {
    const existingTenant = await ssoIntegration.findOne({ where: { entra_tenant_id: tenant_id } });
    if (!existingTenant) {
      return null;
    }

      logger.debug('SSO tenant ownership verification', {
        tenantIdMasked: maskInput(String(tenant_id)),
        companyIdMasked: maskInput(String(company_id)),
      });
      const dbCompanyId = existingTenant.dataValues
        ? existingTenant.dataValues.company_id
        : existingTenant.company_id;
      if (
        dbCompanyId != null &&
        company_id != null &&
        String(dbCompanyId).trim() !== String(company_id).trim()
      ) {
        return {
          success: false,
          message: 'This Microsoft Entra tenant ID is already registered by another organization.',
        };
      }
    
    return null;
  } catch (dbError) {
    logger.error('Database verification failed', {
      tenantIdMasked: maskInput(String(tenant_id)),
      companyIdMasked: maskInput(String(company_id)),
      error: dbError.message,
    });
    return {
      success: false,
      message: 'Internal server error occurred while verifying tenant configuration.',
    };
  }
};

const testConnection = async (payload) => {
  let {
    protocol, auth_method, tenant_id, client_id, client_secret,
    certificate, certificate_password, use_existing_cert,
    sso_url, redirect_uri, scope, company_id, sign_authn_request,
    signing_certificate, signing_certificate_password, use_existing_signing_cert,
  } = payload;
  logger.debug('[testConnection] Initiated', {
    protocol,
    companyIdMasked: maskInput(String(company_id)),
    tenantIdMasked: maskInput(String(tenant_id)),
    authMethod: auth_method,
  });
  const tenantValidation = await validateTenantOwnership(tenant_id, company_id);
  if (tenantValidation) return tenantValidation;
  if (tenant_id && !isValidTenantScope(tenant_id)) {
    return { success: false, message: 'tenant_id must be a valid UUID or common/consumers/organizations' };
  }
  if (protocol === 'oidc') {
    const check = (auth_method === 'client_secret_post' && client_id && client_secret)
      ? await testOidcClientSecret({ tenant_id, client_id, client_secret })
      : await testOidcDiscovery({ tenant_id });
    if (!check.success) return check;
    let encryptedPrivateKey = null;
    let oidcThumbprint = null;
    if (use_existing_cert && company_id && auth_method === 'private_key_jwt') {
      const oidc = await getOidcConfig(company_id);
      if (!oidc) {
        throw createSsoError(
          'SSO_CONFIGURATION_NOT_FOUND',
          'Stored OIDC configuration was not found.',
          404
        );
      }
      encryptedPrivateKey = oidc.private_key_enc || null;
      oidcThumbprint = oidc.client_cert_thumbprint || null;
      logger.debug('OIDC existing certificate retrieved', {
        companyIdMasked: maskInput(String(company_id)),
        tenantIdMasked: maskInput(String(tenant_id)),
        hasPrivateKey: Boolean(encryptedPrivateKey),
        hasThumbprint: Boolean(oidcThumbprint),
      });
    }
    const session = await buildOidcTestSession({
      tenant_id,
      client_id,
      client_secret,
      auth_method,
      redirect_uri,
      scope,
      certificate,
      certificate_password,
      encrypted_private_key: encryptedPrivateKey,
      client_cert_thumbprint: oidcThumbprint,
      use_existing_cert: use_existing_cert === true,
    });
    return {
      success: true,
      message: check.message,
      data: {
        protocol: 'oidc',
        client_auth_method: auth_method,
        sessionRef: session.sessionRef,
        config: session.config,
      },
    };
  }
  if (protocol === 'saml') {
    logger.debug('SAML protocol flow initiated', {
      companyIdMasked: maskInput(String(company_id)),
      tenantIdMasked: maskInput(String(tenant_id)),
    });
    if (use_existing_signing_cert) {
      signing_certificate = await getExistingSamlSigningCertificate(company_id, signing_certificate);
    }
    const check = await testSamlDiscovery({
      tenant_id, sso_url,
      certificate, sign_authn_request, signing_certificate,
      signing_certificate_password, use_existing_signing_cert,
    });
    return withSamlTestSession(check, { sso_url, certificate });
  }
  return { success: false, message: 'Unknown protocol' };
};

const getSsoConfigForActivation = async (company_id) => {
  logger.debug('[getSsoConfigForActivation] Fetching SSO config', {
    companyIdMasked: maskInput(String(company_id)),
  });
  const integration = await ssoIntegration.findByPk(company_id);
  if (!integration) return null;
  if (integration.protocol === 'oidc') {
    const oidc = await OidcConfiguration.findOne({ where: { company_id } });
     if (!oidc) {
      return null;
    }
    return {
      protocol: 'oidc',
      tenant_id: integration.entra_tenant_id,
      client_id: oidc.client_id,
      auth_method: oidc.client_auth_method,
      client_secret: resolveSecret(oidc.client_secret_enc),
      scope: oidc.scope,
      redirect_uri: oidc.redirect_uri,
      private_key_enc:oidc.private_key_enc || null,
      client_cert_thumbprint:
              oidc.client_cert_thumbprint || null,
    };
  }
  if (integration.protocol === 'saml') {
    const saml = await SamlConfiguration.findOne({ where: { company_id } });
    return {
      protocol: 'saml',
      tenant_id: integration.entra_tenant_id,
      sso_url: saml.sso_url,
      certificate: resolveSecret(saml.certificate),
    };
  }
  return null;
};

const validateSsoConfiguration = async (company_id) => {
  logger.debug('[validateSsoConfiguration] Started', {
    companyIdMasked: maskInput(String(company_id)),
  });
  const config = await getSsoConfigForActivation(company_id);

  if (!config) {
    throw createSsoError(
      'SSO_CONFIGURATION_NOT_FOUND',
      'SSO configuration was not found.',
      404
    );
  }
  if (config.protocol === 'oidc') {
    const check = config.auth_method === 'client_secret_post'
      ? await testOidcClientSecret({
        tenant_id: config.tenant_id,
        client_id: config.client_id,
        client_secret: config.client_secret,
      })
      : await testOidcDiscovery({ tenant_id: config.tenant_id });
    logger.debug('[validateSsoConfiguration] OIDC pre-check result', {
      companyIdMasked: maskInput(String(company_id)),
      tenantIdMasked: maskInput(String(config.tenant_id)),
      success: check.success,
    });
      if (!check.success) {
      return check;
    }
    const session = await buildOidcTestSession({
      tenant_id: config.tenant_id,
      client_id: config.client_id,
      client_secret: config.client_secret,
      auth_method: config.auth_method,
      redirect_uri: config.redirect_uri,
      scope: config.scope,
      encrypted_private_key: config.private_key_enc || null,
      client_cert_thumbprint: config.client_cert_thumbprint || null,
      is_existing_test: true,
    });
    return {
      success: true,
      message: check.message,
      data: {
        protocol: 'oidc',
        client_auth_method: config.auth_method,
        sessionRef: session.sessionRef,
        config: session.config,
      },
    };
  }
  if (config.protocol === 'saml') {
    logger.debug('[validateSsoConfiguration] SAML validation started', {
      companyIdMasked: maskInput(String(company_id)),
      tenantIdMasked: maskInput(String(config.tenant_id)),
    });
    const check = await testSamlDiscovery({
      tenant_id: config.tenant_id,
      sso_url: config.sso_url,
      certificate: config.certificate,
    });
    return withSamlTestSession(check, { sso_url: config.sso_url, certificate: config.certificate });
  }
  return { success: false, message: 'Unknown protocol' };
};


module.exports = { testConnection, validateSsoConfiguration };
 