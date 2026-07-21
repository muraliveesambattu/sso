/**
 * Domain Check Service
 *
 * Validates the user's email or domain, looks up the SSO integration,
 * and returns the config the frontend needs to build the /authorize URL.
 *
 * Auth method behaviour:
 *
 *   client_auth_method = 'none' (PKCE):
 *     - Backend generates: state, nonce, code_verifier, code_challenge
 *     - Stores in session: { state, nonce, code_verifier, company_id, createdAt }
 *     - Returns to frontend: state, nonce, code_challenge, code_challenge_method
 *     - code_verifier NEVER leaves the server
 *
 *   client_auth_method = 'client_secret' | 'client_secret_post' | 'private_key_jwt':
 *     - Backend generates: state, nonce
 *     - Stores in session: { state, nonce, company_id, createdAt }
 *     - Returns to frontend: state, nonce, client_id, sso_url, redirect_uri, scope
 *     - No code_verifier needed — credential resolved server-side at token exchange
 */

const crypto   = require('crypto');
const { logger }    = require('../../config/logger');
const { isEnabled } = require('../featureFlag.service');
const { buildSamlRedirectUrl } = require('../Saml/samlAuthRequest.service');
const {
  getSsoIntegrationByDomain,
  getOidcConfig,
  getSamlConfig,
} = require('../db/ssoDataService');
const { stateStore } = require('../../config/stateStore');
const { microsoft } = require('../../config/constants');
const { resolveSecret } = require('../../utils/crypto.util');

// ── OIDC State Store ──────────────────────────────────────────────────────────
// In-memory, TTL-based store keyed by `state` (10-minute expiry, single-use).
const OIDC_TTL_MS      = 600000; // 10 minutes
const OIDC_TTL_SECONDS = 600;

const EMAIL_REGEX  = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const DOMAIN_REGEX = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// ── Config Readers ────────────────────────────────────────────────────────────

// Secret resolution (env: refs AND enc: encrypted values) uses the shared
// crypto.util.resolveSecret — see resolveSecret below. A previous local helper
// only handled env: refs and silently passed enc:-encrypted secrets through
// undecrypted.

// Finds the active SSO integration for a domain
const lookupSsoConfig = async (domain) => {
  const integration = await getSsoIntegrationByDomain(domain);
  if (!integration) return null;

  // ── Feature flag: sso_enabled ─────────────────────────────────────────────
  const ssoEnabled = await isEnabled(integration.company_id, 'sso_enabled');
  if (!ssoEnabled) {
    logger.info('SSO disabled by feature flag', {
      action:     'sso_flag_blocked',
      company_id: integration.company_id,
      domain,
    });
    return null; // treated as "not configured" — returns generic not-found message
  }

  if (integration.protocol === 'saml') {
    const saml = await getSamlConfig(integration.company_id);
    if (!saml) return null;
    return {
      company_id: integration.company_id,
      protocol:   'saml',
      entity_id:  saml.entity_id,
      sso_url:    saml.sso_url,
      acs_url:    saml.acs_url,
    };
  }

  if (integration.protocol === 'oidc') {
    const oidc = await getOidcConfig(integration.company_id);
    if (!oidc) return null;

    // Build the authorization URL dynamically from entra_tenant_id stored in
    // sso_integrations. This means no sso_url is needed in oidc_configurations —
    // just change entra_tenant_id to control which users can authenticate:
    //   "consumers"  → any personal Microsoft / Gmail account (via MSA tenant)
    //   "common"     → any Microsoft account (work, school, or personal)
    //   "<tenant-id>"→ only users in that specific Azure tenant
    const ssoUrl = microsoft.authorizeUrl(integration.entra_tenant_id);

    return {
      company_id:             integration.company_id,
      protocol:               'oidc',
      entra_tenant_id:        integration.entra_tenant_id,
      client_id:              oidc.client_id,
      client_auth_method:     oidc.client_auth_method,
      client_secret:          resolveSecret(oidc.client_secret),
      client_cert_enc:        oidc.client_cert_enc,
      client_cert_thumbprint: oidc.client_cert_thumbprint,
      sso_url:                ssoUrl,   // dynamic — overrides any value in oidc_configurations
      redirect_uri:           resolveSecret(oidc.redirect_uri),
    };
  }

  return null;
};

// ── OIDC Response Builder ─────────────────────────────────────────────────────

/**
 * Builds the OIDC domain check response based on client_auth_method.
 *
 * PKCE (none):
 *   Generates state, nonce, code_verifier server-side.
 *   Stores in oidcStateStore (Map) keyed by state — no session cookie needed.
 *   Returns code_challenge to frontend — code_verifier stays on server only.
 *
 * client_secret_post / private_key_jwt:
 *   Generates state and nonce server-side.
 *   Stores in oidcStateStore keyed by state.
 *   Frontend validates state at callback via token-exchange.
 */
const buildOidcResponse = async (config) => {
  const state = crypto.randomBytes(16).toString('base64url');
  const nonce = crypto.randomBytes(16).toString('base64url');

  const storeEntry = {
    nonce,
    company_id: config.company_id,
    createdAt:  Date.now(),
  };

  const responseConfig = {
    client_id:     config.client_id,
    sso_url:       config.sso_url,
    redirect_uri:  config.redirect_uri,
    scope:         'openid profile email',
    state,
    nonce,
    response_mode: 'query',
  };

  if (config.client_auth_method === 'none') {
    // PKCE flow — backend owns codeVerifier, never sent to client
    const codeVerifier  = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');

    storeEntry.code_verifier             = codeVerifier;
    responseConfig.code_challenge        = codeChallenge;
    responseConfig.code_challenge_method = 'S256';
  }

  // Persist state to the in-memory state store with 10-minute TTL
  await stateStore.set(state, storeEntry, OIDC_TTL_SECONDS);
  logger.debug(`[STATE-STORE] Saved state | company_id: ${config.company_id} | ttl: ${OIDC_TTL_SECONDS}s`);

  return {
    found:              true,
    protocol:           'oidc',
    message:            'Redirecting to Microsoft Entra...',
    company_id:         config.company_id,
    client_auth_method: config.client_auth_method,
    config:             responseConfig,
  };
};

// ── SAML Response Builder ─────────────────────────────────────────────────────

const buildSamlResponse = async (config, session, sessionID) => {
  const redirectUrl = await buildSamlRedirectUrl(
    config.entity_id,
    config.acs_url,
    config.sso_url,
    session,
    sessionID,
    config.company_id
  );

  return {
    found:       true,
    protocol:    'saml',
    message:     'Redirecting to Microsoft Entra...',
    redirectUrl
  };
};

// ── Main Export ───────────────────────────────────────────────────────────────

const checkDomain = async (email, domain, session, sessionID) => {
  if (!email && !domain) {
    const err = new Error('Email or domain is required');
    err.statusCode = 400;
    err.code = 'MISSING_INPUT';
    throw err;
  }

  if (!session || !sessionID) {
    const err = new Error('Session unavailable');
    err.statusCode = 500;
    err.code = 'MISSING_SESSION';
    throw err;
  }

  let extractedDomain;

  if (email) {
    if (!EMAIL_REGEX.test(email)) {
      const err = new Error('Invalid email format');
      err.statusCode = 400;
      err.code = 'INVALID_EMAIL';
      throw err;
    }
    extractedDomain = email.split('@')[1].toLowerCase();
  } else {
    if (!DOMAIN_REGEX.test(domain)) {
      const err = new Error('Invalid domain format');
      err.statusCode = 400;
      err.code = 'INVALID_DOMAIN';
      throw err;
    }
    extractedDomain = domain.toLowerCase();
  }

  const config = await lookupSsoConfig(extractedDomain);

  if (!config) {
    return email
      ? { found: false, promptOrgDomain: true,  message: 'Please enter your organisation domain name' }
      : { found: false, promptOrgDomain: false, message: 'SSO is not available for this domain. Please contact your administrator.' };
  }

  if (config.protocol === 'saml') return buildSamlResponse(config, session, sessionID);

  return await buildOidcResponse(config);
};

module.exports = { checkDomain, stateStore, OIDC_TTL_MS };
