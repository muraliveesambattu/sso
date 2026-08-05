/**
 * Low-level utilities for the authorization code → token exchange with Entra.
 *
 * Supports three client auth methods:
 *   client_secret / client_secret_post → shared secret in POST body
 *   private_key_jwt    → signed JWT assertion using client certificate
 *   none (PKCE)        → code_verifier proves possession of code_challenge
 */

const https  = require('node:https');
const { logger } = require('../../config/logger');
const crypto = require('node:crypto');
const { URL } = require('node:url');
const { microsoft } = require('../../config/constants');

// Builds the URL-encoded POST body for the /token request
const buildRequestParams = (code, clientId, authMethod, authCredential, redirectUri) => {
  const base = {
    grant_type:   'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id:    clientId
  };

  switch (authMethod) {
    // 'secret' is the console's raw form value — it reaches this column when a
    // save path skips AUTH_METHOD_MAP's translation to 'client_secret_post'.
    // resolveAuthCredential already accepts it, so accepting it here keeps the
    // two switches in step; otherwise the credential resolves and the request
    // body build throws.
    case 'client_secret_post':
    case 'client_secret':
    case 'secret':
      return new URLSearchParams({ ...base, client_secret: authCredential });

    case 'none': {
      logger.debug(`[TOKEN-EXCHANGE] PKCE | code_verifier present: ${!!authCredential} | length: ${authCredential?.length}`);
      const pkceParams = new URLSearchParams({ ...base, code_verifier: authCredential });
      logger.debug(`[TOKEN-EXCHANGE] PKCE body keys: ${[...pkceParams.keys()].join(', ')}`);
      return pkceParams;
    }

    case 'private_key_jwt':
      return new URLSearchParams({
        ...base,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion:      authCredential
      });

    default:
      throw new Error(`Unsupported client_auth_method: ${authMethod}`);
  }
};

/**
 * Generates a signed JWT assertion for private_key_jwt authentication.
 *
 * The JWT proves to Entra that we hold the private key matching the
 * certificate registered in the App Registration.
 *
 * Claims follow RFC 7523:
 *   aud → Entra token endpoint
 *   iss/sub → client_id
 *   jti → unique per request (prevents assertion replay)
 *   exp → 10-minute window
 */
const generateJwtAssertion = (clientId, tenantId, privateKeyEnc, thumbprint) => {
  const now = Math.floor(Date.now() / 1000);

  // Decode base64-encoded PEM key stored in ssoData
  const privateKeyPem = Buffer.from(privateKeyEnc, 'base64').toString('utf8');

  // x5t must be base64url-encoded SHA-1 thumbprint (Azure shows it as hex)
  const x5t = Buffer.from(thumbprint, 'hex').toString('base64url');

  const header = Buffer.from(JSON.stringify({
    alg: 'RS256',
    typ: 'JWT',
    x5t               // tells Entra which registered certificate to use
  })).toString('base64url');

  const payload = Buffer.from(JSON.stringify({
    aud: microsoft.tokenUrl(tenantId),
    iss: clientId,
    sub: clientId,
    jti: crypto.randomUUID(),
    exp: now + 600,
    iat: now,
    nbf: now
  })).toString('base64url');

  const signingInput = `${header}.${payload}`;
  const signature    = crypto
    .sign('RSA-SHA256', Buffer.from(signingInput), privateKeyPem)
    .toString('base64url');

  return `${signingInput}.${signature}`;
};

/**
 * Exchanges the authorization code for tokens via Entra's /token endpoint.
 *
 * - No retry logic — auth codes are single-use
 * - 10-second timeout
 * - rejectUnauthorized: true always (never disable TLS verification)
 */
const exchangeCodeForTokens = (code, clientId, authMethod, authCredential, redirectUri, tokenEndpoint) => {
  return new Promise((resolve, reject) => {
    try {
      const params   = buildRequestParams(code, clientId, authMethod, authCredential, redirectUri);
      const postBody = params.toString();
      const url      = new URL(tokenEndpoint);

      const options = {
        hostname: url.hostname,
        path:     url.pathname,
        method:   'POST',
        headers: {
          'Content-Type':   'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(postBody)
        },
        timeout:             10000,
        rejectUnauthorized:  true
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            if (res.statusCode === 200) resolve(JSON.parse(data));
            else reject(new Error(`Token exchange failed: HTTP ${res.statusCode} — ${data}`));
          } catch (err) {
            reject(new Error(`Failed to parse token response: ${err.message}`));
          }
        });
      });

      req.on('error',   err => reject(new Error(`Network error: ${err.message}`)));
      req.on('timeout', ()  => { req.destroy(); reject(new Error('Token exchange timed out')); });
      req.write(postBody);
      req.end();

    } catch (err) {
      reject(new Error(`Token exchange setup error: ${err.message}`));
    }
  });
};

/**
 * Decodes a JWT without verifying its signature.
 * Used only to read the header (kid) and payload before signature verification.
 * Never trust decoded claims until verifyJwtSignature() has been called.
 */
const decodeJwt = (token) => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT format');

    return {
      header:  JSON.parse(Buffer.from(parts[0], 'base64url').toString()),
      payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString())
    };
  } catch (err) {
    const error = new Error(`JWT decode error: ${err.message}`);
    error.statusCode = 400;
    error.code = 'JWT_DECODE_FAILED';
    throw error;
  }
};

module.exports = { exchangeCodeForTokens, decodeJwt, generateJwtAssertion };
