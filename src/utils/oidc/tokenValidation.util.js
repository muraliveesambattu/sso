
/**
 * Validates security claims in the decoded id_token and extracts identity claims.
 */

/**
 * Validates: iss, aud, exp, nbf, iat, token age, nonce
 * Any single failure throws immediately ,partial validation is not acceptable.
 */
// Microsoft's personal account (MSA) tenant ID — a well-known constant.
// When entra_tenant_id is 'consumers', the /authorize and /token endpoints
// accept personal Microsoft accounts, but the id_token issuer always contains
// this fixed GUID — NOT the word "consumers".
const CONSUMER_TENANT_ID = '9188040d-6c67-4c5b-b112-36a304b66dad';
const CLOCK_SKEW_SECONDS = 300;
const MAX_TOKEN_AGE_SECONDS = 3600;
const { microsoft } = require('../../config/constants');

// Build a 401 auth error with a stable error code.
const authError = (message, code) =>
  Object.assign(new Error(message), { statusCode: 401, code });

// Issuer must match the expected Entra tenant endpoint. For the 'common'
// endpoint the issuer is the user's own tenant, so accept any valid GUID issuer.
const validateIssuer = (idTokenClaims, tenantId) => {
  const effectiveTenantId = tenantId === 'consumers' ? CONSUMER_TENANT_ID : tenantId;
  const expectedIssuer = microsoft.issuer(effectiveTenantId);

  const issuerValid = tenantId === 'common'
    ? microsoft.issuerPattern.test(idTokenClaims.iss)
    : idTokenClaims.iss === expectedIssuer;

  if (!issuerValid) {
    throw authError(`Invalid issuer: expected ${expectedIssuer}, got ${idTokenClaims.iss}`, 'INVALID_ISSUER');
  }
};

// Audience must match our registered client_id.
const validateAudience = (idTokenClaims, oidcConfig) => {
  const audiences = Array.isArray(idTokenClaims.aud) ? idTokenClaims.aud : [idTokenClaims.aud];
  if (!audiences.includes(oidcConfig.client_id)) {
    throw authError(`Invalid audience: expected ${oidcConfig.client_id}`, 'INVALID_AUDIENCE');
  }
};

// Temporal claims: exp, nbf, iat, and overall token age.
const validateTemporalClaims = (idTokenClaims, now) => {
  if (!idTokenClaims.exp) {
    throw authError('Missing expiration claim (exp)', 'MISSING_EXPIRATION');
  }
  if (idTokenClaims.exp < (now - CLOCK_SKEW_SECONDS)) {
    throw authError(`Token expired at ${new Date(idTokenClaims.exp * 1000).toISOString()}`, 'TOKEN_EXPIRED');
  }
  if (idTokenClaims.nbf && idTokenClaims.nbf > (now + CLOCK_SKEW_SECONDS)) {
    throw authError(`Token not valid until ${new Date(idTokenClaims.nbf * 1000).toISOString()}`, 'TOKEN_NOT_YET_VALID');
  }
  if (!idTokenClaims.iat) {
    throw authError('Missing issued-at claim (iat)', 'MISSING_ISSUED_AT');
  }
  if (idTokenClaims.iat > (now + CLOCK_SKEW_SECONDS)) {
    throw authError('Token issued in the future', 'INVALID_ISSUED_AT');
  }
  if ((now - idTokenClaims.iat) > MAX_TOKEN_AGE_SECONDS) {
    throw authError(`Token too old: issued ${now - idTokenClaims.iat}s ago`, 'TOKEN_TOO_OLD');
  }
};

// Nonce binds the token to this specific auth session, preventing replay.
const validateNonce = (idTokenClaims, expectedNonce) => {
  if (!expectedNonce) return;
  if (!idTokenClaims.nonce) {
    throw authError('Missing nonce claim in token', 'MISSING_NONCE');
  }
  if (idTokenClaims.nonce !== expectedNonce) {
    throw authError('Nonce mismatch - possible replay attack', 'INVALID_NONCE');
  }
};

const validateTokenClaims = (idTokenClaims, oidcConfig, tenantId, expectedNonce) => {
  const now = Math.floor(Date.now() / 1000);

  validateIssuer(idTokenClaims, tenantId);
  validateAudience(idTokenClaims, oidcConfig);
  validateTemporalClaims(idTokenClaims, now);
  validateNonce(idTokenClaims, expectedNonce);

  return true;
};

/**
 * Validates required claims exist then returns the full id_token claims.
 * Required: oid or sub
 * Required: email (fallback: preferred_username access_token upn)
 * Returns everything Entra sends no claims are dropped.
 */
const validateUserClaims = (idTokenClaims, accessTokenClaims) => {
  if (!idTokenClaims.oid && !idTokenClaims.sub) {
    const err = new Error('Missing required claim: oid or sub');
    err.statusCode = 400; err.code = 'MISSING_OID'; throw err;
  }

  const email =
    idTokenClaims.email            ||
    idTokenClaims.preferred_username ||
    idTokenClaims.upn              ||
    accessTokenClaims?.upn;

  if (!email) {
    const err = new Error('Missing required claim: email');
    err.statusCode = 400; err.code = 'MISSING_EMAIL'; throw err;
  }

  return {
    oid: idTokenClaims.oid || idTokenClaims.sub,
    email,
    ...idTokenClaims
  };
};

module.exports = { validateTokenClaims, validateUserClaims };
