
/**
 * Fetches Microsoft Entra's public JWKS keys and verifies the RS256
 * signature of a JWT (id_token or access_token).
 *
 * Only RS256 is accepted — rejects alg=none and HS256 attacks.
 *
 * JWKS keys are cached per tenant with a ~1hr TTL (Entra rotates signing keys
 * infrequently) so we don't hit Entra on every verification. If a token's `kid`
 * isn't in the cached set the cache is refreshed once before rejecting — this
 * handles a key rotation that happened before the TTL expired.
 */

const https  = require('https');
const crypto = require('crypto');
const { microsoft } = require('../../config/constants');

const JWKS_TIMEOUT_MS   = 10000;
const JWKS_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const jwksCache = new Map(); // tenantId -> { jwks, expiresAt }

// Marks an error as a JWKS-retrieval failure (network/timeout/HTTP/parse) so
// the caller can report it as a retryable 503 rather than a 401 auth rejection.
const jwksError = (message) => Object.assign(new Error(message), { jwksFetchError: true });

const fetchJwksFromNetwork = (tenantId) => {
  return new Promise((resolve, reject) => {
    const url = microsoft.jwksUrl(tenantId);

    const options = {
      rejectUnauthorized: process.env.NODE_ENV === 'production',
      timeout: JWKS_TIMEOUT_MS,
    };

    const req = https.get(url, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 200) resolve(JSON.parse(data));
          else reject(jwksError(`JWKS fetch failed: HTTP ${res.statusCode}`));
        } catch (err) {
          reject(jwksError(`Failed to parse JWKS response: ${err.message}`));
        }
      });
    });
    req.on('error', err => reject(jwksError(`JWKS network error: ${err.message}`)));
    req.on('timeout', () => { req.destroy(); reject(jwksError('JWKS fetch timed out')); });
  });
};

// Returns the tenant's JWKS, served from a 1hr cache. `forceRefresh` bypasses
// the cache — used on a kid miss, where keys may have rotated before the TTL.
const getJwks = async (tenantId, forceRefresh = false) => {
  if (!forceRefresh) {
    const cached = jwksCache.get(tenantId);
    if (cached && cached.expiresAt > Date.now()) return cached.jwks;
  }
  const jwks = await fetchJwksFromNetwork(tenantId);
  jwksCache.set(tenantId, { jwks, expiresAt: Date.now() + JWKS_CACHE_TTL_MS });
  return jwks;
};

// Test hook — clears the JWKS cache. Never call from production code.
const __resetJwksCache = () => jwksCache.clear();

const verifyJwtSignature = async (token, tenantId) => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT format');

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());

    if (header.alg !== 'RS256') {
      throw new Error(`Unsupported algorithm: ${header.alg}. Only RS256 accepted`);
    }

    let jwks = await getJwks(tenantId);
    let key  = jwks.keys.find(k => k.kid === header.kid);
    if (!key) {
      // kid not in the cached set — signing keys may have rotated; refresh once.
      jwks = await getJwks(tenantId, true);
      key  = jwks.keys.find(k => k.kid === header.kid);
    }
    if (!key) throw new Error(`Signing key (kid: ${header.kid}) not found in JWKS`);

    const publicKey      = crypto.createPublicKey({ key, format: 'jwk' });
    const signatureInput = `${parts[0]}.${parts[1]}`;
    const signature      = Buffer.from(parts[2], 'base64url');

    const isValid = crypto.verify('RSA-SHA256', Buffer.from(signatureInput), publicKey, signature);
    if (!isValid) throw new Error('JWT signature verification failed');

    return true;

  } catch (err) {
    // Distinguish a JWKS-retrieval outage (retryable) from an actual token
    // rejection: a transient Microsoft-side failure must not look like a bad
    // signature to the caller.
    if (err.jwksFetchError) {
      const error = new Error(`JWKS unavailable: ${err.message}`);
      error.statusCode = 503;
      error.code = 'JWKS_UNAVAILABLE';
      throw error;
    }
    const error = new Error(`JWT verification error: ${err.message}`);
    error.statusCode = 401;
    error.code = 'JWT_VERIFICATION_FAILED';
    throw error;
  }
};

module.exports = { verifyJwtSignature, __resetJwksCache };
