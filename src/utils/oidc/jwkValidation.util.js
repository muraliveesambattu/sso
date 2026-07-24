
/**
 * Fetches Microsoft Entra's public JWKS keys and verifies the RS256
 * signature of a JWT (id_token or access_token).
 *
 * Only RS256 is accepted — rejects alg=none and HS256 attacks.
 *
 * Production note: Cache JWKS keys with ~1hr TTL to avoid hitting
 * Entra on every request. Keys rotate infrequently.
 */

const https  = require('https');
const crypto = require('crypto');
const { microsoft } = require('../../config/constants');

const JWKS_TIMEOUT_MS = 10000;

const fetchJwks = (tenantId) => {
  return new Promise((resolve, reject) => {
    const url = microsoft.jwksUrl(tenantId);

    const options = {
      rejectUnauthorized: true,
      timeout: JWKS_TIMEOUT_MS,
    };

    const req = https.get(url, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode === 200) resolve(JSON.parse(data));
          else reject(new Error(`JWKS fetch failed: HTTP ${res.statusCode}`));
        } catch (err) {
          reject(new Error(`Failed to parse JWKS response: ${err.message}`));
        }
      });
    });
    req.on('error', err => reject(new Error(`JWKS network error: ${err.message}`)));
    req.on('timeout', () => { req.destroy(); reject(new Error('JWKS fetch timed out')); });
  });
};

const verifyJwtSignature = async (token, tenantId) => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT format');

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());

    if (header.alg !== 'RS256') {
      throw new Error(`Unsupported algorithm: ${header.alg}. Only RS256 accepted`);
    }

    const jwks = await fetchJwks(tenantId);
    const key  = jwks.keys.find(k => k.kid === header.kid);
    if (!key) throw new Error(`Signing key (kid: ${header.kid}) not found in JWKS`);

    const publicKey      = crypto.createPublicKey({ key, format: 'jwk' });
    const signatureInput = `${parts[0]}.${parts[1]}`;
    const signature      = Buffer.from(parts[2], 'base64url');

    const isValid = crypto.verify('RSA-SHA256', Buffer.from(signatureInput), publicKey, signature);
    if (!isValid) throw new Error('JWT signature verification failed');

    return true;

  } catch (err) {
    const error = new Error(`JWT verification error: ${err.message}`);
    error.statusCode = 401;
    error.code = 'JWT_VERIFICATION_FAILED';
    throw error;
  }
};

module.exports = { verifyJwtSignature };
