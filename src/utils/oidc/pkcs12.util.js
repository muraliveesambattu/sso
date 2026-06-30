/**
 * PKCS#12 (.pfx / .p12) Utility
 *
 * Extracts the private key and certificate thumbprint from a password-protected
 * PKCS#12 bundle — used for the OIDC `private_key_jwt` (Client Certificate) auth
 * method. The extracted pieces feed generateJwtAssertion():
 *   - private key  → stored as base64(PEM) in oidc_configurations.private_key_enc
 *   - thumbprint   → SHA-1 hex, stored in oidc_configurations.client_cert_thumbprint
 *                    (generateJwtAssertion converts it to base64url x5t)
 */

const forge      = require('node-forge');
const { logger } = require('../../config/logger');

/**
 * Parse a base64-encoded .pfx/.p12 and extract the client cert material.
 *
 * @param {string} base64Pfx  - base64-encoded PKCS#12 bundle
 * @param {string} password   - password protecting the bundle
 * @returns {{ privateKeyB64: string, thumbprintHex: string }}
 * @throws  {Error} statusCode 400 if the bundle/password is invalid
 */
const extractFromPkcs12 = async (base64Pfx, password) => {
  if (!base64Pfx) {
    throw Object.assign(new Error('certificate (.pfx/.p12) is required for private_key_jwt'), {
      statusCode: 400, code: 'MISSING_CERTIFICATE',
    });
  }

  // Accept either pure base64 or a data-URL ("data:...;base64,XXXX") — the
  // frontend's FileReader.readAsDataURL produces the latter. Strip the prefix.
  const pureB64 = base64Pfx.includes(',') ? base64Pfx.slice(base64Pfx.indexOf(',') + 1) : base64Pfx;

  // Yield the event loop before CPU-bound forge operations so concurrent
  // requests are not stalled for the duration of PKCS#12 parsing and crypto.
  await new Promise(resolve => setImmediate(resolve));

  let p12;
  try {
    const der  = forge.util.decode64(pureB64);
    const asn1 = forge.asn1.fromDer(der);
    p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password || '');
  } catch (err) {
    logger.error('extractFromPkcs12: failed to parse PKCS#12 bundle', {
      action: 'pkcs12_parse_failed', error: err.message, code: 'INVALID_PKCS12',
    });
    throw Object.assign(new Error('Invalid certificate or password — could not open the PKCS#12 bundle'), {
      statusCode: 400, code: 'INVALID_PKCS12', cause: err,
    });
  }

  // ── Private key ──────────────────────────────────────────────────────────────
  const keyBags =
    p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] ||
    p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] ||
    [];
  const keyBag = keyBags[0];
  if (!keyBag || !keyBag.key) {
    throw Object.assign(new Error('No private key found in the certificate bundle'), {
      statusCode: 400, code: 'NO_PRIVATE_KEY',
    });
  }
  const privateKeyPem = forge.pki.privateKeyToPem(keyBag.key);
  const privateKeyB64 = Buffer.from(privateKeyPem, 'utf8').toString('base64');

  // ── Certificate + SHA-1 thumbprint ───────────────────────────────────────────
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const certBag  = certBags[0];
  if (!certBag || !certBag.cert) {
    throw Object.assign(new Error('No certificate found in the bundle'), {
      statusCode: 400, code: 'NO_CERTIFICATE',
    });
  }
  // SHA-1 over the DER-encoded certificate = the Azure-registered thumbprint
  const certDer       = forge.asn1.toDer(forge.pki.certificateToAsn1(certBag.cert)).getBytes();
  const thumbprintHex = forge.md.sha1.create().update(certDer).digest().toHex().toUpperCase();

  return { privateKeyB64, thumbprintHex };
};

module.exports = { extractFromPkcs12 };
