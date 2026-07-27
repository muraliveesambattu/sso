/**
 * PKCS#12 (.pfx / .p12) Utility
 *
 * Extracts the private key and certificate thumbprint from a password-protected
 * PKCS#12 bundle — used for the OIDC `private_key_jwt` (Client Certificate) auth
 * method. The extracted pieces feed generateJwtAssertion():
 *   - private key  → stored as base64(PEM) in oidc_configurations.private_key_enc
 *   - thumbprint   → SHA-1 hex, stored in oidc_configurations.client_cert_thumbprint
 *                    (generateJwtAssertion converts it to base64url x5t)
 *
 * Uses openssl CLI + Node.js built-in crypto — no third-party libraries required.
 * openssl is guaranteed available on Linux/Cloud Run environments.
 */

const { spawn }  = require('node:child_process');
const crypto     = require('node:crypto');
const { logger } = require('../../config/logger');

// Hard cap so a wedged openssl can never hang a request (it reads the bundle
// from stdin — if that pipe were ever left open, openssl would block forever).
const OPENSSL_TIMEOUT_MS = 10000;

/**
 * Spawn openssl with the PKCS#12 buffer on stdin.
 * Password is passed via a unique env var to avoid exposure in the process list.
 *
 * NOTE: async execFile has no `input` option (only the *Sync variants / spawn do),
 * so we must spawn and write the buffer to stdin ourselves, then end() it — or
 * openssl blocks forever waiting on stdin.
 *
 * @param {string[]} args      - openssl arguments
 * @param {Buffer}   input     - PKCS#12 binary data
 * @param {string}   passKey   - env var name holding the password
 * @param {string}   password  - the password value
 * @returns {Promise<string>}  - stdout from openssl
 */
const runOpenssl = (args, input, passKey, password) =>
  new Promise((resolve, reject) => {
    const env   = { ...process.env, [passKey]: password };
    const child = spawn('openssl', args, { env });

    let stdout = '';
    let stderr = '';

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(Object.assign(new Error('openssl timed out'), { code: 'OPENSSL_TIMEOUT' }));
    }, OPENSSL_TIMEOUT_MS);

    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });

    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('close', (exitCode) => {
      clearTimeout(timer);
      if (exitCode === 0) resolve(stdout);
      else reject(Object.assign(new Error(stderr.trim() || `openssl exited with code ${exitCode}`), { code: 'OPENSSL_ERROR' }));
    });

    // openssl may exit before consuming all of stdin (e.g. garbage input) →
    // swallow the resulting EPIPE instead of crashing the process.
    child.stdin.on('error', () => {});
    child.stdin.write(input);
    child.stdin.end();
  });

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
  const pureB64   = base64Pfx.includes(',') ? base64Pfx.slice(base64Pfx.indexOf(',') + 1) : base64Pfx;
  const pfxBuffer = Buffer.from(pureB64, 'base64');

  // Unique env var name per invocation — prevents password leakage between
  // concurrent requests sharing the same process environment snapshot.
  const passKey = `PFX_PASS_${crypto.randomUUID().replaceAll(/-/g, '')}`;
  const pass    = password || '';

  // ── Private key ──────────────────────────────────────────────────────────────
  let keyPem;
  try {
    keyPem = await runOpenssl(
      ['pkcs12', '-nocerts', '-nodes', '-passin', `env:${passKey}`],
      pfxBuffer, passKey, pass,
    );
  } catch (err) {
    logger.error('extractFromPkcs12: failed to extract private key', {
      action: 'pkcs12_parse_failed', error: err.message, code: 'INVALID_PKCS12',
    });
    throw Object.assign(new Error('Invalid certificate or password — could not open the PKCS#12 bundle'), {
      statusCode: 400, code: 'INVALID_PKCS12', cause: err,
    });
  }

  if (!keyPem || !keyPem.includes('PRIVATE KEY')) {
    throw Object.assign(new Error('No private key found in the certificate bundle'), {
      statusCode: 400, code: 'NO_PRIVATE_KEY',
    });
  }

  // ── Certificate ──────────────────────────────────────────────────────────────
  let certPem;
  try {
    certPem = await runOpenssl(
      ['pkcs12', '-nokeys', '-clcerts', '-passin', `env:${passKey}`],
      pfxBuffer, passKey, pass,
    );
  } catch (err) {
    throw Object.assign(new Error('No certificate found in the bundle'), {
      statusCode: 400, code: 'NO_CERTIFICATE', cause: err,
    });
  }

  if (!certPem || !certPem.includes('CERTIFICATE')) {
    throw Object.assign(new Error('No certificate found in the bundle'), {
      statusCode: 400, code: 'NO_CERTIFICATE',
    });
  }

  // ── SHA-1 thumbprint (pure Node.js crypto) ───────────────────────────────────
  // Strip PEM headers → base64-decode to DER → SHA-1
  const certBase64 = certPem
    .split('\n')
    .filter(line => !line.startsWith('-----') && line.trim())
    .join('');
  const certDer       = Buffer.from(certBase64, 'base64');
  const thumbprintHex = crypto.createHash('sha1').update(certDer).digest('hex').toUpperCase();

  return {
    privateKeyB64: Buffer.from(keyPem, 'utf8').toString('base64'),
    thumbprintHex,
  };
};

module.exports = { extractFromPkcs12 };
