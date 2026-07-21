jest.mock('../src/config/logger', () => ({ logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() } }));

const { execFileSync } = require('child_process');
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { extractFromPkcs12 } = require('../src/utils/oidc/pkcs12.util');

// Build a real PKCS#12 bundle (self-signed) with openssl — the same tool
// pkcs12.util.js uses to extract — so the happy path is exercised end-to-end
// with no node-forge dependency.
const buildP12 = (password) => {
  const dir      = fs.mkdtempSync(path.join(os.tmpdir(), 'p12-'));
  const keyPath  = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');
  const p12Path  = path.join(dir, 'bundle.p12');
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath,
      '-days', '365', '-subj', '/CN=test-cert',
    ], { stdio: 'ignore' });
    execFileSync('openssl', [
      'pkcs12', '-export', '-inkey', keyPath, '-in', certPath,
      '-out', p12Path, '-passout', `pass:${password}`,
    ], { stdio: 'ignore' });
    return fs.readFileSync(p12Path).toString('base64');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

// NOTE: extractFromPkcs12 is ASYNC — it returns a Promise and rejects on error.
// Tests must await and use rejects/resolves; a sync try/catch leaves the rejected
// promise unhandled and crashes the Node process.
describe('pkcs12.util — extractFromPkcs12', () => {
  test('throws MISSING_CERTIFICATE when no bundle provided', async () => {
    await expect(extractFromPkcs12('', 'pw')).rejects.toMatchObject({
      code: 'MISSING_CERTIFICATE',
      statusCode: 400,
    });
  });

  test('throws INVALID_PKCS12 on garbage input', async () => {
    await expect(extractFromPkcs12('not-a-real-pkcs12-bundle!!!', 'pw')).rejects.toMatchObject({
      code: 'INVALID_PKCS12',
      statusCode: 400,
    });
  });

  test('throws INVALID_PKCS12 on wrong password', async () => {
    const p12 = buildP12('correct-password');
    await expect(extractFromPkcs12(p12, 'wrong-password')).rejects.toMatchObject({
      code: 'INVALID_PKCS12',
    });
  });

  test('extracts private key (base64 PEM) and SHA-1 thumbprint (uppercase hex) from a valid bundle', async () => {
    const p12 = buildP12('s3cret');
    const { privateKeyB64, thumbprintHex } = await extractFromPkcs12(p12, 's3cret');

    const pem = Buffer.from(privateKeyB64, 'base64').toString('utf8');
    expect(pem).toMatch(/-----BEGIN (RSA )?PRIVATE KEY-----/);
    expect(pem).toMatch(/-----END (RSA )?PRIVATE KEY-----/);

    expect(thumbprintHex).toMatch(/^[0-9A-F]{40}$/); // SHA-1 = 40 hex chars, uppercase
  });

  test('accepts a data-URL prefixed bundle (FileReader.readAsDataURL output)', async () => {
    const p12 = buildP12('pw');
    const dataUrl = `data:application/x-pkcs12;base64,${p12}`;
    const { privateKeyB64, thumbprintHex } = await extractFromPkcs12(dataUrl, 'pw');
    expect(privateKeyB64).toBeTruthy();
    expect(thumbprintHex).toMatch(/^[0-9A-F]{40}$/);
  });
});
