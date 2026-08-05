jest.mock('../src/config/logger', () => ({ logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() } }));

const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs     = require('node:fs');
const os     = require('node:os');
const path   = require('node:path');

const { extractFromPkcs12 } = require('../src/utils/oidc/pkcs12.util');

// The implementation shells out to the openssl CLI, so the bundle is built the
// same way rather than with a third-party library. (node-forge was dropped when
// pkcs12.util was rewritten — the previous version of this suite still required
// it and had been failing to load ever since, which is how a thumbprint bug
// reached production unnoticed.)
//
// NOTE: extractFromPkcs12 is ASYNC — it returns a Promise and rejects on error.
// Tests must await and use rejects/resolves; a sync try/catch leaves the
// rejected promise unhandled and crashes the Node process.
const PASSWORD = 'TestPass123!';

let pfxBase64;
let trueThumbprint;
let tmpDir;

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pkcs12-test-'));
  const key = path.join(tmpDir, 't.key');
  const cer = path.join(tmpDir, 't.cer');
  const pfx = path.join(tmpDir, 't.pfx');

  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '2', '-nodes',
    '-keyout', key, '-out', cer, '-subj', '/CN=pkcs12-util-test',
  ], { stdio: 'ignore' });

  execFileSync('openssl', [
    'pkcs12', '-export', '-inkey', key, '-in', cer, '-out', pfx,
    '-passout', `pass:${PASSWORD}`,
    // Modern algorithms — OpenSSL 3 rejects legacy RC2/3DES bundles without -legacy
    '-keypbe', 'AES-256-CBC', '-certpbe', 'AES-256-CBC', '-macalg', 'SHA256',
  ], { stdio: 'ignore' });

  pfxBase64 = fs.readFileSync(pfx).toString('base64');

  // The authoritative value, straight from openssl: SHA-1 over the cert DER.
  trueThumbprint = execFileSync('openssl', ['x509', '-in', cer, '-noout', '-fingerprint', '-sha1'])
    .toString()
    .split('=')[1]
    .replaceAll(':', '')
    .trim()
    .toUpperCase();
});

afterAll(() => {
  if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('pkcs12.util — input validation', () => {
  test('throws MISSING_CERTIFICATE when no bundle is provided', async () => {
    await expect(extractFromPkcs12(null, PASSWORD)).rejects.toMatchObject({
      statusCode: 400, code: 'MISSING_CERTIFICATE',
    });
    await expect(extractFromPkcs12('', PASSWORD)).rejects.toMatchObject({
      code: 'MISSING_CERTIFICATE',
    });
  });

  test('throws INVALID_PKCS12 on garbage input', async () => {
    await expect(extractFromPkcs12(Buffer.from('not a pfx').toString('base64'), PASSWORD))
      .rejects.toMatchObject({ statusCode: 400, code: 'INVALID_PKCS12' });
  });

  test('throws INVALID_PKCS12 on the wrong password', async () => {
    await expect(extractFromPkcs12(pfxBase64, 'WrongPassword'))
      .rejects.toMatchObject({ statusCode: 400, code: 'INVALID_PKCS12' });
  });
});

describe('pkcs12.util — extraction', () => {
  // REGRESSION: openssl prefixes each PEM block with a "Bag Attributes /
  // localKeyID / subject= / issuer=" preamble. An earlier implementation
  // filtered only lines starting with '-----', so those preamble lines were
  // base64-decoded as part of the DER and the SHA-1 covered the wrong bytes.
  // Entra rejected the resulting x5t with AADSTS700027.
  test('the thumbprint matches openssl x509 -fingerprint -sha1 exactly', async () => {
    const { thumbprintHex } = await extractFromPkcs12(pfxBase64, PASSWORD);
    expect(thumbprintHex).toBe(trueThumbprint);
  });

  test('the thumbprint is uppercase hex of the expected length', async () => {
    const { thumbprintHex } = await extractFromPkcs12(pfxBase64, PASSWORD);
    expect(thumbprintHex).toMatch(/^[0-9A-F]{40}$/); // SHA-1 = 20 bytes
  });

  test('the private key is a clean PEM with no Bag Attributes preamble', async () => {
    const { privateKeyB64 } = await extractFromPkcs12(pfxBase64, PASSWORD);
    const pem = Buffer.from(privateKeyB64, 'base64').toString('utf8');

    expect(pem.startsWith('-----BEGIN')).toBe(true);
    expect(pem).not.toContain('Bag Attributes');
    expect(pem).not.toContain('localKeyID');
    expect(pem.trimEnd().endsWith('-----')).toBe(true);
  });

  test('the extracted key can actually sign — the point of the whole flow', async () => {
    const { privateKeyB64 } = await extractFromPkcs12(pfxBase64, PASSWORD);
    const pem = Buffer.from(privateKeyB64, 'base64').toString('utf8');

    const signature = crypto.sign('RSA-SHA256', Buffer.from('assertion'), crypto.createPrivateKey(pem));
    expect(signature).toHaveLength(256); // RSA-2048
  });

  test('accepts a data-URL prefixed bundle (FileReader.readAsDataURL output)', async () => {
    const dataUrl = `data:application/x-pkcs12;base64,${pfxBase64}`;
    const { thumbprintHex } = await extractFromPkcs12(dataUrl, PASSWORD);
    expect(thumbprintHex).toBe(trueThumbprint);
  });

  test('is deterministic across calls', async () => {
    const a = await extractFromPkcs12(pfxBase64, PASSWORD);
    const b = await extractFromPkcs12(pfxBase64, PASSWORD);
    expect(a.thumbprintHex).toBe(b.thumbprintHex);
    expect(a.privateKeyB64).toBe(b.privateKeyB64);
  });
});
