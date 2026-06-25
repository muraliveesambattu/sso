jest.mock('../src/config/logger', () => ({ logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() } }));

const forge = require('node-forge');
const { extractFromPkcs12 } = require('../src/utils/oidc/pkcs12.util');

// Build a real PKCS#12 bundle (self-signed) so the happy path is exercised end-to-end.
const buildP12 = (password) => {
  const keys = forge.pki.rsa.generateKeyPair(1024); // 1024 = fast enough for tests
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter  = new Date(Date.now() + 365 * 24 * 3600 * 1000);
  const attrs = [{ name: 'commonName', value: 'test-cert' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey);

  const asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], password, { algorithm: '3des' });
  const der  = forge.asn1.toDer(asn1).getBytes();
  return forge.util.encode64(der);
};

describe('pkcs12.util — extractFromPkcs12', () => {
  test('throws MISSING_CERTIFICATE when no bundle provided', () => {
    try { extractFromPkcs12('', 'pw'); throw new Error('no throw'); }
    catch (e) { expect(e.code).toBe('MISSING_CERTIFICATE'); expect(e.statusCode).toBe(400); }
  });

  test('throws INVALID_PKCS12 on garbage input', () => {
    try { extractFromPkcs12('not-a-real-pkcs12-bundle!!!', 'pw'); throw new Error('no throw'); }
    catch (e) { expect(e.code).toBe('INVALID_PKCS12'); expect(e.statusCode).toBe(400); }
  });

  test('throws INVALID_PKCS12 on wrong password', () => {
    const p12 = buildP12('correct-password');
    try { extractFromPkcs12(p12, 'wrong-password'); throw new Error('no throw'); }
    catch (e) { expect(e.code).toBe('INVALID_PKCS12'); }
  });

  test('extracts private key (base64 PEM) and SHA-1 thumbprint (uppercase hex) from a valid bundle', () => {
    const p12 = buildP12('s3cret');
    const { privateKeyB64, thumbprintHex } = extractFromPkcs12(p12, 's3cret');

    const pem = Buffer.from(privateKeyB64, 'base64').toString('utf8');
    expect(pem).toMatch(/-----BEGIN (RSA )?PRIVATE KEY-----/);
    expect(pem).toMatch(/-----END (RSA )?PRIVATE KEY-----/);

    expect(thumbprintHex).toMatch(/^[0-9A-F]{40}$/); // SHA-1 = 40 hex chars, uppercase
  });

  test('accepts a data-URL prefixed bundle (FileReader.readAsDataURL output)', () => {
    const p12 = buildP12('pw');
    const dataUrl = `data:application/x-pkcs12;base64,${p12}`;
    const { privateKeyB64, thumbprintHex } = extractFromPkcs12(dataUrl, 'pw');
    expect(privateKeyB64).toBeTruthy();
    expect(thumbprintHex).toMatch(/^[0-9A-F]{40}$/);
  });
});
