jest.mock('../src/config/logger', () => ({ logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() } }));

const { execFileSync } = require('child_process');
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { SignedXml } = require('xml-crypto');
const { verifyXmlSignature } = require('../src/utils/saml/samlSignature.util');

// Generate a self-signed cert + matching private key with openssl (no node-forge).
const makeKeyAndCert = () => {
  const dir      = fs.mkdtempSync(path.join(os.tmpdir(), 'saml-'));
  const keyPath  = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
      '-keyout', keyPath, '-out', certPath,
      '-days', '365', '-subj', '/CN=saml-test',
    ], { stdio: 'ignore' });
    return {
      privateKeyPem: fs.readFileSync(keyPath, 'utf8'),
      certPem:       fs.readFileSync(certPath, 'utf8'),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

// Enveloped-sign an XML document with xml-crypto so the happy path
// (valid signature → true) is exercised end-to-end.
const makeSignedXml = () => {
  const { privateKeyPem, certPem } = makeKeyAndCert();

  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp1"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">ok</saml:Assertion></samlp:Response>`;

  const sig = new SignedXml({ privateKey: privateKeyPem });
  sig.signatureAlgorithm     = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  sig.addReference({
    xpath: "//*[local-name(.)='Response']",
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  sig.computeSignature(xml, { location: { reference: "//*[local-name(.)='Response']", action: 'append' } });

  return { signedXml: sig.getSignedXml(), certPem };
};

// A minimal cert body (PEM-less base64) — enough to drive formatCertAsPem; the
// signature itself is invalid, so verification must reject (that's the point:
// unsigned/forged assertions are never accepted).
const DUMMY_CERT_B64 = 'MIIBdummycertbodybase64AAAA';

const xmlNoSig = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">data</saml:Assertion></samlp:Response>`;
const xmlWithFakeSig = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo></SignedInfo><SignatureValue>AAAA</SignatureValue></Signature></samlp:Response>`;

describe('samlSignature.util — verifyXmlSignature', () => {
  test('throws INVALID_XML_INPUT for empty / non-string xml', () => {
    for (const bad of ['', '   ', null, undefined, 123]) {
      try { verifyXmlSignature(bad, DUMMY_CERT_B64); throw new Error('no throw'); }
      catch (e) { expect(e.code).toBe('INVALID_XML_INPUT'); expect(e.statusCode).toBe(400); }
    }
  });

  test('throws MISSING_CERTIFICATE when certificate not provided', () => {
    try { verifyXmlSignature(xmlNoSig, null); throw new Error('no throw'); }
    catch (e) { expect(e.code).toBe('MISSING_CERTIFICATE'); expect(e.statusCode).toBe(400); }
  });

  test('throws MISSING_SIGNATURE when the assertion is unsigned (security: reject unsigned)', () => {
    try { verifyXmlSignature(xmlNoSig, DUMMY_CERT_B64); throw new Error('no throw'); }
    catch (e) { expect(e.code).toBe('MISSING_SIGNATURE'); expect(e.statusCode).toBe(400); }
  });

  test('never accepts an invalid/forged signature (throws or returns non-true)', () => {
    // Security property: a forged/invalid signature must NOT verify as true.
    let accepted = false;
    try {
      accepted = verifyXmlSignature(xmlWithFakeSig, DUMMY_CERT_B64) === true;
    } catch (e) {
      // Any rejection (raw parse error or a coded SIGNATURE/INVALID error) is fine —
      // what matters is that a forged signature does NOT verify as true.
      expect(e).toBeInstanceOf(Error);
      accepted = false;
    }
    expect(accepted).toBe(false);
  });

  test('returns true for a correctly signed assertion (happy path)', () => {
    const { signedXml, certPem } = makeSignedXml();
    expect(verifyXmlSignature(signedXml, certPem)).toBe(true);
  });

  test('rejects a signed assertion when verified with a DIFFERENT cert', () => {
    const { signedXml } = makeSignedXml();
    const { certPem: otherCert } = makeSignedXml(); // unrelated key/cert
    let accepted = false;
    try { accepted = verifyXmlSignature(signedXml, otherCert) === true; } catch { accepted = false; }
    expect(accepted).toBe(false);
  });
});
