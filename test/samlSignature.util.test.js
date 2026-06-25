jest.mock('../src/config/logger', () => ({ logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() } }));

const forge = require('node-forge');
const { SignedXml } = require('xml-crypto');
const { verifyXmlSignature } = require('../src/utils/saml/samlSignature.util');

// Generate a self-signed cert + matching private key, then enveloped-sign an XML
// document so the happy path (valid signature → true) is exercised end-to-end.
const makeSignedXml = () => {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter  = new Date(Date.now() + 365 * 24 * 3600 * 1000);
  const attrs = [{ name: 'commonName', value: 'saml-test' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
  const certPem       = forge.pki.certificateToPem(cert);

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
      // Any rejection (raw parse error or a coded SIGNATURE/INVALID error) is fine.
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
