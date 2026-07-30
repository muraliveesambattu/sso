const { DOMParser } = require('@xmldom/xmldom');
const { SignedXml }  = require('xml-crypto');
const { logger }     = require('../../config/logger');

const formatCertAsPem = (cert) => {
  let certStr = (cert || '').trim();

  // Strip a data-URL prefix if present (data:...;base64,XXXX).
  if (certStr.includes(',') && certStr.startsWith('data:')) {
    certStr = certStr.slice(certStr.indexOf(',') + 1);
  }

  // Case 1: the stored value is base64 of the whole PEM file (the frontend's
  // FileReader.readAsDataURL of a .cer produces base64 of "-----BEGIN CERT...").
  // Decoding it yields the real PEM — use that directly. (Without this the PEM
  // body ends up being base64-of-PEM, and OpenSSL throws ERR_OSSL_ASN1_WRONG_TAG.)
  try {
    const decoded = Buffer.from(certStr, 'base64').toString('utf-8');
    if (decoded.includes('-----BEGIN CERTIFICATE-----')) {
      return decoded.trim();
    }
  } catch (e) {
    // Not base64 — fall through to Case 2 / Case 3 (do NOT throw)
    logger.debug('formatCertAsPem: base64 decode skipped', { error: e.message });
  }

  // Case 2: already a PEM string.
  if (certStr.includes('-----BEGIN CERTIFICATE-----')) {
    return certStr;
  }

  // Case 3: raw base64 DER (just the body) — wrap it in PEM headers.
  const clean = certStr.replaceAll(/\s/g, '');
  return `-----BEGIN CERTIFICATE-----\n${clean.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
};

const verifyXmlSignature = (xml, certificate) => {
  if (!xml || typeof xml !== 'string' || xml.trim().length === 0) {
    const err = new Error('XML payload is required and must be a non-empty string');
    err.statusCode = 400;
    err.code = 'INVALID_XML_INPUT';
    throw err;
  }
  if (!certificate || typeof certificate !== 'string') {
    const err = new Error('Certificate is required and must be a string');
    err.statusCode = 400;
    err.code = 'MISSING_CERTIFICATE';
    throw err;
  }

  const doc = new DOMParser().parseFromString(xml, 'text/xml');

  const signature = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];

  if (!signature) {
    const err = new Error('No XML signature found - unsigned assertion rejected');
    err.statusCode = 400;                  // was: err.statuscode (ignored → 500)
    err.code = 'MISSING_SIGNATURE';
    throw err;
  }

  const signedXml = new SignedXml({ publicCert: formatCertAsPem(certificate) });
  signedXml.loadSignature(signature);

  let isValid;
  try {
    isValid = signedXml.checkSignature(xml);
  } catch (error) {
    const err = new Error(`XML signature verification failed: ${error.message}`);
    err.statusCode = 400;
    err.code = 'SIGNATURE_VERIFICATION_ERROR';
    err.cause = error;
    throw err;
  }

  if (!isValid) {
    const err = new Error('XML signature verification failed');
    err.statusCode = 401;                  // was: err.statuscode (ignored → 500)
    err.code = 'INVALID_SIGNATURE';
    throw err;
  }

  return true;
};

module.exports = { verifyXmlSignature };
