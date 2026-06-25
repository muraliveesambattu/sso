// const crypto = require('crypto');
// const zlib = require('zlib');

// const generateAuthRequestXml = (config,authnRequestId) => {
//     const issueInstant = new Date().toISOString();
//     return `<samlp:AuthnRequest
//             xmlns:samlp="urn:oasiss:name:tc:SAML:2.0:protocol"
//             xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
//             ID="${authnRequestId}
//             Version = "2.0"
//             IssueInstant ="${issueInstant}"
//             Destination="${config.sso_url}"
//             AssertionConsumerServiceURL="${config.acs_url}"
//             ProtocolBinding = "urn:oasis:name:tc:SAML:2.0:bindings:HTTP-POST">
//             <saml:Issuer>${config.entity_id}</saml:Issuer>
//             <samlp:NameIDPolicy
//                 Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
//                 AllowCreate="true"/>
//             </samlp:AuthnRequest>`;
// };

// const buildSamlRedirecttUrl = (config,session,sessionID) =>
// {
//     return new Promise((resolve,reject)=>
//     {
//         const authnRequestId = `_zdna_${crypto.randomUUID()}`;
//             session[`sso:saml:request:${sessionID}`] = {
//             authnRequestId,
//             timeStamp:Date.now(),
//             ssoContext:{
//                 entity_id:config.entity_id,
//                 acs_url:config.acs_url,
//                 sso_url:config.sso_url,
//             }
//         };

//         const xml = generateAuthRequestXml(config,authnRequestId);
//         zlib.deflateRaw(Buffer.from(xml,'utf-8'),(err,compressed)=>{
//             if(err) return reject(err);

//             const base64 = compressed.toString('base64');
//             const urlEncoded = encodeURIComponent(base64);
//             const relayState = encodeURIComponent(sessionID);
//             const redirectUrl = `${config.sso_url}?SAMLRequest=${urlEncoded}&RelayState=${relayState}`;
//             resolve(redirectUrl);
//         });
//     })
// }

// module.exports = {buildSamlRedirecttUrl};


const crypto = require('crypto');
const { logger } = require('../../config/logger');
const zlib   = require('zlib');
const fs     = require('fs');
const path   = require('path');
const { promisify } = require('util');

const deflateRaw = promisify(zlib.deflateRaw);
const SESSION_TTL_MS = 600000; // 10 minutes

// SP private key for signing AuthnRequest (HTTP-Redirect binding)
// Key is loaded once at startup — avoids repeated disk reads.
// Priority: 1) file on disk  2) SP_CERT_PRIVATE_KEY_B64 env var (base64-encoded PEM)
const SP_PRIVATE_KEY_PATH = path.join(__dirname, '../../../certs/zdna-sso-client.key');
let spPrivateKey = null;
try {
  spPrivateKey = fs.readFileSync(SP_PRIVATE_KEY_PATH, 'utf8');
  logger.debug('[SAML] SP private key loaded from file — AuthnRequest signing enabled');
} catch {
  if (process.env.SP_CERT_PRIVATE_KEY_B64) {
    spPrivateKey = Buffer.from(process.env.SP_CERT_PRIVATE_KEY_B64, 'base64').toString('utf8');
    logger.debug('[SAML] SP private key loaded from SP_CERT_PRIVATE_KEY_B64 env var — AuthnRequest signing enabled');
  } else {
    logger.warn('[SAML] SP private key not found — AuthnRequest will be unsigned');
  }
}

// SigAlg URI for RSA-SHA256
const SIG_ALG = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

/**
 * Signs the SAML AuthnRequest query string (HTTP-Redirect binding).
 *
 * Per SAML spec, the signature covers:
 *   SAMLRequest=...&RelayState=...&SigAlg=...
 * (URL-encoded, in that exact order)
 *
 * The Signature is appended as a final query param.
 */
const signSamlRedirectQuery = (samlRequest, relayState) => {
  if (!spPrivateKey) return null;

  const sigAlgEncoded  = encodeURIComponent(SIG_ALG);
  const stringToSign   = `SAMLRequest=${samlRequest}&RelayState=${relayState}&SigAlg=${sigAlgEncoded}`;
  const signature      = crypto.sign('RSA-SHA256', Buffer.from(stringToSign), spPrivateKey);

  return {
    sigAlg:    sigAlgEncoded,
    signature: encodeURIComponent(signature.toString('base64'))
  };
};

// In-memory store keyed by authnRequestId.
// Avoids reliance on session cookies which are blocked on cross-site SAML POST callbacks (sameSite: lax).
const samlRequestStore = new Map();

const generateAuthnRequestXml = (authnRequestId, entityId, acsUrl, ssoUrl) => {
  const issueInstant = new Date().toISOString();
  // Single line XML - no formatting, no line breaks
  
logger.debug('[XML_GENERATION_PARAMS]', {
    authnRequestId,
    entityId,
    acsUrl,
    ssoUrl,
    entityIdType: typeof entityId,
    acsUrlType: typeof acsUrl,
    ssoUrlType: typeof ssoUrl
  });

  return `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${authnRequestId}" Version="2.0" IssueInstant="${issueInstant}" Destination="${ssoUrl}" AssertionConsumerServiceURL="${acsUrl}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>${entityId}</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>`;
};

const buildSamlRedirectUrl = async (entityId, acsUrl, ssoUrl, session, sessionId) => {
  try {
    // Generate unique AuthnRequest ID
    const authnRequestId = `_zdna_${crypto.randomUUID()}`;
    
    // Generate AuthnRequest XML
    const xml = generateAuthnRequestXml(authnRequestId, entityId, acsUrl, ssoUrl);
    
    logger.debug('[SAML_AUTHN_REQUEST_XML]', xml);
    
    // Store in server-side Map keyed by authnRequestId.
    // Cannot use session cookie here — sameSite:lax blocks cookies on the
    // cross-site POST that Microsoft sends back to the ACS URL.
    samlRequestStore.set(authnRequestId, {
      authnRequestId,
      timestamp: Date.now(),
      ssoContext: {
        entity_id: entityId,
        acs_url: acsUrl
      }
    });

    // Compress with DEFLATE
    const compressed = await deflateRaw(Buffer.from(xml, 'utf-8'));

    // Base64 encode
    const base64Encoded = compressed.toString('base64');

    // URL encode
    const urlEncoded   = encodeURIComponent(base64Encoded);
    const relayState   = encodeURIComponent(authnRequestId);

    // Sign the query string if SP private key is available
    const signed = signSamlRedirectQuery(urlEncoded, relayState);

    // Build final redirect URL
    // Signed:   ?SAMLRequest=...&RelayState=...&SigAlg=...&Signature=...
    // Unsigned: ?SAMLRequest=...&RelayState=...
    const redirectUrl = signed
      ? `${ssoUrl}?SAMLRequest=${urlEncoded}&RelayState=${relayState}&SigAlg=${signed.sigAlg}&Signature=${signed.signature}`
      : `${ssoUrl}?SAMLRequest=${urlEncoded}&RelayState=${relayState}`;

    logger.debug('[SAML_AUTHN_REQUEST_SIGNED]', !!signed);
    
    // Audit log
    logger.debug('[SAML_AUTHN_REQUEST]', JSON.stringify({
      timestamp: new Date().toISOString(),
      authnRequestId,
      sessionId,
      entityId,
      ssoUrl
    }));

    return redirectUrl;
    
  } catch (err) {
    logger.error('[SAML_AUTHN_REQUEST_ERROR]', err);
    const error = new Error('Failed to generate SAML AuthnRequest');
    error.statusCode = 500;
    error.code = 'AUTHN_REQUEST_GENERATION_FAILED';
    throw error;
  }
};

module.exports = { buildSamlRedirectUrl, samlRequestStore };
