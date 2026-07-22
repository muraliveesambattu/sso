const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const { logger } = require('../../config/logger');
const { getSamlConfig } = require('../db/ssoDataService');
const { verifyXmlSignature }   = require('../../utils/saml/samlSignature.util');
const { samlRequestStore }     = require('./samlAuthRequest.service');
const { resolveUser }          = require('../SSO/userResolution.service');
const { resolvePermissions }   = require('../SSO/permissionResolver.service');
const { generateCustomToken, getTenantFriendlyId }  = require('../../utils/firebase/firebaseAdmin.util');
const {
  validateStatus,
  validateIssuer,
  validateInResponseTo,
  validateConditions,
  validateAudience,
} = require('../../utils/saml/samlValidator.util');

const SESSION_TTL_MS = 600000;

// Extract ALL SAML attributes dynamically (no hardcoding)
const extractAllAttributes = (assertion) => {
  const result = {};
  
  // Extract NameID
  const nameId = assertion.getElementsByTagNameNS(
    'urn:oasis:names:tc:SAML:2.0:assertion', 'NameID'
  )[0];
  
  if (nameId) {
    result.nameId = {
      value: nameId.textContent.trim(),
      format: nameId.getAttribute('Format')
    };
  }

  // Extract ALL AttributeStatement attributes
  const attrStatements = assertion.getElementsByTagNameNS(
    'urn:oasis:names:tc:SAML:2.0:assertion', 'AttributeStatement'
  );

  if (attrStatements.length > 0) {
    const attrs = attrStatements[0].getElementsByTagNameNS(
      'urn:oasis:names:tc:SAML:2.0:assertion', 'Attribute'
    );

    for (const attr of Array.from(attrs)) {
      const attrName = attr.getAttribute('Name');
      const attrFriendlyName = attr.getAttribute('FriendlyName');

      const values = attr.getElementsByTagNameNS(
        'urn:oasis:names:tc:SAML:2.0:assertion', 'AttributeValue'
      );

      let attrValue;
      if (values.length === 0) {
        attrValue = null;
      } else if (values.length === 1) {
        attrValue = values[0].textContent.trim();
      } else {
        attrValue = Array.from(values, v => v.textContent.trim());
      }

      // Store with both full URI and friendly name (if available)
      result[attrName] = attrValue;
      if (attrFriendlyName) {
        result[attrFriendlyName] = attrValue;
      }
    }
  }

  return result;
};

// Extract Subject details
const extractSubject = (assertion) => {
  const subject = assertion.getElementsByTagNameNS(
    'urn:oasis:names:tc:SAML:2.0:assertion', 'Subject'
  )[0];
  
  if (!subject) return null;

  const nameId = subject.getElementsByTagNameNS(
    'urn:oasis:names:tc:SAML:2.0:assertion', 'NameID'
  )[0];
  
  const subjectConfirmation = subject.getElementsByTagNameNS(
    'urn:oasis:names:tc:SAML:2.0:assertion', 'SubjectConfirmation'
  )[0];

  const subjectConfirmationData = subjectConfirmation?.getElementsByTagNameNS(
    'urn:oasis:names:tc:SAML:2.0:assertion', 'SubjectConfirmationData'
  )[0];

  return {
    nameId: nameId?.textContent.trim() || null,
    nameIdFormat: nameId?.getAttribute('Format') || null,
    confirmationMethod: subjectConfirmation?.getAttribute('Method') || null,
    recipient: subjectConfirmationData?.getAttribute('Recipient') || null,
    notOnOrAfter: subjectConfirmationData?.getAttribute('NotOnOrAfter') || null,
    inResponseTo: subjectConfirmationData?.getAttribute('InResponseTo') || null
  };
};

const processSamlCallback = async (samlResponse, relayState, session, clientIp) => {
  const startTime = Date.now();

  // LAYER 1: Decode SAMLResponse first to extract InResponseTo
  // (session cookie unavailable — sameSite:lax blocks cookies on cross-site POST from Entra)
  let xml;
  try {
    xml = Buffer.from(samlResponse, 'base64').toString('utf-8');
  } catch (decodeErr) {
    const err = new Error('Invalid SAMLResponse encoding');
    err.statusCode = 400;
    err.code = 'INVALID_ENCODING';
    err.cause = decodeErr;
    throw err;
  }

  // LAYER 2: Parse XML to get InResponseTo
  const docForId = new DOMParser().parseFromString(xml, 'text/xml');
  const responseEl = docForId.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'Response')[0];
  const authnRequestId = responseEl?.getAttribute('InResponseTo');

  if (!authnRequestId) {
    const err = new Error('Missing InResponseTo in SAMLResponse');
    err.statusCode = 400;
    err.code = 'MISSING_IN_RESPONSE_TO';
    throw err;
  }

  // LAYER 3: Look up stored request from server-side Map
  const storedSession = samlRequestStore.get(authnRequestId);

  if (!storedSession) {
    const err = new Error('Session expired or invalid. Please try again.');
    err.statusCode = 401;
    err.code = 'SESSION_NOT_FOUND';
    throw err;
  }

  // LAYER 4: TTL Check
  const sessionAge = Date.now() - storedSession.timestamp;
  if (sessionAge > SESSION_TTL_MS) {
    samlRequestStore.delete(authnRequestId);
    const err = new Error('Session expired. Please try again.');
    err.statusCode = 401;
    err.code = 'SESSION_EXPIRED';
    throw err;
  }

  const { ssoContext } = storedSession;

  // LAYER 6: Retrieve Certificate from the SSO store (NEVER expose to client)
  const samlConfig = await getSamlConfig(ssoContext.company_id);

  if (!samlConfig) {
    const err = new Error('SAML configuration not found');
    err.statusCode = 500;
    err.code = 'CONFIG_NOT_FOUND';
    throw err;
  }

  const entraTenantId = samlConfig.sso_url
    .split('microsoftonline.com/')[1]
    .split('/')[0];

  // LAYER 7: Reuse the document already parsed in Layer 2 — parsing the same
  // XML twice duplicates CPU-bound work on every SAML callback.
  const doc = docForId;

  const parserError = doc.getElementsByTagName('parsererror')[0];
  if (parserError) {
    const err = new Error('Invalid SAML XML structure');
    err.statusCode = 400;
    err.code = 'INVALID_XML';
    throw err;
  }

  // LAYER 6: Semantic Validations
  validateStatus(doc);
  validateIssuer(doc, entraTenantId);
  validateInResponseTo(doc, authnRequestId);

  // LAYER 7: Outer Response Signature
  verifyXmlSignature(xml, samlConfig.certificate);

  // LAYER 8: Extract Assertion
  const assertion = doc.getElementsByTagNameNS(
    'urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion'
  )[0];
  
  if (!assertion) {
    const err = new Error('Missing Assertion element');
    err.statusCode = 400;
    err.code = 'MISSING_ASSERTION';
    throw err;
  }

  // LAYER 9: Inner Assertion Signature
  const assertionXml = new XMLSerializer().serializeToString(assertion);
  verifyXmlSignature(assertionXml, samlConfig.certificate);

  // LAYER 10: Time-based Conditions
  validateConditions(assertion);

  // LAYER 11: Audience Restriction
  validateAudience(assertion, ssoContext.entity_id);

  // LAYER 12: Extract ALL Data Dynamically
  const allAttributes = extractAllAttributes(assertion);
  const subject = extractSubject(assertion);

  // LAYER 13: Validate Required Claims (flexible lookup)
  const email = allAttributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] 
    || allAttributes.emailaddress
    || allAttributes.email
    || allAttributes.nameId?.value
    || subject?.nameId;

  const oid = allAttributes['http://schemas.microsoft.com/identity/claims/objectidentifier']
    || allAttributes.objectidentifier
    || allAttributes.oid;

  if (!oid) {
    const err = new Error('Missing required claim: objectidentifier');
    err.statusCode = 400;
    err.code = 'MISSING_OID';
    throw err;
  }

  if (!email) {
    const err = new Error('Missing required claim: email');
    err.statusCode = 400;
    err.code = 'MISSING_EMAIL';
    throw err;
  }

  // LAYER 14: Delete from store (single-use)
  samlRequestStore.delete(authnRequestId);

  const processingTime = Date.now() - startTime;

  // LAYER 15: Audit trace — pass structured fields (NOT a JSON.stringify'd
  // string) so the logger's field-level PII masking (email/oid/tenantId) applies
  // and Cloud Logging can query them. The durable audit record is written
  // separately via audit.service.writeAuditLog.
  logger.debug('[SAML_LOGIN_SUCCESS]', {
    action: 'saml_login_success',
    oid,
    email,
    tenantId: allAttributes['http://schemas.microsoft.com/identity/claims/tenantid'] || allAttributes.tenantid,
    clientIp,
    processingTimeMs: processingTime,
    sessionAge,
    protocol: 'saml',
  });

  // LAYER 16: User Resolution (JIT or non-JIT)
  const resolution = await resolveUser(samlConfig.company_id, allAttributes, 'saml');

  // LAYER 17: Generate Firebase Custom Token
  // Use ZDNA user_id as Firebase UID
  const zdnaTenantId = resolution.user.user_id;
  logger.debug(`[SAML] Generating Firebase Custom Token | uid: ${zdnaTenantId} | email: ${email}`);

  // Resolve permissions (RMS when configured, else zdna_roles)
  const resolvedPerms = await resolvePermissions(resolution.roles, resolution.user);

  // Mirror the native login's "Company ID" alias for SSO parity.
  const friendlyId = await getTenantFriendlyId(samlConfig.company_id);

  const customToken = await generateCustomToken(zdnaTenantId, {
    email:       email,
    role:        resolution.roles[0]?.role_name || 'user',
    roles:       resolution.roles,
    permissions: resolvedPerms.permissions,
    companyId:   samlConfig.company_id,
    friendlyId,
    displayName: allAttributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']
                 || allAttributes.name
                 || allAttributes.displayname
                 || '',
  });

  logger.debug(`[SAML] Firebase Custom Token generated | uid: ${zdnaTenantId}`);

  // LAYER 18: Return customToken + session metadata
  return {
    customToken,
    user:       resolution.user,
    roles:      resolution.roles,
    userAction: resolution.action,
    session: {
      protocol:        'saml',
      processingTimeMs: processingTime,
      sessionAge:       sessionAge,
      validatedAt:      new Date().toISOString()
    }
  };
};

module.exports = { processSamlCallback };
