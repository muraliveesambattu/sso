const CLOCK_SKEW_SECONDS = 60;
const { microsoft } = require('../../config/constants');

const validateStatus = (doc) => {
    const statusCode = doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'StatusCode')[0];
    if (statusCode?.getAttribute('Value') !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
        const err = new Error('Authentication failed at Identity Provider');
        err.statusCode = 401;
        err.code = 'AUTHENTICATION_FAILED';
        throw err;
    }
}

const validateIssuer = (doc,entra_tenant_id) => {
    const issuer = doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion','Issuer')[0];
    const expected = microsoft.samlIssuer(entra_tenant_id);

    if(issuer?.textContent.trim()!== expected)
    {
        const err = new Error('Invalid issuer');
        err.statusCode = 401;
        err.code = 'INVALID_ISSUER';
        throw err;
    }
}

const validateInResponseTo = (doc, storedAuthnRequestID) =>{
    const response = doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol','Response')[0];
    const inResponseTo = response?.getAttribute('InResponseTo');

    if(!inResponseTo)
    {
        const err = new Error('Missing InResponseTo');
        err.statusCode = 400;
        err.code = 'MISSING_INRESPONSET';
        throw err;
    }
    if(inResponseTo !== storedAuthnRequestID)
    {
        const err = new Error('InResponseTo mismatch — possible CSRF attempt');
        err.statusCode = 401;
        err.code = 'INVALID_INRESPONSETO';
        throw err;
    }
};

const validateConditions = (assertion) => {
  const conditions = assertion.getElementsByTagNameNS(
    'urn:oasis:names:tc:SAML:2.0:assertion', 'Conditions'
  )[0];

  if (!conditions)
    {
        const err = new Error('Missing Conditions element');
        err.statusCode = 400;
        err.code = 'MISSING_CONDITIONS';
        throw err;

    } 

  const now = Math.floor(Date.now() / 1000);
  const notBefore = conditions.getAttribute('NotBefore');
  const notOnOrAfter = conditions.getAttribute('NotOnOrAfter');

  if (notBefore) {
    const nbf = Math.floor(new Date(notBefore).getTime() / 1000);
    if (now < nbf - CLOCK_SKEW_SECONDS) {
        const err = new Error('Assertion not yet valid');
        err.statusCode = 401;
        err.code = 'ASSERTION_NOT_YET_VALID';
        throw err;
    } 
  }

  if (notOnOrAfter) {
    const exp = Math.floor(new Date(notOnOrAfter).getTime() / 1000);
    if (now > exp + CLOCK_SKEW_SECONDS) {
        const err = new Error('Assertion expired');
        err.statusCode = 401;
        err.code = 'ASSERTION_EXPIRED';
        throw err;
    }
  }
};

const validateAudience = (assertion, entityId) => {
  const audiences = assertion.getElementsByTagNameNS(
    'urn:oasis:names:tc:SAML:2.0:assertion', 'Audience'
  );

  const matched = Array.from(
    { length: audiences.length }, (_, i) => audiences[i]
  ).some((a) => a.textContent.trim() === entityId);

  if (!matched) 
  {
        const err = new Error('Audience restriction not satisfied');
        err.statusCode = 401;
        err.code = 'INVALID_AUDIENCE';
        throw err;
  }
};

module.exports = {
  validateStatus,
  validateIssuer,
  validateInResponseTo,
  validateConditions,
  validateAudience,
};
