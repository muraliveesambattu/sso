const { takeSamlTestResult } = require('../services/Saml/samlAuthRequest.service');

// Phase 2 of the SAML Test Connection popup flow. The parent window posts { sessionRef } once the
// popup signals "done". No admin key: the single-use sessionRef (created by the protected
// init call) is the credential. Response shapes mirror the OIDC test callback.
const handleSamlTestResult = (req, res) => {
  const { sessionRef } = req.body || {};
  if (!sessionRef || typeof sessionRef !== 'string') {
    return res.status(400).json({ success: false, error: { message: 'sessionRef is required', code: 'MISSING_SESSION_REF' } });
  }

  const result = takeSamlTestResult(sessionRef);
  if (!result) {
    return res.status(401).json({ success: false, error: { message: 'Session expired. Please try again.', code: 'TC_STORE_EXPIRED' } });
  }
  if (result.pending) return res.status(202).json({ success: true, pending: true });
  if (!result.success) {
    return res.status(400).json({ success: false, error: { message: result.message, code: result.code } });
  }
  return res.status(200).json({
    success: true,
    data: { protocol: 'saml', sso_status: 'active', claims: result.claims },
  });
};

module.exports = { handleSamlTestResult };
