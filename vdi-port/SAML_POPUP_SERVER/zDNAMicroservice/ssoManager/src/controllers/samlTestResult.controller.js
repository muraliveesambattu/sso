const { takeSamlTestResult } = require('../services/Saml/samlAuthRequest.service');

const SESSION_REF_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Phase 2 of the SAML Test Connection popup flow. The parent window posts { sessionRef } once the
// popup signals "done". No admin key: the single-use sessionRef (created by the protected
// init call) is the credential. Response shapes mirror the OIDC test callback.
const handleSamlTestResult = (req, res) => {
  const { sessionRef } = req.body || {};
  if (!sessionRef || typeof sessionRef !== 'string' || !SESSION_REF_RE.test(sessionRef)) {
    return res.status(400).json({ success: false, error: { message: 'sessionRef must be a valid UUID', code: 'MISSING_SESSION_REF' } });
  }

  const result = takeSamlTestResult(sessionRef);
  if (!result) {
    // null means either TTL expired or the session was never created (service restart cleared
    // the in-memory store). Both are surfaced as session-expired to the caller.
    return res.status(401).json({ success: false, error: { message: 'Session not found or expired. Please start a new test connection.', code: 'TC_STORE_EXPIRED' } });
  }
  if (result.pending) return res.status(202).json({ success: true, pending: true });
  if (!result.success) {
    return res.status(400).json({ success: false, error: { message: result.message, code: result.code || 'TEST_CONNECTION_FAILED' } });
  }
  return res.status(200).json({
    success: true,
    data: { protocol: 'saml', sso_status: 'active', claims: result.claims },
  });
};

module.exports = { handleSamlTestResult };