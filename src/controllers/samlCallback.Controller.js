const { processSamlCallback } = require('../services/Saml/samlCallback.service');
const { logger } = require('../config/logger');
const { defaults } = require('../config/constants');

const FRONTEND_URL = defaults.FRONTEND_URL;

// Upper bounds so a non-string body or oversized value can't reach base64
// decoding / XML parsing downstream. Entra SAMLResponses are well under 200KB.
const MAX_SAML_RESPONSE_LEN = 200000;
const MAX_RELAY_STATE_LEN   = 512;

const isValidField = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max;

const samlCallbackController = async (req, res, next) => {
  try {
    const { SAMLResponse, RelayState } = req.body;

    // Input validation — type + length, not just truthiness
    if (!isValidField(SAMLResponse, MAX_SAML_RESPONSE_LEN)) {
      logger.warn('[SAML] Missing or invalid SAMLResponse in callback');
      return res.redirect(
        `${FRONTEND_URL}/auth/oidc/callback?error=MISSING_SAML_RESPONSE`
      );
    }

    if (!isValidField(RelayState, MAX_RELAY_STATE_LEN)) {
      logger.warn('[SAML] Missing or invalid RelayState in callback');
      return res.redirect(
        `${FRONTEND_URL}/auth/oidc/callback?error=MISSING_RELAY_STATE`
      );
    }

    // Get client IP for audit (handle proxy scenarios)
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim()
      || req.ip
      || req.connection.remoteAddress
      || req.socket.remoteAddress;

    // Process SAML callback — validate assertion, resolve user, generate token
    const result = await processSamlCallback(
      SAMLResponse,
      RelayState,
      req.session,
      clientIp
    );

    // Redirect to frontend with customToken in URL
    // Frontend oidc-callback component reads ?token= and calls signInWithCustomToken()
    logger.debug(`[SAML] Redirecting to frontend with customToken | uid: ${result.user?.user_id}`);
    return res.redirect(
      `${FRONTEND_URL}/auth/oidc/callback?token=${encodeURIComponent(result.customToken)}`
    );

  } catch (err) {
    // Audit failed login attempts — structured fields (NOT a JSON.stringify'd
    // string) so logger PII masking applies and the fields stay queryable.
    // relayState omitted: opaque, no diagnostic value, avoids logging it.
    logger.error('[SAML_LOGIN_FAILED]', {
      action:     'saml_login_failed',
      error:      err.message,
      code:       err.code,
      statusCode: err.statusCode,
      clientIp:   req.headers['x-forwarded-for']?.split(',')[0].trim()
        || req.ip
        || req.connection.remoteAddress,
    });

    // Redirect to frontend with error
    return res.redirect(
      `${FRONTEND_URL}/auth/oidc/callback?error=${encodeURIComponent(err.code || 'SAML_LOGIN_FAILED')}`
    );
  }
};


module.exports = {samlCallbackController};