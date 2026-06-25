const { processSamlCallback } = require('../services/Saml/samlCallback.service');
const { logger } = require('../config/logger');
const { defaults } = require('../config/constants');

const FRONTEND_URL = defaults.FRONTEND_URL;

const samlCallbackController = async (req, res, next) => {
  try {
    const { SAMLResponse, RelayState } = req.body;

    // Input validation
    if (!SAMLResponse) {
      logger.warn('[SAML] Missing SAMLResponse in callback');
      return res.redirect(
        `${FRONTEND_URL}/auth/oidc/callback?error=MISSING_SAML_RESPONSE`
      );
    }

    if (!RelayState) {
      logger.warn('[SAML] Missing RelayState in callback');
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
    // Audit failed login attempts
    logger.error('[SAML_LOGIN_FAILED]', JSON.stringify({
      timestamp: new Date().toISOString(),
      error: err.message,
      code: err.code,
      statusCode: err.statusCode,
      clientIp: req.headers['x-forwarded-for']?.split(',')[0].trim()
        || req.ip
        || req.connection.remoteAddress,
      relayState: req.body.RelayState
    }));

    // Redirect to frontend with error
    return res.redirect(
      `${FRONTEND_URL}/auth/oidc/callback?error=${encodeURIComponent(err.code || 'SAML_LOGIN_FAILED')}`
    );
  }
};


module.exports = {samlCallbackController};