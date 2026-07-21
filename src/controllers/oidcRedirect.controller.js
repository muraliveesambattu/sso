/**
 * OIDC Redirect Controller
 *
 * Handles the browser redirect from Microsoft Entra after user authentication.
 * Entra sends the authorization code + state to this GET endpoint, which relays
 * them to the separately-hosted frontend's /auth/oidc/callback route. The React
 * app there renders OIDCCallback, which POSTs to /auth/oidc/token-exchange.
 *
 * The frontend is hosted separately (not bundled with this microservice) — set
 * FRONTEND_URL to its origin. This mirrors the SAML callback controller, which
 * already relays to FRONTEND_URL.
 *
 * GET /auth/oidc/callback?code=...&state=...&session_state=...
 */

const { logger } = require('../config/logger');
const { defaults } = require('../config/constants');

const handleOidcRedirect = (req, res) => {
  const { code, state, error, error_description } = req.query;

  logger.debug(`[OIDC-REDIRECT] GET /auth/oidc/callback received | code: ${!!code} | state: ${!!state}`);

  // Entra returned an error (e.g. user cancelled login)
  if (error) {
    logger.error(`[OIDC-REDIRECT] Entra returned error: ${error} — ${error_description}`);
    return res.redirect(
      `${defaults.FRONTEND_URL}/auth/oidc/error?error=${encodeURIComponent(error)}&description=${encodeURIComponent(error_description || '')}`
    );
  }

  if (!code || !state) {
    logger.warn(`[OIDC-REDIRECT] Missing code or state in callback`);
    return res.status(400).json({
      error: 'Missing code or state in OIDC redirect',
      code:  'MISSING_OIDC_PARAMS'
    });
  }

  // Relay code + state to the separately-hosted frontend callback route. The
  // React app renders OIDCCallback and POSTs /auth/oidc/token-exchange.
  const redirectUrl = `${defaults.FRONTEND_URL}/auth/oidc/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`;
  logger.debug(`[OIDC-REDIRECT] Relaying code to frontend | url: ${defaults.FRONTEND_URL}/auth/oidc/callback`);

  return res.redirect(redirectUrl);
};

module.exports = { handleOidcRedirect };
