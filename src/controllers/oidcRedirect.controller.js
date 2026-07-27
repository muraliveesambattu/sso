/**
 * OIDC Redirect Controller
 *
 * Handles the browser redirect from Microsoft Entra after user authentication.
 * Entra sends the authorization code + state to this GET endpoint.
 *
 * Production (same-origin): Express serves React's index.html directly.
 *   The browser keeps the /auth/oidc/callback?code=...&state=... URL.
 *   React Router renders OIDCCallback, which POSTs to /auth/oidc/token-exchange.
 *
 * Development (separate origins): Redirects to the local frontend dev server
 *   so the React app running on localhost:3000 can handle the callback.
 *
 * GET /auth/oidc/callback?code=...&state=...&session_state=...
 */

const path = require('node:path');
const { logger } = require('../config/logger');
const { defaults } = require('../config/constants');

const handleOidcRedirect = (req, res) => {
  const { code, state, error, error_description } = req.query;

  logger.debug(`[OIDC-REDIRECT] GET /auth/oidc/callback received | code: ${!!code} | state: ${!!state}`);

  // Entra returned an error (e.g. user cancelled login)
  if (error) {
    logger.error(`[OIDC-REDIRECT] Entra returned error: ${error} — ${error_description}`);
    const frontendUrl = defaults.FRONTEND_URL;
    return res.redirect(
      `${frontendUrl}/auth/oidc/error?error=${encodeURIComponent(error)}&description=${encodeURIComponent(error_description || '')}`
    );
  }

  if (!code || !state) {
    logger.warn(`[OIDC-REDIRECT] Missing code or state in callback`);
    return res.status(400).json({
      error: 'Missing code or state in OIDC redirect',
      code:  'MISSING_OIDC_PARAMS'
    });
  }

  // ── Production: same-origin — serve React SPA directly ──────────────────────
  // Redirecting to FRONTEND_URL/auth/oidc/callback would loop back to this same
  // Express route. Instead, serve index.html so React Router renders OIDCCallback.
  // The code + state remain in the URL for the React component to read.
  if (process.env.NODE_ENV === 'production') {
    logger.debug(`[OIDC-REDIRECT] Production same-origin — serving React SPA for OIDCCallback`);
    return res.sendFile(path.join(__dirname, '../../client/dist/index.html'));
  }

  // ── Development: separate frontend origin — relay via redirect ───────────────
  const frontendUrl = defaults.FRONTEND_URL;
  const redirectUrl = `${frontendUrl}/auth/oidc/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`;

  logger.debug(`[OIDC-REDIRECT] Dev mode — relaying code to frontend | url: ${frontendUrl}/auth/oidc/callback`);

  return res.redirect(redirectUrl);
};

module.exports = { handleOidcRedirect };
