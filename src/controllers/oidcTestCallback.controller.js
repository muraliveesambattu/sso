/**
 * OIDC Test Connection Callback Controller
 *
 * Phase 2 of the browser-based test-connection flow.
 * The parent window (MDNA Console) POSTs { code, state, sessionRef } here
 * after the Azure popup returns. Secrets are retrieved from tcStore — they
 * were parked there by handleTestConnection and never sent to the browser.
 *
 * No admin key on this route: the single-use sessionRef (created by the
 * admin-key-protected init call) is the credential.
 */

const { decodeJwt }       = require('../utils/oidc/tokenExchange.util');
const { verifyJwtSignature } = require('../utils/oidc/jwkValidation.util');
const { logger }          = require('../config/logger');
const tcStore             = require('../utils/shared/testConnectionStore');
const https               = require('https');
const { microsoft }       = require('../config/constants');

const fetchJson = (url, options) =>
  new Promise((resolve, reject) => {
    const body = options.body || null;
    const headers = { ...(options.headers || {}) };
    if (body) headers['Content-Length'] = Buffer.byteLength(body);

    const req = https.request(url, { method: options.method || 'GET', headers }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });

const oidcTestCallbackController = async (req, res, next) => {
  try {
    const { code, state, sessionRef } = req.body;

    if (!code || !state) {
      return res.status(400).json({
        success: false,
        error: { message: 'code and state are required', code: 'MISSING_PARAMS' },
      });
    }

    if (!sessionRef) {
      return res.status(400).json({
        success: false,
        error: { message: 'sessionRef is required', code: 'MISSING_SESSION_REF' },
      });
    }

    // Single-use — consume() removes the entry on retrieval (prevents replay)
    const stored = tcStore.consume(sessionRef);
    if (!stored) {
      return res.status(401).json({
        success: false,
        error: { message: 'Session expired. Please try again.', code: 'TC_STORE_EXPIRED' },
      });
    }

    const {
      tenant_id, client_id, client_auth_method,
      code_verifier, client_secret, redirect_uri,
      private_key_b64, client_cert_thumbprint,
      state: storedState, nonce,
    } = stored;

    // Validate state (CSRF / session-fixation protection)
    if (storedState !== state) {
      return res.status(401).json({
        success: false,
        error: { message: 'State mismatch', code: 'STATE_MISMATCH' },
      });
    }

    // Build token request body
    const tokenParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id,
      redirect_uri,
    });

    if (client_auth_method === 'none') {
      // PKCE — code_verifier proves possession
      tokenParams.set('code_verifier', code_verifier);
    } else if (client_auth_method === 'private_key_jwt' || client_auth_method === 'certificate') {
      // Client Certificate — sign a JWT assertion with the cert's private key
      const { generateJwtAssertion } = require('../utils/oidc/tokenExchange.util');
      const assertion = generateJwtAssertion(client_id, tenant_id, private_key_b64, client_cert_thumbprint);
      tokenParams.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      tokenParams.set('client_assertion', assertion);
    } else {
      // client_secret_post / client_secret
      tokenParams.set('client_secret', client_secret);
    }

    const tokenUrl = microsoft.tokenUrl(tenant_id);

    const tokenRes = await fetchJson(tokenUrl, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    tokenParams.toString(),
    });

    if (tokenRes.status !== 200 || !tokenRes.body.id_token) {
      const errCode = tokenRes.body.error || 'TOKEN_EXCHANGE_FAILED';
      const errDesc = tokenRes.body.error_description?.split('\r\n')[0] || 'Token exchange failed';
      logger.warn('Test callback — token exchange failed', { action: 'test_callback_exchange_failed', errCode });
      return res.status(400).json({
        success: false,
        error: { message: errDesc, code: errCode },
      });
    }

    // Verify the id_token is genuinely from Microsoft (signature via JWKS)
    await verifyJwtSignature(tokenRes.body.id_token, tenant_id);

    // Verify nonce — only when the id_token actually carries one. The popup
    // doesn't always echo a nonce; for a test connection the state match +
    // JWKS signature verification already bind the token to this session, so a
    // missing nonce is not a failure (defense-in-depth, not the primary guard).
    const claims = decodeJwt(tokenRes.body.id_token);
    if (nonce && claims.nonce && claims.nonce !== nonce) {
      logger.warn('Test callback — nonce mismatch', { action: 'test_callback_nonce_mismatch' });
      return res.status(401).json({
        success: false,
        error: { message: 'Nonce mismatch', code: 'NONCE_MISMATCH' },
      });
    }

    logger.info('Test callback — token exchange succeeded', {
      action: 'test_callback_success',
      email:  claims.email || claims.preferred_username,
    });

    // Token exchange succeeded — test connection passed
    return res.status(200).json({
      success: true,
      data: {
        protocol:   'oidc',
        sso_status: 'active',
      },
    });
  } catch (err) {
    logger.error('Test callback error', { action: 'test_callback_error', error: err.message });
    next(err);
  }
};

module.exports = { oidcTestCallbackController };
