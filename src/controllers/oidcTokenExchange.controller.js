/**
 * OIDC Token Exchange Controller
 * POST /v1/auth/oidc/token-exchange
 */

const { oidcTokenExchangeService } = require('../services/oidc/oidcTokenExchange.service');
const { stateStore }    = require('../config/stateStore');
const { logger }        = require('../config/logger');
const { auditUserLogin } = require('../services/audit/audit.service');

const handleOidcCallback = async (req, res, next) => {
  try {
    const { code, company_id, state } = req.body;

    logger.info('Token exchange request', { action: 'token_exchange', company_id, ip: req.ip });

    if (!code || !company_id || !state) {
      logger.warn('Token exchange missing fields', { action: 'token_exchange_error', code: !!code, company_id: !!company_id, state: !!state });
      return res.status(400).json({ error: 'Missing required fields: code, company_id, state', code: 'MISSING_REQUIRED_FIELDS' });
    }

    const storedState = await stateStore.get(state);
    if (!storedState) {
      logger.warn('State not found', { action: 'state_not_found', company_id });
      return res.status(401).json({ error: 'Session expired or not found. Please sign in again.', code: 'SESSION_EXPIRED' });
    }

    await stateStore.del(state);
    logger.debug('State validated and cleared', { action: 'state_cleared', company_id });

    const result = await oidcTokenExchangeService(
      code, company_id, storedState.code_verifier, storedState.nonce, req.ip
    );

    logger.info('Token exchange successful', { action: 'token_exchange_success', company_id, userAction: result.userAction });

    // Audit — record every login with email, company, IP, and action (created/updated/login)
    await auditUserLogin(result.user?.email, company_id, req.ip, result.userAction);

    return res.status(200).json({
      customToken: result.customToken,
      user:        result.user,
      roles:       result.roles,
      userAction:  result.userAction,
      session:     result.session,
    });

  } catch (err) {
    logger.error('Token exchange error', { action: 'token_exchange_error', code: err.code, error: err.message });
    next(err);
  }
};

module.exports = { handleOidcCallback };
