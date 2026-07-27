/**
 * Admin Auth Middleware
 * Protects POST /auth/sso/save and POST /auth/test-connection.
 * Validates X-Admin-API-Key header using timing-safe comparison.
 */

const crypto        = require('node:crypto');
const { logger }    = require('../config/logger');

const requireAdminKey = (req, res, next) => {
  const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

  if (!ADMIN_API_KEY) {
    logger.error('ADMIN_API_KEY not set — admin endpoints unprotected', { action: 'admin_auth_misconfigured' });
    return res.status(503).json({
      success: false,
      error: { code: 'SERVER_MISCONFIGURED', message: 'Server is not properly configured. Please contact your administrator.' },
    });
  }

  const providedKey = req.headers['x-admin-api-key'];

  if (!providedKey) {
    logger.warn('Missing admin API key', { action: 'admin_auth_missing', path: req.path, ip: req.ip });
    return res.status(401).json({
      success: false,
      error: { code: 'MISSING_API_KEY', message: 'Admin API key is required. Provide it in the X-Admin-API-Key header.' },
    });
  }

  try {
    const expected = Buffer.from(ADMIN_API_KEY);
    const provided = Buffer.from(providedKey);

    if (expected.length !== provided.length || !crypto.timingSafeEqual(expected, provided)) {
      logger.warn('Invalid admin API key', { action: 'admin_auth_invalid', path: req.path, ip: req.ip });
      return res.status(403).json({
        success: false,
        error: { code: 'INVALID_API_KEY', message: 'Invalid admin API key.' },
      });
    }
  } catch {
    return res.status(403).json({
      success: false,
      error: { code: 'INVALID_API_KEY', message: 'Invalid admin API key.' },
    });
  }

  logger.info('Admin authenticated', { action: 'admin_auth_ok', path: req.path, ip: req.ip });
  next();
};

module.exports = { requireAdminKey };
