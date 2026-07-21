const { checkDomain } = require('../services/SSO/domainCheck.service');
const { logger }      = require('../config/logger');

const MAX_INPUT_LEN = 256;

// Coerce to a bounded, trimmed string or null — rejects non-string request
// bodies and oversized input before they reach validation / domain lookups.
const asBoundedString = (v) => {
  if (typeof v !== 'string') return null;
  const trimmed = v.trim();
  return trimmed.length > 0 && trimmed.length <= MAX_INPUT_LEN ? trimmed : null;
};

const domainCheck = async (req, res, next) => {
  try {
    const email     = asBoundedString(req.body.email);
    const rawDomain = asBoundedString(req.body.domain);
    const domain    = rawDomain?.includes('@') ? rawDomain.split('@')[1] : rawDomain;

    // debug (not info): /auth/domain-check is a high-traffic unauthenticated
    // entry point already covered by the requestLogger middleware.
    logger.debug('Domain check request', {
      action: 'domain_check',
      email:  email  || undefined,
      domain: domain || undefined,
      ip:     req.ip,
    });

    const result = await checkDomain(email, domain, req.session, req.sessionID);

    logger.info('Domain check result', {
      action:     'domain_check_result',
      found:      result.found,
      protocol:   result.protocol  || undefined,
      company_id: result.company_id || undefined,
    });

    return res.status(200).json(result);
  } catch (err) {
    logger.error('Domain check error', { action: 'domain_check_error', code: err.code, error: err.message });
    next(err);
  }
};

module.exports = { domainCheck };
