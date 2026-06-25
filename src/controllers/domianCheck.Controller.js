const { checkDomain } = require('../services/SSO/domainCheck.service');
const { logger }      = require('../config/logger');

const domainCheck = async (req, res, next) => {
  try {
    const email     = req.body.email  ? String(req.body.email).trim()  : null;
    const rawDomain = req.body.domain ? String(req.body.domain).trim() : null;
    const domain    = rawDomain?.includes('@') ? rawDomain.split('@')[1] : rawDomain;

    logger.info('Domain check request', {
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
