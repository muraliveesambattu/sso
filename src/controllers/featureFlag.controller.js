/**
 * Feature Flag Controller
 *
 * GET  /v1/auth/admin/flags/:company_id  → list all flags for a company
 * POST /v1/auth/admin/flags              → set a flag for a company
 */

const { isEnabled, setFlag, getFlagsForCompany, VALID_FLAGS } = require('../services/featureFlag.service');
const { logger } = require('../config/logger');
const { writeAuditLog } = require('../services/audit/audit.service');

// GET /v1/auth/admin/flags/:company_id
const getFlags = async (req, res, next) => {
  try {
    const { company_id } = req.params;
    if (!company_id) return res.status(400).json({ success: false, error: { code: 'MISSING_COMPANY_ID', message: 'company_id is required' } });

    const flags = await getFlagsForCompany(company_id);

    logger.info('Feature flags fetched', { action: 'flags_get', company_id, ip: req.ip });

    return res.status(200).json({
      success:    true,
      company_id,
      flags,
      valid_flags: VALID_FLAGS,
    });
  } catch (err) {
    next(err);
  }
};

// POST /v1/auth/admin/flags
const updateFlag = async (req, res, next) => {
  try {
    const { company_id, flag, enabled } = req.body;

    if (!company_id) return res.status(400).json({ success: false, error: { code: 'MISSING_COMPANY_ID', message: 'company_id is required' } });
    if (!flag)       return res.status(400).json({ success: false, error: { code: 'MISSING_FLAG',       message: 'flag is required' } });
    if (enabled === undefined) return res.status(400).json({ success: false, error: { code: 'MISSING_ENABLED', message: 'enabled (true/false) is required' } });

    await setFlag(company_id, flag, !!enabled, req.ip);

    // Audit every flag change — who, what, when
    await writeAuditLog({
      actor:       req.ip,
      actor_ip:    req.ip,
      action:      'feature_flag_updated',
      resource:    'feature_flags',
      resource_id: company_id,
      status:      'success',
      detail:      { flag, enabled: !!enabled },
    });

    logger.info('Feature flag updated', { action: 'flag_set', company_id, flag, enabled, ip: req.ip });

    return res.status(200).json({
      success:    true,
      company_id,
      flag,
      enabled:    !!enabled,
      message:    `Flag '${flag}' set to ${enabled} for company '${company_id}'`,
    });
  } catch (err) {
    next(err);
  }
};

module.exports = { getFlags, updateFlag };
