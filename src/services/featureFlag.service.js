/**
 * Feature Flag Service
 *
 * Controls two flags per company:
 *   sso_enabled  — master SSO switch
 *   jit_enabled  — auto user provisioning on first login
 *
 * Priority (highest wins):
 *   1. Env var FEATURE_<FLAG>_DISABLED=true  → kills flag globally (all companies)
 *   2. DB row per company                    → per-company control
 *   3. Default (true)                        → if no DB row found
 *
 * Usage:
 *   const { isEnabled } = require('./featureFlag.service');
 *   if (!await isEnabled(companyId, 'sso_enabled')) { ... }
 */

const { logger } = require('../config/logger');

const VALID_FLAGS = ['sso_enabled', 'jit_enabled'];

// ── Firestore read ────────────────────────────────────────────────────────────
// Collection: feature_flags / doc: <companyId> / fields: { sso_enabled, jit_enabled }
const getFlagFromFirestore = async (companyId, flagName) => {
  try {
    const admin = require('firebase-admin');
    const db = admin.firestore();
    const doc = await db.collection('feature_flags').doc(companyId).get();
    if (!doc.exists) return null;
    const data = doc.data();
    return data[flagName] !== undefined ? data[flagName] : null;
  } catch (err) {
    logger.warn('Firestore feature flag read failed — falling back to DB', {
      action: 'feature_flag_firestore_error', flag: flagName, error: err.message,
    });
    return null;
  }
};

// ── DB read ───────────────────────────────────────────────────────────────────
const getFlagFromDb = async (companyId, flagName) => {
  try {
    const sequelize = require('../config/db');
    const [rows] = await sequelize.query(
      'SELECT enabled FROM feature_flags WHERE company_id = :companyId AND flag_name = :flagName LIMIT 1',
      { replacements: { companyId, flagName }, type: sequelize.QueryTypes.SELECT }
    );
    return rows ? rows.enabled : null;
  } catch (err) {
    logger.warn('Feature flag DB read failed — using default', {
      action: 'feature_flag_db_error', flag: flagName, error: err.message,
    });
    return null;
  }
};

// ── DB write ──────────────────────────────────────────────────────────────────
const setFlagInDb = async (companyId, flagName, enabled, updatedBy) => {
  const sequelize = require('../config/db');
  await sequelize.query(
    `INSERT INTO feature_flags (company_id, flag_name, enabled, updated_by, created_at, updated_at)
     VALUES (:companyId, :flagName, :enabled, :updatedBy, NOW(), NOW())
     ON CONFLICT (company_id, flag_name)
     DO UPDATE SET enabled = :enabled, updated_by = :updatedBy, updated_at = NOW()`,
    { replacements: { companyId, flagName, enabled, updatedBy: updatedBy || null } }
  );
};

// ── List all flags for a company ──────────────────────────────────────────────
const getFlagsForCompany = async (companyId) => {
  const result = {};

  for (const flag of VALID_FLAGS) {
    const globalKill = process.env[`FEATURE_${flag.toUpperCase()}_DISABLED`] === 'true';
    if (globalKill) {
      result[flag] = { enabled: false, source: 'env_override' };
      continue;
    }
    const dbValue = await getFlagFromDb(companyId, flag);
    result[flag] = {
      enabled: dbValue !== null ? dbValue : true,
      source:  dbValue !== null ? 'database' : 'default',
    };
  }

  return result;
};

// ── Main: check a single flag ─────────────────────────────────────────────────
const isEnabled = async (companyId, flagName) => {
  if (!VALID_FLAGS.includes(flagName)) {
    logger.warn('Unknown feature flag checked', { action: 'unknown_flag', flag: flagName });
    return true; // unknown flags default to enabled (fail open)
  }

  // 1. Global env kill switch — FEATURE_SSO_ENABLED_DISABLED=true
  const envKey = `FEATURE_${flagName.toUpperCase()}_DISABLED`;
  if (process.env[envKey] === 'true') {
    logger.info('Feature flag disabled by env var', { action: 'flag_env_kill', flag: flagName, company_id: companyId });
    return false;
  }

  // 2. Firestore — real-time, per-company
  const firestoreValue = await getFlagFromFirestore(companyId, flagName);
  if (firestoreValue !== null) {
    logger.debug('Feature flag from Firestore', { action: 'flag_firestore', flag: flagName, company_id: companyId, enabled: firestoreValue });
    return firestoreValue;
  }

  // 3. Per-company DB flag
  const dbValue = await getFlagFromDb(companyId, flagName);
  if (dbValue !== null) {
    logger.debug('Feature flag from DB', { action: 'flag_db', flag: flagName, company_id: companyId, enabled: dbValue });
    return dbValue;
  }

  // 4. Default — enabled
  logger.debug('Feature flag using default (true)', { action: 'flag_default', flag: flagName, company_id: companyId });
  return true;
};

// ── Set a flag ────────────────────────────────────────────────────────────────
const setFlag = async (companyId, flagName, enabled, updatedBy) => {
  if (!VALID_FLAGS.includes(flagName)) {
    const err = new Error(`Unknown flag: ${flagName}. Valid flags: ${VALID_FLAGS.join(', ')}`);
    err.statusCode = 400;
    err.code = 'INVALID_FLAG';
    throw err;
  }

  await setFlagInDb(companyId, flagName, enabled, updatedBy);

  logger.info('Feature flag updated', {
    action:     'flag_updated',
    flag:       flagName,
    company_id: companyId,
    enabled,
    updated_by: updatedBy,
  });
};

module.exports = { isEnabled, setFlag, getFlagsForCompany, VALID_FLAGS };
