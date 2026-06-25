/**
 * Audit Log Service
 *
 * Records every significant action for compliance (SOC2 / ISO27001).
 * Write-only — audit logs are never modified or deleted.
 *
 * Actions logged:
 *   sso_config_saved      — SSO config created/updated
 *   sso_test_connection   — credentials tested
 *   user_login            — user signed in via SSO
 *   user_jit_created      — new user auto-provisioned
 *   user_jit_updated      — existing user roles synced
 *   domain_check          — domain lookup performed
 *
 * Falls back to logger.info if DB is not available.
 */

const { logger } = require('../../config/logger');
const { usePostgres } = require('../../config/dataSource');

const writeAuditLog = async ({ actor, actor_ip, action, resource, resource_id, status = 'success', detail }) => {
  const entry = { actor, actor_ip, action, resource, resource_id, status, detail };

  if (usePostgres) {
    try {
      const sequelize = require('../../config/db');
      await sequelize.query(
        `INSERT INTO audit_logs (actor, actor_ip, action, resource, resource_id, status, detail, created_at)
         VALUES (:actor, :actor_ip, :action, :resource, :resource_id, :status, :detail, NOW())`,
        {
          replacements: {
            actor:       actor       || null,
            actor_ip:    actor_ip    || null,
            action,
            resource:    resource    || null,
            resource_id: resource_id || null,
            status,
            detail:      detail ? JSON.stringify(detail) : null,
          },
          type: sequelize.QueryTypes.INSERT,
        }
      );
    } catch (err) {
      // Never fail a request because of audit logging
      logger.error('Audit log write failed', { action: 'audit_write_error', error: err.message });
    }
  }

  // Always log to stdout (captured by GCP Cloud Logging)
  logger.info('AUDIT', { ...entry });
};

// ── Convenience helpers ───────────────────────────────────────────────────────

const auditSsoConfigSaved = (companyId, actor, ip, protocol) =>
  writeAuditLog({ actor, actor_ip: ip, action: 'sso_config_saved', resource: 'sso_integrations', resource_id: companyId, detail: { protocol } });

const auditTestConnection = (ip, protocol, success) =>
  writeAuditLog({ actor_ip: ip, action: 'sso_test_connection', resource: 'oidc_configurations', status: success ? 'success' : 'failure', detail: { protocol } });

const auditUserLogin = (email, companyId, ip, userAction) =>
  writeAuditLog({ actor: email, actor_ip: ip, action: 'user_login', resource: 'sso_users', resource_id: companyId, detail: { userAction } });

const auditDomainCheck = (domain, ip, found) =>
  writeAuditLog({ actor_ip: ip, action: 'domain_check', resource: 'sso_integrations', status: found ? 'success' : 'failure', detail: { domain } });

module.exports = { writeAuditLog, auditSsoConfigSaved, auditTestConnection, auditUserLogin, auditDomainCheck };
