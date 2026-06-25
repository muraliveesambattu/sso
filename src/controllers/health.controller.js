/**
 * Health Check Controller
 *
 * GET /health
 *
 * Used by:
 *   - Cloud Run load balancer (liveness + readiness probe)
 *   - Monitoring tools (UptimeRobot, GCP Cloud Monitoring)
 *
 * Response codes:
 *   200 — all systems healthy
 *   503 — a dependency is degraded (DB down)
 *
 * Response body:
 * {
 *   status:   "healthy" | "degraded",
 *   uptime:   123.45,          // seconds since server start
 *   version:  "1.0.0",
 *   checks: {
 *     database: { status: "healthy" | "unhealthy" | "not_configured", responseTimeMs: 4 },
 *   }
 * }
 */

const sequelize    = require('../config/db');
const { logger } = require('../config/logger');
const { version }  = require('../../package.json');

const usePostgres  = !!(process.env.DATABASE_URL || process.env.DB_HOST);

// ── Check PostgreSQL ──────────────────────────────────────────────────────────
const checkDatabase = async () => {
  if (!usePostgres) {
    return { status: 'not_configured', detail: 'Using JSON fallback' };
  }
  const start = Date.now();
  try {
    await sequelize.authenticate();
    return { status: 'healthy', responseTimeMs: Date.now() - start };
  } catch (err) {
    return { status: 'unhealthy', responseTimeMs: Date.now() - start, error: err.message };
  }
};

// ── Handler ───────────────────────────────────────────────────────────────────
const healthCheck = async (req, res) => {
  const database = await checkDatabase();

  const allHealthy = database.status !== 'unhealthy';

  const body = {
    status:  allHealthy ? 'healthy' : 'degraded',
    uptime:  Math.floor(process.uptime()),
    version,
    checks: { database },
  };

  const httpStatus = allHealthy ? 200 : 503;

  logger.debug(`[HEALTH] status: ${body.status} | db: ${database.status}`);

  return res.status(httpStatus).json(body);
};

module.exports = { healthCheck };
