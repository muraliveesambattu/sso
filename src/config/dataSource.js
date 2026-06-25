/**
 * Data Source — single source of truth for choosing the backend.
 *
 * Decides ONCE whether the app uses PostgreSQL or the local JSON store, so the
 * choice can't drift between services. Every module that needs to know the
 * backend imports `usePostgres` from here instead of re-deriving it.
 *
 * Priority:
 *   1. Explicit override:  DATA_SOURCE=postgres | json
 *   2. Auto-detect:        Postgres if DATABASE_URL or DB_HOST is set, else JSON
 *
 * Switch the whole app in one place:
 *   DATA_SOURCE=json       → force JSON store everywhere
 *   DATA_SOURCE=postgres   → force PostgreSQL everywhere
 *   (unset)                → auto-detect from DB env vars (original behaviour)
 */

const { logger } = require('./logger');

const explicit = (process.env.DATA_SOURCE || '').trim().toLowerCase();

const usePostgres =
  explicit === 'postgres' ? true  :
  explicit === 'json'     ? false :
  !!(process.env.DATABASE_URL || process.env.DB_HOST);

logger.info(`Data source: ${usePostgres ? 'PostgreSQL' : 'JSON'}`, {
  action: 'data_source',
  mode:   usePostgres ? 'postgres' : 'json',
  reason: explicit ? `DATA_SOURCE=${explicit}` : 'auto-detect',
});

module.exports = { usePostgres };
