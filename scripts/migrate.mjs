/**
 * Database Migration Script
 *
 * Runs all pending Sequelize migrations then seeds default roles.
 * Safe to run multiple times — migrations track state in `sequelize_meta` table.
 *
 * Usage:
 *   node scripts/migrate.mjs           ← run pending migrations + seed
 *   node scripts/migrate.mjs --seed    ← also run seeders explicitly
 *
 * Called automatically by:
 *   - npm run migrate
 */

import dotenv from 'dotenv';
import { Sequelize } from 'sequelize';
import { Umzug, SequelizeStorage } from 'umzug';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

dotenv.config();

// The migration and seeder files are CommonJS (`module.exports = { up, down }`)
// and Umzug's resolve() loads them synchronously. createRequire keeps that
// working from an ES module: dynamic import() would force resolve() to become
// async and would need pathToFileURL() to accept a Windows path.
const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── DB Connection ─────────────────────────────────────────────────────────────
const sequelize = process.env.DATABASE_URL
  ? new Sequelize(process.env.DATABASE_URL, { dialect: 'postgres', logging: false })
  : new Sequelize(
      process.env.DB_NAME,
      process.env.DB_USER,
      process.env.DB_PASSWORD,
      {
        host:    process.env.DB_HOST || 'localhost',
        port:    Number(process.env.DB_PORT) || 5432,
        dialect: 'postgres',
        logging: false,
      }
    );

// ── Migration runner ──────────────────────────────────────────────────────────
const migrator = new Umzug({
  migrations: {
    glob: path.join(__dirname, '../src/database/migrations/*.js'),
    resolve: ({ name, path: migPath, context }) => {
      const migration = require(migPath);
      return {
        name,
        up:   async () => migration.up(context, Sequelize),
        down: async () => migration.down(context, Sequelize),
      };
    },
  },
  context:  sequelize.getQueryInterface(),
  storage:  new SequelizeStorage({ sequelize }),
  logger:   {
    info:  ({ event, name }) => console.log(`[MIGRATE] ${event}: ${name}`),
    warn:  (msg) => console.warn('[MIGRATE]', msg),
    error: (msg) => console.error('[MIGRATE]', msg),
    debug: () => {},
  },
});

// ── Seeder runner ─────────────────────────────────────────────────────────────
const seeder = new Umzug({
  migrations: {
    glob: path.join(__dirname, '../src/database/seeders/*.js'),
    resolve: ({ name, path: seedPath, context }) => {
      const seeder = require(seedPath);
      return {
        name,
        up:   async () => seeder.up(context, Sequelize),
        down: async () => seeder.down(context, Sequelize),
      };
    },
  },
  context:  sequelize.getQueryInterface(),
  storage:  new SequelizeStorage({ sequelize, tableName: 'sequelize_seed_meta' }),
  logger:   {
    info:  ({ event, name }) => console.log(`[SEED] ${event}: ${name}`),
    warn:  (msg) => console.warn('[SEED]', msg),
    error: (msg) => console.error('[SEED]', msg),
    debug: () => {},
  },
});

// ── Main ──────────────────────────────────────────────────────────────────────
async function run() {
  try {
    console.log('[MIGRATE] Connecting to PostgreSQL...');
    await sequelize.authenticate();
    console.log('[MIGRATE] Connection OK');

    // Run pending migrations
    const pending = await migrator.pending();
    if (pending.length === 0) {
      console.log('[MIGRATE] No pending migrations — schema is up to date');
    } else {
      console.log(`[MIGRATE] Running ${pending.length} pending migration(s)...`);
      await migrator.up();
      console.log('[MIGRATE] All migrations complete ✓');
    }

    // Always run seeders (INSERT ON CONFLICT DO NOTHING — safe to repeat)
    console.log('[SEED] Running seeders...');
    await seeder.up();
    console.log('[SEED] Seeders complete ✓');

    console.log('[MIGRATE] Done ✓');
    process.exit(0);
  } catch (err) {
    console.error('[MIGRATE] Failed:', err.message);
    console.error(err.stack);
    process.exit(1);
  }
}

// Top-level await (ESM) — no wrapper call. run() reports its own errors and exits;
// anything thrown outside it is caught here.
try {
  await run();
} catch (error) {
  console.error(error);
  process.exit(1);
}
