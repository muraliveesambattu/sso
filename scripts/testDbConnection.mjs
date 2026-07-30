/**
 * Standalone DB connection test.
 *
 * Tries to connect to PostgreSQL using DATABASE_URL (or DB_* vars), runs a
 * trivial query, and prints a clear PASS/FAIL with the underlying error.
 *
 * Handles the Cloud SQL Unix-socket form:
 *   postgresql://user:pass@localhost/db?host=/cloudsql/PROJECT:REGION:INSTANCE
 * (the `pg` driver needs the socket dir in `host`, not a `socketPath` option).
 *
 * Usage (any of):
 *   node scripts/testDbConnection.mjs                       # uses repo-root .env
 *   node scripts/testDbConnection.mjs 'postgresql://...'    # pass URL as arg
 *   DATABASE_URL='postgresql://...' node scripts/testDbConnection.mjs
 *
 * NOTE: this connects the SAME way the app does, so it only succeeds from an
 * environment that can actually reach the instance (inside the VPC / Cloud Run).
 * From your Mac or Cloud Shell it will ETIMEDOUT against a private-only instance.
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import pg from 'pg';

const { Client } = pg;   // pg is CommonJS — take Client off the default export
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load .env from the repo root regardless of the current working directory,
// so `node scripts/testDbConnection.mjs` works the same as running from scripts/.
dotenv.config({ path: path.join(__dirname, '../.env') });

const TIMEOUT_MS = 10000;

function buildConfig() {
  // Allow passing the connection string as the first CLI arg:
  //   node scripts/testDbConnection.mjs 'postgresql://...'
  const url = process.argv[2] || process.env.DATABASE_URL;

  if (url) {
    const parsed = new URL(url);
    const socketPath = parsed.searchParams.get('host'); // /cloudsql/... when present

    const base = {
      user:     decodeURIComponent(parsed.username),
      password: decodeURIComponent(parsed.password),
      database: parsed.pathname.replace(/^\//, ''),
      connectionTimeoutMillis: TIMEOUT_MS,
    };

    if (socketPath && socketPath.startsWith('/cloudsql/')) {
      // Cloud SQL Unix socket — pg uses `host` as the socket directory.
      return { ...base, host: socketPath, mode: `unix-socket (${socketPath})` };
    }
    // TCP connection string (host:port in the URL authority).
    return {
      ...base,
      host: parsed.hostname,
      port: Number(parsed.port) || 5432,
      ssl:  process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
      mode: `tcp (${parsed.hostname}:${parsed.port || 5432})`,
    };
  }

  // Fallback to discrete DB_* env vars (local dev).
  return {
    host:     process.env.DB_HOST || 'localhost',
    port:     Number(process.env.DB_PORT) || 5432,
    user:     process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl:      process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    connectionTimeoutMillis: TIMEOUT_MS,
    mode:     `tcp (${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 5432})`,
  };
}

// buildConfig() is called in here rather than at module scope so that a malformed
// DATABASE_URL (new URL() throws) is reported by the top-level handler below
// instead of surfacing as a raw unhandled rejection.
async function run() {
  const { mode, ...config } = buildConfig();
  console.log('--- DB connection test ---');
  console.log('Connecting via:', mode);
  console.log('Database:', config.database, '| User:', config.user);

  const client = new Client(config);
  const started = Date.now();

  try {
    await client.connect();
    const { rows } = await client.query(
      'SELECT current_user, current_database(), version() AS pg_version, now() AS server_time'
    );
    console.log(`\n✅ CONNECTED in ${Date.now() - started}ms`);
    console.log(rows[0]);

    // Optional: confirm the app table is reachable.
    try {
      const t = await client.query('SELECT count(*)::int AS n FROM sso_integrations');
      console.log(`sso_integrations rows: ${t.rows[0].n}`);
    } catch (e) {
      console.log('(could not read sso_integrations:', e.message, ')');
    }
  } catch (err) {
    console.error(`\n❌ FAILED after ${Date.now() - started}ms`);
    console.error('code:', err.code || '(none)');
    console.error('message:', err.message);
    process.exitCode = 1;
  } finally {
    await client.end().catch(() => {});
  }
}

// Top-level await (ESM) — matches S7785's compliant form.
try {
  await run();
} catch (error) {
  console.error(error);
  process.exit(1);
}
