const { Sequelize } = require('sequelize');
require('dotenv').config();

const IS_PROD = process.env.NODE_ENV === 'production';

// ── Connection Pool ───────────────────────────────────────────────────────────
// Sized for Cloud Run (default concurrency: 80 req/instance)
const pool = {
  min:     2,
  max:     IS_PROD ? 20 : 5,
  acquire: 30000,  // 30s — max wait for a free connection
  idle:    10000,  // 10s — release idle connections
};

// ── Parse DATABASE_URL for Cloud SQL Unix socket ──────────────────────────────
// Cloud Run + Cloud SQL format:
//   postgresql://user:pass@localhost/sso_db?host=/cloudsql/PROJECT:REGION:INSTANCE
//
// The socket directory is parsed from the `host` query param and passed to the
// `pg` driver as the Sequelize `host` (pg uses `host` for Unix sockets).
const getCloudSqlSocketPath = (databaseUrl) => {
  try {
    const url = new URL(databaseUrl);
    const socketPath = url.searchParams.get('host');
    return socketPath?.startsWith('/cloudsql/') ? socketPath : null;
  } catch {
    return null;
  }
};

// ── Dialect Options ───────────────────────────────────────────────────────────
// NOTE: the `pg` driver does NOT support `socketPath` (that's a mysql2 option).
// For a Cloud SQL Unix socket, the socket directory must be passed as `host`
// (see the Sequelize construction below). These dialectOptions only carry the
// timeouts and the TCP-mode SSL flag.
const buildDialectOptions = (socketPath) => ({
  statement_timeout:                    10000,  // 10s max query time
  idle_in_transaction_session_timeout:  30000,  // 30s max idle transaction
  ...(socketPath
    // Cloud SQL Unix socket — socket dir is set via `host`, not here.
    ? {}
    // TCP — used locally
    : {
        ssl: process.env.DB_SSL === 'true'
          // Validate the server cert by default; only skip when an operator
          // explicitly opts in (self-signed local/test certs). A custom CA can
          // be supplied via DB_SSL_CA instead of disabling validation entirely.
          ? {
              require: true,
              rejectUnauthorized: process.env.DB_SSL_ALLOW_SELF_SIGNED !== 'true',
              ...(process.env.DB_SSL_CA ? { ca: process.env.DB_SSL_CA } : {}),
            }
          : false,
      }
  ),
});

// ── Sequelize instance ────────────────────────────────────────────────────────
let sequelize;

if (process.env.DATABASE_URL) {
  const socketPath = getCloudSqlSocketPath(process.env.DATABASE_URL);
  if (socketPath) {
    // Cloud SQL Unix socket. The `pg` driver connects via a Unix socket when
    // `host` is the socket directory (/cloudsql/PROJECT:REGION:INSTANCE). The
    // `@localhost` authority and `?host=` query param in the URL are NOT honoured
    // by Sequelize's URL parser, so build from discrete credentials and set the
    // host explicitly to the socket path.
    const url = new URL(process.env.DATABASE_URL);
    sequelize = new Sequelize(
      url.pathname.replace(/^\//, ''),               // database name
      decodeURIComponent(url.username),
      decodeURIComponent(url.password),
      {
        host:           socketPath,                  // pg: Unix socket directory
        dialect:        'postgres',
        logging:        false,
        pool,
        dialectOptions: buildDialectOptions(socketPath),
      }
    );
  } else {
    // TCP connection string (e.g. private-IP host:port).
    sequelize = new Sequelize(process.env.DATABASE_URL, {
      dialect:        'postgres',
      logging:        false,
      pool,
      dialectOptions: buildDialectOptions(null),
    });
  }
} else {
  sequelize = new Sequelize(
    process.env.DB_NAME,
    process.env.DB_USER,
    process.env.DB_PASSWORD,
    {
      host:           process.env.DB_HOST     || 'localhost',
      port:           Number(process.env.DB_PORT) || 5432,
      dialect:        'postgres',
      logging:        false,
      pool,
      dialectOptions: buildDialectOptions(null),
    }
  );
}

module.exports = sequelize;
