require('dotenv').config();

const { logger, requestLogger } = require('./src/config/logger');

// ── Process-level error guards ────────────────────────────────────────────────
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception', { action: 'uncaught_exception', error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Promise Rejection', { action: 'unhandled_rejection', reason: String(reason) });
  process.exit(1);
});

const express        = require('express');
const cors           = require('cors');
const helmet         = require('helmet');
const session        = require('express-session');
const path           = require('node:path');
const swaggerUi      = require('swagger-ui-express');
const swaggerSpec    = require('./src/docs/swagger');
const ssoRoutes      = require('./src/routers/sso.routes');
const errorHandler   = require('./src/middlewares/errorHandler');
const { globalLimiter }  = require('./src/middlewares/rateLimiter');
const { healthCheck }    = require('./src/controllers/health.controller');
const { requireAdminKey } = require('./src/middlewares/adminAuth.middleware');

// PostgreSQL is the sole backend; the startup connection check runs whenever a
// database is configured (an unset DATABASE_URL/DB_HOST is a misconfiguration).
const dbConfigured = !!(process.env.DATABASE_URL || process.env.DB_HOST);

const app = express();

app.set('trust proxy', true);

// ── Security Headers (Helmet) ─────────────────────────────────────────────────
// Sets: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection,
//       Strict-Transport-Security, Content-Security-Policy, etc.
app.use(helmet({
  // Allow cross-origin requests from the SSO admin UI and React client
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  // CSP — tighten as needed per deployment
  contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false,
}));

// ── Health Check — first, no rate limit, no auth ──────────────────────────────
app.get('/health', healthCheck);

// ── API Docs (Swagger UI) ─────────────────────────────────────────────────────
// Available at /api-docs — protected by admin key in production
// JSON spec at /api-docs.json
const swaggerMiddleware = process.env.NODE_ENV === 'production'
  ? [requireAdminKey, swaggerUi.serve, swaggerUi.setup(swaggerSpec)]
  : [swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
      customSiteTitle: 'ZDNA SSO API Docs',
      swaggerOptions: { persistAuthorization: true },
    })];

app.use('/api-docs', swaggerMiddleware);
app.get('/api-docs.json', (req, res) => res.json(swaggerSpec));

// ── Request Logger ────────────────────────────────────────────────────────────
app.use(requestLogger);

// ── Global Rate Limiter ───────────────────────────────────────────────────────
app.use(globalLimiter);

// ── Body Parsers — 50kb limit prevents large payload / DoS attacks ───────────
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

// ── CORS ──────────────────────────────────────────────────────────────────────
// Allowed browser origins come from env, not code:
//   DEFAULT_ORIGINS — baseline origins shared across deployments
//   CLIENT_URL      — this deployment's console origin(s)
// Both are comma-separated; either may be empty. They are merged.
const parseOrigins = (value) =>
  (value || '').split(',').map(o => o.trim()).filter(Boolean);

const allowedOrigins = new Set([
  ...parseOrigins(process.env.DEFAULT_ORIGINS),
  ...parseOrigins(process.env.CLIENT_URL),
]);

// An empty allowlist rejects every browser request with CORS_ERROR — a failure
// that looks like a routing bug from the client side. Say so at startup.
if (allowedOrigins.size === 0) {
  logger.warn('CORS allowlist is empty — all browser origins will be rejected', {
    action: 'cors_allowlist_empty',
  });
}

// SAML callback — skip CORS entirely. Microsoft Entra POSTs the SAML assertion
// here as a cross-origin top-level form submit (Origin: login.microsoftonline.com),
// which is not in the allowlist. CORS doesn't apply to this server-processed POST,
// so the ACS paths must bypass the strict origin check below (which would otherwise
// throw "CORS: origin ... not allowed").
const SAML_ACS_PATHS = ['/auth/callback', '/v1/auth/callback'];
app.use(SAML_ACS_PATHS, cors({ origin: true, credentials: true }));

const strictCors = cors({
  origin: (origin, cb) => {
    // Allow no-origin requests (server-to-server)
    if (!origin || origin === 'null') return cb(null, true);
    if (allowedOrigins.has(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
});

app.use((req, res, next) => {
  // The SAML ACS callback is exempt from the strict origin allowlist.
  if (SAML_ACS_PATHS.includes(req.path)) return next();
  return strictCors(req, res, next);
});

// ── Session ───────────────────────────────────────────────────────────────────
app.use(session({
  secret:            process.env.SESSION_SECRET,
  resave:            true,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge:   600000,
  },
}));

// ── Routes ────────────────────────────────────────────────────────────────────
// v1 versioned routes — new clients use /v1/auth/...
app.use('/v1/auth', ssoRoutes);

// Legacy unversioned routes — backward compatible, kept for existing clients
app.use('/auth', ssoRoutes);

// ── React Frontend is hosted separately ──────────────────────────────────────
// Not served from this microservice.
// Set CLIENT_URL env var to the React app origin for CORS.

// ── Centralised Error Handler ─────────────────────────────────────────────────
app.use(errorHandler);

// ── Start Server + Graceful Shutdown ─────────────────────────────────────────
if (require.main === module) {
  const PORT = process.env.PORT || 5000;

  // ── DB Connection Check — retry with exponential back-off ───────────────────
  // A brief PostgreSQL blip at startup would silently degrade all DB-backed SSO
  // lookups for the lifetime of the instance without retry protection.
  //
  // A named function invoked from the listen callback, rather than a top-level
  // async IIFE (S7785). It is deliberately NOT awaited: the server must accept
  // connections immediately, so this runs in the background once the port is
  // bound. Top-level await is not an option here either — this file is CommonJS
  // and is required by index.js for the Cloud Function.
  const connectWithRetry = async () => {
    const sequelizeCheck = require('./src/config/db');
    const MAX_ATTEMPTS = 5;
    let delay = 1000;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        await sequelizeCheck.authenticate();
        logger.info('Database connected successfully', { action: 'db_connected', attempt });
        return;
      } catch (err) {
        if (attempt === MAX_ATTEMPTS) {
          logger.error('Database connection failed after all retries — DB-backed SSO degraded', {
            action: 'db_connection_failed', error: err.message, attempts: MAX_ATTEMPTS,
          });
          return;
        }
        logger.warn(`DB connect attempt ${attempt}/${MAX_ATTEMPTS} failed — retrying in ${delay}ms`, {
          action: 'db_connect_retry', attempt, delay, error: err.message,
        });
        await new Promise(r => setTimeout(r, delay));
        delay = Math.min(delay * 2, 30000);
      }
    }
  };

  const server = app.listen(PORT, () => {
    logger.info(`SSO Microservice started`, { action: 'server_start', port: PORT, node_env: process.env.NODE_ENV || 'development' });

    // Fire-and-forget once we are accepting connections. connectWithRetry handles
    // its own failures; the .catch is a safety net for anything unexpected (e.g.
    // the db module failing to load) so it can never become an unhandled rejection.
    if (dbConfigured) {
      connectWithRetry().catch((err) =>
        logger.error('DB connection check failed unexpectedly', {
          action: 'db_connect_crashed', error: err.message,
        }));
    }
  });

  // ── Graceful Shutdown ───────────────────────────────────────────────────────
  // On SIGTERM (Cloud Run / process stop):
  //   1. Stop accepting new connections
  //   2. Wait for active requests to finish (max 10s)
  //   3. Close DB connections
  //   4. Exit cleanly
  const shutdown = (signal) => {
    logger.info(`${signal} received — starting graceful shutdown`, { action: 'shutdown_start', signal });

    server.close(async () => {
      logger.info('HTTP server closed — no new connections', { action: 'shutdown_http_closed' });

      // Close DB connection pool
      try {
        const sequelize = require('./src/config/db');
        await sequelize.close();
        logger.info('Database connections closed', { action: 'shutdown_db_closed' });
      } catch (err) {
        logger.warn('DB close error', { action: 'shutdown_db_error', error: err.message });
      }

      logger.info('Graceful shutdown complete', { action: 'shutdown_complete' });
      process.exit(0);
    });

    // Force exit after 10s if requests haven't finished
    setTimeout(() => {
      logger.error('Graceful shutdown timed out — forcing exit', { action: 'shutdown_timeout' });
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
}

module.exports = app;
