/**
 * Winston Logger
 *
 * Structured JSON logging for production (GCP Cloud Logging compatible).
 * Human-readable colorised output for development.
 *
 * Log levels: error > warn > info > http > debug
 *
 * PII masking: email addresses and OIDs are masked in production logs.
 *
 * Usage:
 *   const logger = require('./logger');
 *   logger.info('Domain check', { domain: 'gmail-local.com', company_id: '...' });
 *   logger.error('Token exchange failed', { code: 'TOKEN_EXPIRED', ip: req.ip });
 */

const { createLogger, format, transports } = require('winston');

const IS_PROD = process.env.NODE_ENV === 'production';
const LOG_LEVEL = process.env.LOG_LEVEL || (IS_PROD ? 'info' : 'debug');

// ── PII Masking ───────────────────────────────────────────────────────────────
// Mask email and OID fields in production to protect user privacy
const maskPii = format((info) => {
  if (!IS_PROD) return info;
  if (info.email)   info.email   = maskEmail(info.email);
  if (info.oid)     info.oid     = '***masked***';
  if (info.message) info.message = info.message
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[email]');
  return info;
});

const maskEmail = (email) => {
  if (!email || typeof email !== 'string') return email;
  const [local, domain] = email.split('@');
  if (!domain) return '***@***';
  return `${local[0]}***@${domain}`;
};

// ── GCP Cloud Logging compatible format ──────────────────────────────────────
const gcpFormat = format.combine(
  maskPii(),
  format.timestamp(),
  format.errors({ stack: true }),
  format.json()
);

// ── Human-readable dev format ─────────────────────────────────────────────────
const devFormat = format.combine(
  format.colorize(),
  format.timestamp({ format: 'HH:mm:ss' }),
  format.errors({ stack: true }),
  format.printf(({ level, message, timestamp, ...meta }) => {
    const metaStr = Object.keys(meta).length
      ? ' ' + JSON.stringify(meta)
      : '';
    return `${timestamp} [${level}] ${message}${metaStr}`;
  })
);

// ── Transports ────────────────────────────────────────────────────────────────
const logTransports = [
  new transports.Console({
    format:     IS_PROD ? gcpFormat : devFormat,
    handleExceptions: true,
    handleRejections: true,
  }),
];

// File transport for production (daily rotation)
if (IS_PROD) {
  const DailyRotateFile = require('winston-daily-rotate-file');
  logTransports.push(
    new DailyRotateFile({
      filename:     'logs/sso-%DATE%.log',
      datePattern:  'YYYY-MM-DD',
      maxSize:      '20m',
      maxFiles:     '14d',
      format:       gcpFormat,
      zippedArchive: true,
    })
  );
}

// ── Create logger ─────────────────────────────────────────────────────────────
const logger = createLogger({
  level:             LOG_LEVEL,
  defaultMeta:       { service: 'zdna-sso' },
  transports:        logTransports,
  exitOnError:       false,
});

// Map an HTTP status code to a log level.
const levelForStatus = (statusCode) => {
  if (statusCode >= 500) return 'error';
  if (statusCode >= 400) return 'warn';
  return 'http';
};

// ── HTTP request logger middleware ────────────────────────────────────────────
const requestLogger = (req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = levelForStatus(res.statusCode);
    logger.log(level, 'HTTP', {
      method:   req.method,
      path:     req.path,
      status:   res.statusCode,
      ms:       duration,
      ip:       req.ip,
    });
  });
  next();
};

module.exports = { logger, requestLogger };
