const rateLimit = require('express-rate-limit');
const { logger } = require('../config/logger');

// Domain check rate limiter - prevents brute force domain enumeration
const domainCheckLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute per IP
  message: {
    success: false,
    error: 'Too many domain check requests. Please try again later.',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', {
      action: 'rate_limit_exceeded',
      ip: req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip,
      endpoint: '/api/sso/domain-check',
    });

    res.status(429).json({
      success: false,
      error: 'Too many domain check requests. Please try again later.',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: 60
    });
  }
});

// SAML callback rate limiter - prevents replay attacks
const samlCallbackLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // 20 requests per 5 minutes per IP
  message: {
    success: false,
    error: 'Too many login attempts. Please try again later.',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', {
      action: 'rate_limit_exceeded',
      ip: req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip,
      endpoint: '/api/sso/saml/callback',
    });

    res.status(429).json({
      success: false,
      error: 'Too many login attempts. Please try again later.',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: 300
    });
  }
});

// Global API rate limiter - protects all endpoints
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per 15 minutes per IP
  message: {
    success: false,
    error: 'Too many requests. Please try again later.',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false }
});

module.exports = {
  domainCheckLimiter,
  samlCallbackLimiter,
  globalLimiter
};
