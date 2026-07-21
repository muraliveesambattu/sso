/**
 * Global Error Handler Middleware
 * Sanitizes all errors before sending to client.
 * Full error details logged server-side only.
 */

const { logger } = require('../config/logger');

const IS_PROD = process.env.NODE_ENV === 'production';

const SAFE_MESSAGES = {
  MISSING_REQUIRED_FIELDS:  'Missing required fields. Please try again.',
  INVALID_STATE:            'Authentication session expired. Please sign in again.',
  SESSION_EXPIRED:          'Authentication session expired. Please sign in again.',
  TOKEN_EXPIRED:            'Your token has expired. Please sign in again.',
  INVALID_NONCE:            'Security validation failed. Please sign in again.',
  JWT_VERIFICATION_FAILED:  'Security validation failed. Please sign in again.',
  JWKS_UNAVAILABLE:         'Sign-in service is temporarily unavailable. Please try again.',
  MISSING_CODE_VERIFIER:    'PKCE session error. Please sign in again.',
  TOKEN_EXCHANGE_FAILED:    'Sign-in failed. Please try again.',
  TENANT_MISMATCH:          'Organisation mismatch. Please contact your administrator.',
  INVALID_ISSUER:           'Token issuer validation failed. Please sign in again.',
  INVALID_AUDIENCE:         'Token audience validation failed. Please sign in again.',
  MISSING_EXPIRATION:       'Invalid token received. Please sign in again.',
  TOKEN_NOT_YET_VALID:      'Invalid token received. Please sign in again.',
  MISSING_ISSUED_AT:        'Invalid token received. Please sign in again.',
  INVALID_ISSUED_AT:        'Invalid token received. Please sign in again.',
  TOKEN_TOO_OLD:            'Token is too old. Please sign in again.',
  INTEGRATION_NOT_FOUND:    'SSO is not configured for your organisation.',
  CONFIG_NOT_FOUND:         'SSO configuration not found. Please contact your administrator.',
  USER_NOT_PROVISIONED:     'Your account is not authorised for SSO access. Please contact your administrator.',
  LOGIN_METHOD_NOT_ALLOWED: 'SSO login is not permitted for this account.',
  MISSING_IDENTITY_CLAIMS:  'Required identity claims are missing. Please contact your administrator.',
  MISSING_EMAIL:            'Your account is missing a required email claim.',
  MISSING_OID:              'Your account is missing a required identifier.',
  FIREBASE_TOKEN_FAILED:    'Failed to complete sign-in. Please try again.',
  MISSING_INPUT:            'Email or domain is required.',
  INVALID_EMAIL:            'Invalid email format.',
  INVALID_DOMAIN:           'Invalid domain format.',
  SAML_LOGIN_FAILED:        'SAML authentication failed. Please try again.',
  MISSING_SESSION:          'Session unavailable. Please try again.',
  DOMAIN_ALREADY_EXISTS:    'This domain is already configured by another organisation.',
  TENANT_ALREADY_REGISTERED: 'This Microsoft Entra tenant ID is already registered by another organisation.',
  INVALID_ROLE_ID:          'One or more selected roles do not exist. Please refresh and try again.',
  MISSING_ROLES:            'At least one role is required.',
  INVALID_MAPPING_SOURCE:   'Unsupported mapping type. Use group, department, jobtitle, role, or default.',
  MISSING_MAPPING_VALUE:    'A value to match against is required for this mapping type.',
  JIT_NO_MATCHING_ROLE:     'Your account is not assigned a role for SSO access. Please contact your administrator.',
  GRAPH_PROFILE_FETCH_FAILED: 'Unable to verify your profile with Microsoft. Please try again.',
  MISSING_ID_TOKEN:         'Authentication required. Please sign in and try again.',
  INVALID_ID_TOKEN:         'Your session is invalid or expired. Please sign in again.',
  INSUFFICIENT_PERMISSIONS: 'You do not have permission to perform this action.',
  COMPANY_SCOPE_VIOLATION:  'You may only manage your own organisation.',
  USER_ALREADY_EXISTS:      'A user with this email already exists.',
  USER_NOT_FOUND:           'User not found.',
  AUTH_NOT_CONFIGURED:      'Authentication service unavailable. Please contact your administrator.',
};

const getSafeMessage = (code, originalMessage) => {
  if (code && SAFE_MESSAGES[code]) return SAFE_MESSAGES[code];
  if (!IS_PROD) return originalMessage || 'Internal Server Error';
  return 'An unexpected error occurred. Please try again.';
};

const isSequelizeError = (err) =>
  err?.name?.startsWith('Sequelize') || err?.constructor?.name?.startsWith('Sequelize');

const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || err.status || 500;
  const errCode    = err.code || 'INTERNAL_ERROR';

  // Sequelize errors
  if (isSequelizeError(err)) {
    logger.error('Database error', { action: 'db_error', name: err.name, error: err.message, path: req.path });
    return res.status(500).json({
      success: false,
      error: { code: 'DATABASE_ERROR', message: IS_PROD ? 'A database error occurred. Please try again.' : err.message },
    });
  }

  // CORS errors
  if (err.message?.startsWith('CORS:')) {
    return res.status(403).json({
      success: false,
      error: { code: 'CORS_ERROR', message: 'Request origin not allowed.' },
    });
  }

  // Operational errors (4xx)
  if (statusCode < 500) {
    logger.warn('Operational error', { action: 'operational_error', code: errCode, status: statusCode, method: req.method, path: req.path });
    return res.status(statusCode).json({
      success: false,
      error: { code: errCode, message: getSafeMessage(errCode, err.message) },
    });
  }

  // Unexpected errors (5xx) — full details in logs, sanitized to client
  logger.error('Unexpected error', { action: 'unexpected_error', code: errCode, error: err.message, method: req.method, path: req.path, stack: err.stack });

  return res.status(500).json({
    success: false,
    error: {
      code:    errCode,
      message: getSafeMessage(errCode, err.message),
      ...(IS_PROD ? {} : { stack: err.stack }),
    },
  });
};

module.exports = errorHandler;
