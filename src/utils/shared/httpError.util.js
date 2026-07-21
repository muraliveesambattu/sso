/**
 * createHttpError — single builder for an Error that carries an HTTP statusCode
 * and a stable machine-readable `code`, so the repeated
 *   const err = new Error(msg); err.statusCode = s; err.code = c; throw err;
 * pattern doesn't get duplicated across services and validators. The global
 * errorHandler maps `code` → a safe client message and `statusCode` → the HTTP
 * response status.
 *
 * @param {string} message      developer-facing message (logged server-side)
 * @param {number} statusCode   HTTP status to return
 * @param {string} code         stable error code (see errorHandler SAFE_MESSAGES)
 * @param {Error}  [cause]       optional underlying error
 * @returns {Error}
 */
const createHttpError = (message, statusCode, code, cause) => {
  const err = new Error(message);
  err.statusCode = statusCode;
  err.code = code;
  if (cause !== undefined) err.cause = cause;
  return err;
};

module.exports = { createHttpError };
