/**
 * Request-field normalisers shared by the SSO controllers.
 *
 * Kept in one place so trim / first-domain / lowercase-domain semantics can't
 * drift between domainCheck, testConnection, and saveSsoConfig controllers
 * (previously each redefined `trimStr` / `firstDomain` locally).
 */

// Trim strings; pass non-strings through untouched.
const trimStr = (v) => (typeof v === 'string' ? v.trim() : v);

// The frontend sends `domains` as an array (e.g. ["zebra.com"]); the backend
// works with a single domain string. Take the first entry when it's an array.
const firstDomain = (v) => (Array.isArray(v) ? v[0] : v);

// Trim + unwrap-array + lowercase a domain value (null/undefined-safe).
const trimLowerDomain = (v) => {
  const first = trimStr(firstDomain(v));
  return typeof first === 'string' ? first.toLowerCase() : first;
};

module.exports = { trimStr, firstDomain, trimLowerDomain };
