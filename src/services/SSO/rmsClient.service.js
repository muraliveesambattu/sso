/**
 * RMS Client — Role Management System (user-centric permission authority)
 *
 * Mirrors the calling convention of zdna-functions/api/roleManagement.js
 * checkUserExistInRMS → getUserInfoFromRms, so our SSO service speaks to the
 * SAME RMS the Phoenix login path uses:
 *
 *   1. Bearer token from the OAuth endpoint (GET, static Authorization key),
 *      cached in memory until shortly before expiry.
 *   2. POST {ROLE_MANAGEMENT_SERVICE_URL}/user
 *        headers: Authorization: Bearer <token>, zuid: <user key>, Origin: {DNS_URL}
 *        body:    { email }
 *      User exists ⇔ response head['sub-code'] === 3004
 *        → permissions = data.rolesArr[0].permissionsArr, roleName
 *
 * Env (all required for the client to activate):
 *   ROLE_MANAGEMENT_SERVICE_URL   — RMS base URL (zdna-functions name kept)
 *   RMS_OAUTH_TOKEN_URL           — OAuth token endpoint (zdna-functions: OAUTH_TOKEN)
 *   RMS_OAUTH_AUTHORIZATION_KEY   — static Authorization header for the token call
 *   DNS_URL                       — Origin header RMS expects
 *   RMS_TIMEOUT_MS                — per-request timeout (default 3000)
 *
 * NOTE (pending team confirmation): the `zuid` header for Entra-born users.
 * Phoenix resolves it via getZuIdByEmail (LGE); until RMS confirms what it
 * accepts for SSO users we send the Entra oid — one line to change below.
 */

const { logger } = require('../../config/logger');

const timeoutMs = () => Number.parseInt(process.env.RMS_TIMEOUT_MS || '3000', 10);

const isRmsConfigured = () =>
  !!(process.env.ROLE_MANAGEMENT_SERVICE_URL &&
     process.env.RMS_OAUTH_TOKEN_URL &&
     process.env.RMS_OAUTH_AUTHORIZATION_KEY);

const fetchWithTimeout = async (url, options) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs());
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
};

// ── OAuth token (in-memory cache; zdna-functions caches the same token in
//    Firestore — per-instance memory is enough for our call volume) ───────────
let tokenCache = { token: null, expiresAt: 0 };

const getRmsToken = async () => {
  if (tokenCache.token && Date.now() < tokenCache.expiresAt) return tokenCache.token;

  const res = await fetchWithTimeout(process.env.RMS_OAUTH_TOKEN_URL, {
    method:  'GET',
    headers: { Authorization: process.env.RMS_OAUTH_AUTHORIZATION_KEY },
  });
  if (!res.ok) throw new Error(`RMS OAuth token endpoint responded HTTP ${res.status}`);
  const data = await res.json();
  if (!data.access_token) throw new Error('RMS OAuth response missing access_token');

  // Refresh 60s before actual expiry — same safety margin zdna-functions uses
  tokenCache = {
    token:     data.access_token,
    expiresAt: Date.now() + (Number(data.expires_in || 300) - 60) * 1000,
  };
  return tokenCache.token;
};

// Test hook — never call from production code
const __resetRmsTokenCache = () => { tokenCache = { token: null, expiresAt: 0 }; };

// ── User permission lookup ────────────────────────────────────────────────────

/**
 * @param {{ email: string, userKey: string }} params
 *        userKey → sent as the `zuid` header (Entra oid until RMS confirms)
 * @returns {Promise<{found: boolean, permissions?: string[], roleName?: string}>}
 */
const fetchUserPermissionsFromRms = async ({ email, userKey }) => {
  const token   = await getRmsToken();
  const baseUrl = process.env.ROLE_MANAGEMENT_SERVICE_URL.replace(/\/$/, '');

  const res = await fetchWithTimeout(`${baseUrl}/user`, {
    method:  'POST',
    headers: {
      Authorization:  `Bearer ${token}`,
      'Content-Type': 'application/json',
      zuid:           userKey,
      Origin:         process.env.DNS_URL || '',
    },
    body: JSON.stringify({ email }),
  });
  if (!res.ok) {
    // Capture RMS's error body — the status alone doesn't say WHY it failed
    // (wrong zuid, unknown user, bad Origin, …). res is a raw fetch Response.
    const bodyText = await res.text().catch(() => '<unreadable>');
    logger.warn(`RMS /user HTTP ${res.status} body >> ${bodyText}`, { action: 'rms_user_http_error', status: res.status });
    throw new Error(`RMS /user responded HTTP ${res.status}`);
  }
  const payload = await res.json();

  // Contract from zdna-functions getUserDetailsMS: 3004 ⇔ user present
  if (payload?.head?.['sub-code'] !== 3004) {
    logger.info('RMS does not know this user — permission fallback applies', {
      action: 'rms_user_not_found',
    });
    return { found: false };
  }

  const firstRole = payload?.data?.rolesArr?.[0] || {};
  return {
    found:       true,
    permissions: Array.isArray(firstRole.permissionsArr) ? firstRole.permissionsArr : [],
    roleName:    firstRole.roleName || '',
  };
};

module.exports = { isRmsConfigured, fetchUserPermissionsFromRms, __resetRmsTokenCache };
