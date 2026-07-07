/**
 * Firebase Admin SDK — Custom Token Generator
 *
 * Initialises the Admin SDK once using a service account.
 * Used after successful Entra OIDC/SAML authentication to issue
 * a Firebase Custom Token that MDNA-Console can consume via
 * signInWithCustomToken().
 *
 * Environment variables required:
 *   FIREBASE_PROJECT_ID      — Firebase project ID
 *   FIREBASE_CLIENT_EMAIL    — Service account email
 *   FIREBASE_PRIVATE_KEY     — Service account private key (PEM, \n escaped)
 */

const admin = require('firebase-admin');
const { logger } = require('../../config/logger');

const FIREBASE_CONFIGURED =
  process.env.FIREBASE_PROJECT_ID &&
  process.env.FIREBASE_CLIENT_EMAIL &&
  process.env.FIREBASE_PRIVATE_KEY;

const RUNNING_IN_FIREBASE =
  process.env.FIREBASE_CONFIG ||
  process.env.FUNCTIONS_EMULATOR ||
  process.env.GCLOUD_PROJECT;

// Initialise once — guard against hot-reload double-init
if (!admin.apps.length) {
  if (RUNNING_IN_FIREBASE) {
    admin.initializeApp();
    logger.debug('[FIREBASE] Admin SDK auto-initialised (running in Firebase environment)');
  } else if (FIREBASE_CONFIGURED) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId:   process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
      }),
    });
    logger.debug('[FIREBASE] Admin SDK initialised using service account certificate');
  } else {
    logger.warn('[FIREBASE] WARNING: Firebase credentials not set — running in DEV mock mode');
  }
}

/**
 * Generates a Firebase Custom Token for an Entra-authenticated user.
 *
 * @param {string} zdnaTenantId   - ZDNA user_id — used as the Firebase UID
 * @param {object} claims
 * @param {string} claims.email
 * @param {string} claims.role
 * @param {string} claims.companyId
 * @param {string} claims.displayName
 * @param {Array<{role_id: string, role_name: string, permissions?: Array|string}>} [claims.roles]
 *                 Full resolved role rows — minted as zdnaRoles/zdnaPermissions
 *                 so consumers (frontend, Firestore rules) see ALL roles, not
 *                 just the flattened `role` (= roles[0]) kept for compatibility.
 * @returns {Promise<string>}     Firebase custom token (JWT)
 */

// zdna_roles.permissions is JSON in Postgres but may arrive as a string from
// the JSON store or raw driver — normalise to an array.
const toPermissionArray = (value) => {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
};
const generateCustomToken = async (zdnaTenantId, claims) => {
  try {
    logger.debug(`[FIREBASE] Generating custom token | uid (zdnaTenantId): ${zdnaTenantId} | email: ${claims.email} | role: ${claims.role}`);

    // ── DEV MOCK MODE ─────────────────────────────────────────────────────────
    // Firebase credentials not set and not in Firebase env — return a mock token for testing
    if (!FIREBASE_CONFIGURED && !RUNNING_IN_FIREBASE) {
      const mockToken = `dev-mock-token::${zdnaTenantId}::${claims.email}::${Date.now()}`;
      logger.warn(`[FIREBASE] DEV MODE: Returning mock token — ${mockToken}`);
      return mockToken;
    }

    // ── PRODUCTION ────────────────────────────────────────────────────────────
    const roles = Array.isArray(claims.roles) ? claims.roles : [];
    const zdnaPermissions = [...new Set(roles.flatMap(r => toPermissionArray(r.permissions)))];

    const additionalClaims = {
      email:       claims.email,
      role:        claims.role        || 'user',
      tenantId:    zdnaTenantId,      // ZDNA user_id
      identity:    zdnaTenantId,      // required by AuthProvider for ADMIN_PERMISSION_TYPE path
      loginType:   'entra',           // distinguishes from PingFederate (v2)
      companyId:   claims.companyId,
      displayName: claims.displayName || '',
      // Full RBAC picture — `role` above only carries roles[0] and gets
      // remapped by the console's AuthProvider; these two claims preserve
      // every resolved role + the union of their zdna_roles permissions.
      zdnaRoles:       roles.map(r => ({ id: r.role_id, name: r.role_name })),
      zdnaPermissions,
    };

    const customToken = await admin.auth().createCustomToken(zdnaTenantId, additionalClaims);
    logger.debug(`[FIREBASE] Custom token generated successfully | uid: ${zdnaTenantId}`);
    return customToken;

  } catch (err) {
    logger.error(`[FIREBASE] ERROR: Failed to generate custom token | uid: ${zdnaTenantId} | ${err.message}`);
    const error = new Error(`Firebase custom token generation failed: ${err.message}`);
    error.statusCode = 500;
    error.code = 'FIREBASE_TOKEN_FAILED';
    throw error;
  }
};

/**
 * Verifies a Firebase ID token (sent by the console as `Authorization: Bearer`).
 * Central wrapper so middleware never touches the Admin SDK directly.
 *
 * @param {string} idToken
 * @returns {Promise<object>} decoded token claims (uid, email, companyId, role, …)
 * @throws statusCode 503 AUTH_NOT_CONFIGURED when the Admin SDK has no credentials
 */
const verifyIdToken = async (idToken) => {
  if (!FIREBASE_CONFIGURED && !RUNNING_IN_FIREBASE) {
    const err = new Error('Firebase Admin SDK not configured — cannot verify ID tokens');
    err.statusCode = 503;
    err.code = 'AUTH_NOT_CONFIGURED';
    throw err;
  }
  return admin.auth().verifyIdToken(idToken);
};

module.exports = { generateCustomToken, verifyIdToken };
