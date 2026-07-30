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
        privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replaceAll('\\n', '\n'),
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

// zdna_roles.permissions is JSONB in Postgres but may arrive as a string from
// the raw driver — normalise to an array.
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

/**
 * Mirrors the native login's per-user permission provisioning
 * (zdna-functions: updatePermission → tenants/{tenantId}/users/{uId}/
 * userPermissions/permissionList). The console's getPermissions() reads this
 * exact doc to enforce feature access (deny-list on `noaccess` entries). SSO
 * users never had it written, so every SSO login fell through to default-allow
 * (full access) regardless of assigned role — this closes that gap.
 *
 * Best-effort: a Firestore failure must never block the login/token issuance.
 *
 * @param {string} companyId   ZDNA company/tenant id (Firestore `tenants` doc)
 * @param {string} uId         SSO user's Firebase uid (= zdnaTenantId)
 * @param {Array}  permissions RMS-resolved permission array [{permissionString, permissionId}, ...]
 */
const writeUserPermissions = async (companyId, uId, permissions) => {
  if ((!FIREBASE_CONFIGURED && !RUNNING_IN_FIREBASE) || !companyId || !uId) return;
  try {
    await admin.firestore()
      .collection('tenants').doc(String(companyId))
      .collection('users').doc(String(uId))
      .collection('userPermissions').doc('permissionList')
      .set({ permissions: Array.isArray(permissions) ? permissions : [] });
    logger.debug(`[FIREBASE] Wrote userPermissions/permissionList | tenant: ${companyId} | uid: ${uId} | count: ${Array.isArray(permissions) ? permissions.length : 0}`);
  } catch (err) {
    logger.warn(`[FIREBASE] Failed to write userPermissions doc (non-fatal) | tenant: ${companyId} | uid: ${uId} | ${err.message}`);
  }
};

// Canonical role-config translation, mirroring zdna-functions
// transformPermissions. A role's Firestore config stores per-feature access
// levels ({'My Services':'No Access', ...}); the console enforces on
// permissionString entries. This converts one into the other so SSO users can
// inherit their JIT-assigned role's permissions WITHOUT a per-user RMS mapping.
const FEATURE_PREFIX = {
  'My Devices': 'zdna.myDevice',
  'New Device Setup': 'zdna.initialSetupNew',
  'Design Studio': 'zdna.designStudio',
  'Users': 'zdna.userManagement',
  'Device Settings': 'zdna.deviceSettings',
  'Licensing': 'zdna.licensing',
  'Android Updates': 'zdna.androidUpdates',
  'Device Users': 'zdna.deviceUsers',
  'My Apps': 'zdna.myApps',
  'Roles': 'zdna.roleManagement',
  'My Services': 'zdna.myServices',
  'My Profile': 'zdna.userProfile',
  'Remote Rxlogger': 'zdna.remoteRxLogger',
  'Profile Dependency': 'zdna.profileDependency',
};
const LEVEL_ACTION = {
  'Editable': 'edit',
  'View Only': 'view',
  'No Access': 'noaccess',
  'View With Remote Control': 'remotesupport.edit',
};

// permObj: { 'My Services': 'No Access', ... } → [{permissionString: 'zdna.all'}, {permissionString: 'zdna.myServices.noaccess'}, ...]
// Enforcement only reads permissionString (not permissionId), so we omit ids.
const transformRolePermissions = (permObj = {}) => ([
  { permissionString: 'zdna.all' },
  ...Object.entries(permObj)
    .filter(([feature, level]) => FEATURE_PREFIX[feature] && LEVEL_ACTION[level])
    .map(([feature, level]) => ({ permissionString: `${FEATURE_PREFIX[feature]}.${LEVEL_ACTION[level]}` })),
]);

/**
 * Reads a role's permission matrix from the tenant's Firestore roleConfig and
 * returns it in the permissionString format the console enforces on. Lets an
 * SSO user inherit their JIT-assigned role's permissions with NO per-user RMS
 * mapping. Best-effort: returns [] on any failure.
 *
 * @param {string} companyId  tenant id (Firestore `tenants` doc)
 * @param {string} roleName   the assigned role's display name (e.g. "Manager")
 * @returns {Promise<Array<{permissionString:string}>>}
 */
const getRolePermissionStrings = async (companyId, roleName) => {
  if ((!FIREBASE_CONFIGURED && !RUNNING_IN_FIREBASE) || !companyId || !roleName) return [];
  try {
    const snap = await admin.firestore()
      .collection('tenants').doc(String(companyId))
      .collection('tenantConfig').doc('roleConfig')
      .collection('roleConfig')
      .where('roleName', '==', roleName).limit(1).get();
    if (snap.empty) {
      logger.info(`[FIREBASE] No roleConfig doc for role "${roleName}" | tenant: ${companyId}`);
      return [];
    }
    const perms = transformRolePermissions(snap.docs[0].data()?.permissions || {});
    logger.info(`[FIREBASE] Derived ${perms.length} permissions from roleConfig | role: ${roleName} | tenant: ${companyId}`);
    return perms;
  } catch (err) {
    logger.warn(`[FIREBASE] roleConfig permission read failed (non-fatal) | role: ${roleName} | tenant: ${companyId} | ${err.message}`);
    return [];
  }
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
    // Permissions come pre-resolved from permissionResolver (RMS → Firestore
    // roleConfig); there is no local role table to fall back to.
    const fullPermissions = Array.isArray(claims.permissions) ? claims.permissions : [];

    // Provision the per-user Firestore permission doc the console reads for
    // feature enforcement — the FULL list (not the token-truncated copy).
    // Awaited so it lands before the console's post-login getPermissions read,
    // but best-effort: writeUserPermissions never throws.
    await writeUserPermissions(claims.companyId, zdnaTenantId, fullPermissions);

    let zdnaPermissions = fullPermissions;

    // Firebase custom-token claims share a ~1KB budget. If the permission list
    // would blow it, mint a marker instead — the frontend fetches the full set
    // from GET /sso/me.
    let zdnaPermissionsRef;
    if (JSON.stringify(zdnaPermissions).length > 800) {
      logger.warn(`[FIREBASE] zdnaPermissions too large for token claims — deferring to /sso/me | uid: ${zdnaTenantId}`);
      zdnaPermissions    = [];
      zdnaPermissionsRef = 'me';
    }

    const additionalClaims = {
      email:       claims.email,
      // The console's Firestore rules gate tenant reads via isUser()/isAdmin():
      //   role ∈ {"Tenant Owner","Administrative User"} AND identity/uid == <tenantId>.
      // Native logins satisfy this by minting role "Tenant Owner" with identity ==
      // the tenant. SSO must match the same gate, or every tenant read is denied
      // regardless of zdnaPermissions (the rules never inspect those). The real
      // ZDNA role stays in zdnaRoles, and feature-level access is still enforced
      // in-app via zdnaPermissions.
      role:        'Tenant Owner',
      tenantId:    zdnaTenantId,        // ZDNA user_id (unique per user; unchanged)
      identity:    claims.companyId,    // tenant id — required by Firestore isUser() and the AuthProvider ADMIN path
      loginType:   'entra',             // distinguishes from PingFederate (v2)
      companyId:   claims.companyId,
      displayName: claims.displayName || '',
      // Full RBAC picture — `role` above only carries roles[0] and gets
      // remapped by the console's AuthProvider; these two claims preserve
      // every resolved role + their permissions.
      zdnaRoles:       roles.map(r => ({ id: r.role_id, name: r.role_name })),
      zdnaPermissions,
      ...(zdnaPermissionsRef ? { zdnaPermissionsRef } : {}),
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

module.exports = { generateCustomToken, verifyIdToken, writeUserPermissions, getRolePermissionStrings, transformRolePermissions };
