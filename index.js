require('dotenv').config();
const { onRequest } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const app = require('./server');

// Secrets pulled from Google Secret Manager, injected into process.env at runtime.
// NOTE: DATABASE_URL is deliberately NOT a secret here — it is set as a plain
// env var on the Cloud Run service (a secret binding conflicted with the env var
// and broke deploys). Only these three are managed as secrets.
const ENCRYPTION_KEY = defineSecret('ENCRYPTION_KEY');
const ADMIN_API_KEY  = defineSecret('ADMIN_API_KEY');
const SESSION_SECRET = defineSecret('SESSION_SECRET');

// Export the Express app as a Cloud Function named 'sso'
// cors: false — Express handles CORS with credentials support
// invoker: 'public' — allows unauthenticated requests including SAML POST callbacks
exports.sso = onRequest({
  cors: false,
  invoker: 'public',
  secrets: [ENCRYPTION_KEY, ADMIN_API_KEY, SESSION_SECRET],
  memory: '1GiB',
  timeoutSeconds: 300,
  cpu: 2,
  maxInstances: 10,
  minInstances: 1,
}, app);
