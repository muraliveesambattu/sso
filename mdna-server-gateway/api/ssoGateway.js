/*
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
SSO Gateway
Single point of communication between MDNA Console and the SSO Microservice
for all ADMIN operations (config CRUD, test-connection, feature flags).

- Verifies the console user's Firebase ID token (same check as other
  console-facing functions), then forwards the request to the SSO
  microservice with the X-Admin-API-Key attached server-side. The admin
  key never reaches the browser.

- Login/browser-flow endpoints (/auth/domain-check, /auth/oidc/callback,
  /auth/oidc/token-exchange, /auth/callback [SAML ACS],
  /auth/test-connection/oidc/callback) are NOT routed here by design:
  their callers are either not-yet-authenticated users mid-login or
  Microsoft Entra itself, so they call the SSO service directly and are
  protected by rate limits, state/nonce and SAML signature validation.

Belongs in: MDNA-Server/CloudFunctions/functions/api/ssoGateway.js
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
const { onRequest } = require('firebase-functions/v2/https')
const axios = require('axios')
const { log } = require('firebase-functions/logger')
const { createExpressApp } = require('../util/commonUtil')
const { isAuthenticatedHSTS } = require('../service/validatorService')
const { STATUS } = require('../util/constant')   // isAuthenticatedHSTS returns { status: STATUS.SUCCESS | STATUS.ERROR }

// Both values come from env/application.properties.js (per environment).
// SSO_BASE_URL e.g. https://sso-323173671147.us-central1.run.app
const SSO_BASE_URL = process.env.SSO_BASE_URL
const SSO_ADMIN_API_KEY = process.env.SSO_ADMIN_API_KEY

// Admin surface of the SSO microservice — the ONLY routes this gateway serves.
// Covers both the /auth and /v1/auth mounts of the microservice router.
const ALLOWED_PREFIXES = [
    '/auth/sso',              // POST /sso/save, GET /sso/config,
    '/v1/auth/sso',           // PATCH /sso/config/:id/status, DELETE /sso/config/:id
    '/auth/test-connection',  // POST — admin "Test Connection" trigger
    '/v1/auth/test-connection',
    '/auth/admin/flags',      // GET /admin/flags/:company_id, POST /admin/flags
    '/v1/auth/admin/flags'
]

// The test-connection OIDC callback is public (Entra redirect target) and
// must not be reachable through the authenticated gateway.
const BLOCKED_PATHS = ['/auth/test-connection/oidc/callback', '/v1/auth/test-connection/oidc/callback']

const app = createExpressApp('ssoGatewayApp')

// Lightweight liveness probe — no auth, no proxying. Lets smoke tests and
// monitoring verify the gateway is up (and that req.path is unprefixed) without
// needing a token.
app.get('/gateway/health', (req, res) => {
    return res.status(200).json({ success: true, service: 'sso-gateway' })
})

app.all('*', async (req, res) => {
    // 1. Route allowlist — anything not on the admin surface is not served here.
    const allowed = ALLOWED_PREFIXES.some((p) => req.path.startsWith(p))
    const blocked = BLOCKED_PATHS.some((p) => req.path.startsWith(p))
    if (!allowed || blocked) {
        log('INFO', 'Inside ssoGateway, unknown route rejected: ' + req.path)
        return res.status(404).json({ success: false, error: { code: 'UNKNOWN_ROUTE' } })
    }

    // 2. Caller must be a signed-in console user (Firebase ID token).
    //    NOTE: isAuthenticatedHSTS ALWAYS resolves — it never throws — returning
    //    { status: STATUS.SUCCESS } on a valid token or { status: STATUS.ERROR }
    //    otherwise. So we must test the status explicitly; a truthy object is NOT
    //    proof of authentication. Without this the admin key would be attached
    //    for anonymous callers.
    const authResult = await isAuthenticatedHSTS(req.headers.authorization)
    if (!authResult || authResult.status !== STATUS.SUCCESS) {
        log('ERROR', 'Inside ssoGateway, caller not authenticated')
        return res.status(401).json({ success: false, error: { code: 'UNAUTHENTICATED' } })
    }

    // 3. Proxy to the SSO microservice with the admin key attached.
    try {
        const response = await axios({
            method: req.method,
            url: SSO_BASE_URL + req.originalUrl,   // originalUrl keeps path + query string
            headers: {
                'Content-Type': 'application/json',
                'X-Admin-API-Key': SSO_ADMIN_API_KEY,
                // isAuthenticatedHSTS does not return the decoded identity, so we
                // can't forward the user's email here. Use isAuthenticatedHSTSCheck
                // (with a userId) if per-user audit attribution is needed later.
                'X-Forwarded-User': 'console-user'
            },
            data: ['GET', 'HEAD', 'DELETE'].includes(req.method) ? undefined : req.body,
            timeout: 30000,
            validateStatus: () => true   // relay SSO service statuses (4xx/5xx) as-is
        })
        log('INFO', 'Inside ssoGateway, proxied ' + req.method + ' ' + req.path + ' -> ' + response.status)
        return res.status(response.status).json(response.data)
    } catch (err) {
        log('ERROR', 'Inside ssoGateway, upstream unreachable: ' + err.message)
        return res.status(502).json({ success: false, error: { code: 'UPSTREAM_UNREACHABLE' } })
    }
})

module.exports.ssoGateway = onRequest(app)
