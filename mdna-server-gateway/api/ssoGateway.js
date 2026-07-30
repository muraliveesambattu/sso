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

// Parsed once at cold start rather than on every request. If SSO_BASE_URL is
// missing or malformed, SSO_BASE stays null, SSO_ALLOWED_HOSTS is empty, and
// every proxy attempt fails closed on the host check below.
const parseBaseUrl = (raw) => {
    try {
        return new URL(raw)
    } catch (err) {
        log('ERROR', 'Inside ssoGateway, SSO_BASE_URL is missing or malformed: ' + err.message)
        return null
    }
}
const SSO_BASE = parseBaseUrl(SSO_BASE_URL)

// Pre-approved scheme + host for the proxy target — the CWE-918 allowlist that
// the request site checks immediately before calling axios.
const SSO_ALLOWED_SCHEMES = ['https:']
const SSO_ALLOWED_HOSTS = SSO_BASE ? [SSO_BASE.hostname] : []

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

// Resolves the proxy target against the fixed SSO base.
//
// Using the WHATWG URL parser instead of string concatenation is what makes the
// forwarding safe: an absolute or protocol-relative originalUrl (e.g.
// "//evil.example/x") resolves to a DIFFERENT origin, which the check below
// rejects, and "../" traversal is normalised before the prefix allowlist sees
// it. Crucially the allowlist is applied to the RESOLVED pathname, so the value
// that gets validated is exactly the value that gets requested — the previous
// code validated req.path but proxied req.originalUrl.
//
// Returns the normalised "pathname + query" to proxy, or null when the request
// must not be forwarded. Returning a PATH (not a URL) keeps the target's origin
// entirely in the caller's hands — it rebuilds the URL from SSO_BASE itself, so
// no host or scheme can travel out of this function.
const resolveProxyPath = (originalUrl) => {
    if (!SSO_BASE) return null            // misconfigured environment — fail closed
    try {
        const candidate = new URL(originalUrl, SSO_BASE)
        if (candidate.origin !== SSO_BASE.origin) return null
        if (!ALLOWED_PREFIXES.some((p) => candidate.pathname.startsWith(p))) return null
        if (BLOCKED_PATHS.some((p) => candidate.pathname.startsWith(p))) return null
        return candidate.pathname + candidate.search
    } catch (err) {
        log('INFO', 'Inside ssoGateway, unparseable request path: ' + err.message)
        return null
    }
}

const app = createExpressApp('ssoGatewayApp')

// Lightweight liveness probe — no auth, no proxying. Lets smoke tests and
// monitoring verify the gateway is up (and that req.path is unprefixed) without
// needing a token.
app.get('/gateway/health', (req, res) => {
    return res.status(200).json({ success: true, service: 'sso-gateway' })
})

app.all('*', async (req, res) => {
    // 1. Route allowlist — anything not on the admin surface is not served here.
    //    Resolving up front also yields the exact URL we will request in step 3.
    const proxyPath = resolveProxyPath(req.originalUrl)
    if (!proxyPath) {
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
    //    The target URL is BUILT here, from the constant SSO_BASE plus the
    //    already-allowlisted path, and its scheme + host are checked against the
    //    pre-approved lists immediately before the request — which is made only
    //    inside that branch. Construction, validation and use all sit in this one
    //    scope so the guarantee is verifiable without following a helper
    //    (CWE-918 / S5144).
    const url = new URL(proxyPath, SSO_BASE)

    if (SSO_ALLOWED_SCHEMES.includes(url.protocol) && SSO_ALLOWED_HOSTS.includes(url.hostname)) {
        try {
            const response = await axios({
                method: req.method,
                url: url.toString(),   // fixed origin + allowlisted path, query preserved
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
    }

    log('ERROR', 'Inside ssoGateway, refusing target outside the allowlist: ' + url.origin)
    return res.status(400).json({ success: false, error: { code: 'INVALID_PROXY_TARGET' } })
})

module.exports.ssoGateway = onRequest(app)
