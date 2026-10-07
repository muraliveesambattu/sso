/*
SSO Gateway — single point of communication between MDNA Console and the SSO
Microservice for ADMIN operations (config CRUD, test-connection, feature flags).
Forwards with X-Admin-API-Key attached server-side; the key never reaches the
browser. company_id comes from the verified token, never from the client.
Login/browser-flow endpoints are NOT routed here by design — their callers are
unauthenticated users mid-login or Entra itself.

Belongs in: MDNA-Server/CloudFunctions/functions/api/ssoGateway.js
*/
const { onRequest } = require('firebase-functions/v2/https')
const axios = require('axios')
const { log } = require('firebase-functions/logger')
const { expressApp } = require('../util/additionalCommonUtil')
const { MIDDLEWARES, ROLE } = require('../util/constant')

const SSO_BASE_URL = process.env.SSO_BASE_URL
const SSO_ADMIN_API_KEY = process.env.SSO_ADMIN_API_KEY

const parseBaseUrl = (raw) => {
    try {
        return new URL(raw)
    } catch (err) {
        log('ERROR', 'Inside ssoGateway, SSO_BASE_URL is missing or malformed: ' + err.message)
        return null
    }
}
const SSO_BASE = parseBaseUrl(SSO_BASE_URL)

// CWE-918 allowlist — checked immediately before calling axios.
const SSO_ALLOWED_SCHEMES = new Set(['https:'])
const SSO_ALLOWED_HOSTS = SSO_BASE ? [SSO_BASE.hostname] : []

// Admin surface of the SSO microservice — the ONLY routes this gateway serves.
const ALLOWED_PREFIXES = [
    '/auth/sso',
    '/v1/auth/sso',
    '/auth/test-connection',
    '/v1/auth/test-connection',
    '/auth/admin/flags',
    '/v1/auth/admin/flags'
]

// Public Entra redirect target — must not be reachable through the gateway.
const BLOCKED_PATHS = ['/auth/test-connection/oidc/callback', '/v1/auth/test-connection/oidc/callback']

const matchesPrefix = (pathname, prefixes) =>
    prefixes.some((p) => pathname === p || pathname.startsWith(p + '/'))

const sanitizeForLog = (value) => String(value).replace(/[\r\n]/g, ' ').slice(0, 200)

// Resolves the proxy target against the fixed SSO base. The WHATWG parser
// normalises traversal and rejects a different origin, and the allowlist is
// applied to the RESOLVED pathname — so what is validated is what is requested.
const resolveProxyPath = (originalUrl) => {
    if (!SSO_BASE) return null
    try {
        const candidate = new URL(originalUrl, SSO_BASE)
        if (candidate.origin !== SSO_BASE.origin) return null
        if (!matchesPrefix(candidate.pathname, ALLOWED_PREFIXES)) return null
        if (matchesPrefix(candidate.pathname, BLOCKED_PATHS)) return null
        return candidate.pathname + candidate.search
    } catch (err) {
        log('INFO', 'Inside ssoGateway, unparseable request path: ' + err.message)
        return null
    }
}

// Tenant of the caller, from the claims authenticateHSTS leaves on req.context.
const resolveTenantId = (context = {}) =>
    context.tenantId || (context.role === ROLE.TENANT_OWNER ? context.identity : context.uid)

// Segments followed by the tenant: /sso/config/:company_id[/status],
// /admin/flags/:company_id. Overwritten so a client value cannot address
// another tenant; routes with nothing after the parent are untouched.
const TENANT_SEGMENT_PARENTS = new Set(['config', 'flags'])

const applyTenant = (url, tenantId) => {
    if (url.searchParams.has('company_id')) url.searchParams.set('company_id', tenantId)
    const parts = url.pathname.split('/')
    for (let i = 0; i < parts.length - 1; i++) {
        if (TENANT_SEGMENT_PARENTS.has(parts[i]) && parts[i + 1]) {
            parts[i + 1] = encodeURIComponent(tenantId)
        }
    }
    url.pathname = parts.join('/')
    return url
}

const app = expressApp('ssoGateway', [
    MIDDLEWARES.AUTH_HSTS,
])

// Liveness probe. Behind the app-level middleware, so it needs a valid token.
app.get('/gateway/health', (req, res) => {
    return res.status(200).json({ success: true, service: 'sso-gateway' })
})

// Preflight carries no Authorization header.
app.options('*', (req, res) => res.status(204).end())

app.all('*', async (req, res) => {
    const proxyPath = resolveProxyPath(req.originalUrl)
    if (!proxyPath) {
        log('INFO', 'Inside ssoGateway, unknown route rejected: ' + sanitizeForLog(req.path))
        return res.status(404).json({ success: false, error: { code: 'UNKNOWN_ROUTE' } })
    }

    const tenantId = resolveTenantId(req.context)
    if (!tenantId) {
        log('ERROR', 'Inside ssoGateway, no tenant on the verified token')
        return res.status(401).json({ success: false, error: { code: 'TENANT_UNRESOLVED' } })
    }

    const url = applyTenant(new URL(proxyPath, SSO_BASE), tenantId)
    const isBodyless = ['GET', 'HEAD', 'DELETE'].includes(req.method)
    const data = isBodyless ? undefined : { ...req.body, company_id: tenantId }

    if (SSO_ALLOWED_SCHEMES.has(url.protocol) && SSO_ALLOWED_HOSTS.includes(url.hostname)) {
        try {
            const response = await axios({
                method: req.method,
                url: url.toString(),
                headers: {
                    'Content-Type': 'application/json',
                    'X-Admin-API-Key': SSO_ADMIN_API_KEY,
                    'X-Forwarded-User': req.context?.email || 'console-user'
                },
                data,
                timeout: 30000,
                validateStatus: () => true   // relay SSO service statuses as-is
            })
            log('INFO', 'Inside ssoGateway, proxied ' + req.method + ' ' + sanitizeForLog(req.path) + ' -> ' + response.status)
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
