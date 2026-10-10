/*
SSO Gateway — proxies MDNA Console ADMIN calls (config CRUD, test-connection,
flags) to the SSO Microservice, attaching X-Admin-API-Key server-side.
company_id comes from the verified token, never the client. Login/browser-flow
endpoints are not routed here: their callers cannot present a console token.

Belongs in: MDNA-Server/CloudFunctions/functions/api/ssoGateway.js
*/
const { onRequest } = require('firebase-functions/v2/https')
const axios = require('axios')
const { log } = require('firebase-functions/logger')
const { expressApp } = require('../util/additionalCommonUtil')
const { MIDDLEWARES, ROLE, SSO_GATEWAY } = require('../util/constant')
const {
    MAX_BODY_BYTES,
    RETRY_BASE_DELAY_MS,
    RETRY_MAX_DELAY_MS,
    SINGLE_ATTEMPT_TIMEOUT_MS,
    RETRY_ATTEMPT_TIMEOUT_MS,
} = SSO_GATEWAY

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
const SSO_ALLOWED_HOSTS = new Set(SSO_BASE ? [SSO_BASE.hostname] : [])

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
    prefixes.some((prefix) => pathname === prefix || pathname.startsWith(prefix + '/'))

const sanitizeForLog = (value) => String(value).replaceAll(/[\r\n]/g, ' ').slice(0, 200)

// Resolved via the WHATWG parser, so the allowlist checks the normalised path.
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

// Only the two console roles carry a tenant; anything else → null → 401.
const TENANT_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/

const resolveTenantId = (context = {}) => {
    let raw = context.tenantId
    if (!raw && context.role === ROLE.TENANT_OWNER) raw = context.identity
    if (!raw && context.role === ROLE.ADMINISTRATIVE_USER) raw = context.uid
    return typeof raw === 'string' && TENANT_ID_PATTERN.test(raw) ? raw : null
}

// CR/LF would split the header; control chars make Node reject the request.
const PRINTABLE_ASCII = /^[\x20-\x7E]*$/

const sanitizeHeaderValue = (value, maxLen = 320) =>
    typeof value === 'string' && PRINTABLE_ASCII.test(value) ? value.slice(0, maxLen) : null

// Arrays and null are typeof 'object' but are not valid JSON request bodies.
const isPlainObject = (value) =>
    typeof value === 'object' && value !== null && !Array.isArray(value)

// Transport failures only — an upstream 4xx/5xx resolves and is relayed.
// POST/PATCH are not retried: a save that failed on the way back would apply twice.
const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'PUT', 'DELETE'])
const BODYLESS_METHODS = new Set(['GET', 'HEAD', 'DELETE'])

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const requestWithRetry = async (config, attempts, logContext) => {
    for (let attempt = 1; ; attempt++) {
        try {
            return await axios(config)
        } catch (err) {
            if (attempt >= attempts) {
                log('ERROR', 'Inside ssoGateway, upstream unreachable after ' + attempt +
                    ' attempt(s) ' + logContext + ': ' + err.message)
                throw err
            }
            const delay = Math.min(RETRY_BASE_DELAY_MS * 2 ** (attempt - 1), RETRY_MAX_DELAY_MS)
            log('WARN', 'Inside ssoGateway, attempt ' + attempt + ' failed ' + logContext +
                ', retrying in ' + delay + 'ms: ' + err.message)
            await sleep(delay)
        }
    }
}

// /sso/config/:company_id[/status], /admin/flags/:company_id — overwritten so a
// client value cannot address another tenant.
const TENANT_SEGMENT_PARENTS = new Set(['config', 'flags'])

const applyTenant = (url, tenantId) => {
    if (typeof tenantId !== 'string' || !tenantId) {
        const err = new TypeError('applyTenant: tenantId must be a non-empty string')
        err.statusCode = 400
        err.code = 'INVALID_TENANT_ID'
        throw err
    }
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

    const isBodyless = BODYLESS_METHODS.has(req.method)
    if (!isBodyless && !isPlainObject(req.body)) {
        log('INFO', 'Inside ssoGateway, rejected non-object body on ' + req.method)
        return res.status(400).json({ success: false, error: { code: 'INVALID_BODY' } })
    }

    if (!isBodyless) {
        let bodyBytes
        try {
            // Byte length, not string length — multi-byte payloads measure larger.
            bodyBytes = Buffer.byteLength(JSON.stringify(req.body), 'utf8')
        } catch (err) {
            log('INFO', 'Inside ssoGateway, unserialisable body on ' + req.method + ': ' + err.message)
            return res.status(400).json({ success: false, error: { code: 'INVALID_BODY' } })
        }
        if (bodyBytes > MAX_BODY_BYTES) {
            log('INFO', 'Inside ssoGateway, rejected oversized body on ' + req.method)
            return res.status(413).json({ success: false, error: { code: 'BODY_TOO_LARGE' } })
        }
    }

    let url
    try {
        url = applyTenant(new URL(proxyPath, SSO_BASE), tenantId)
    } catch (err) {
        log('ERROR', 'Inside ssoGateway, could not build the proxy target: ' + err.message)
        return res.status(400).json({ success: false, error: { code: 'INVALID_PATH' } })
    }
    const data = isBodyless ? undefined : { ...req.body, company_id: tenantId }

    const attempts = IDEMPOTENT_METHODS.has(req.method) ? 3 : 1

    if (SSO_ALLOWED_SCHEMES.has(url.protocol) && SSO_ALLOWED_HOSTS.has(url.hostname)) {
        try {
            const response = await requestWithRetry({
                method: req.method,
                url: url.toString(),
                headers: {
                    'Content-Type': 'application/json',
                    'X-Admin-API-Key': SSO_ADMIN_API_KEY,
                    'X-Forwarded-User': sanitizeHeaderValue(req.context?.email) || 'console-user'
                },
                data,
                timeout: attempts > 1 ? RETRY_ATTEMPT_TIMEOUT_MS : SINGLE_ATTEMPT_TIMEOUT_MS,
                validateStatus: () => true   // relay SSO service statuses as-is
            },
            attempts,
            req.method + ' ' + sanitizeForLog(req.path))
            log('INFO', 'Inside ssoGateway, proxied ' + req.method + ' ' + sanitizeForLog(req.path) + ' -> ' + response.status)
            return res.status(response.status).json(response.data)
        } catch {
            // requestWithRetry already logged the final failure with attempt count.
            return res.status(502).json({ success: false, error: { code: 'UPSTREAM_UNREACHABLE' } })
        }
    }

    log('ERROR', 'Inside ssoGateway, refusing target outside the allowlist: ' + url.origin)
    return res.status(400).json({ success: false, error: { code: 'INVALID_PROXY_TARGET' } })
})

module.exports.ssoGateway = onRequest(app)
