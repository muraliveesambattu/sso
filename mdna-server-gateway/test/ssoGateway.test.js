/* eslint-disable global-require */
// Belongs in: MDNA-Server/CloudFunctions/functions/test/ssoGateway.test.js
//
// Covers the gateway's security guarantees: the CWE-918 allowlist, the blocked
// public callback, preflight, tenant resolution and tenant-forcing, body
// validation, header sanitisation and upstream status relay.

const SSO_BASE_URL = 'https://sso-123.us-central1.run.app'

const mockAxios = jest.fn()
const mockLog = jest.fn()
const mockSsoGateway = {
    MAX_BODY_BYTES: 100_000,
    RETRY_BASE_DELAY_MS: 200,
    RETRY_MAX_DELAY_MS: 2000,
    SINGLE_ATTEMPT_TIMEOUT_MS: 30000,
    RETRY_ATTEMPT_TIMEOUT_MS: 8000,
}

let routes
let loadGateway

const res = () => {
    const response = {}
    response.status = jest.fn((code) => { response.statusCode = code; return response })
    response.json = jest.fn((body) => { response.body = body; return response })
    response.end = jest.fn(() => response)
    return response
}

describe('ssoGateway', () => {
    beforeEach(() => {
        jest.resetModules()
        mockAxios.mockReset()
        mockLog.mockReset()
        routes = {}

        process.env.SSO_BASE_URL = SSO_BASE_URL
        process.env.SSO_ADMIN_API_KEY = 'test-admin-key'

        jest.doMock('../util/additionalCommonUtil', () => ({
            expressApp: () => ({
                get: (_path, handler) => { routes.get = handler },
                options: (_path, handler) => { routes.options = handler },
                all: (_path, handler) => { routes.all = handler },
            }),
        }))
        jest.doMock('../util/constant', () => ({
            MIDDLEWARES: { AUTH_HSTS: 'authenticateHSTS' },
            ROLE: {
                TENANT_OWNER: 'Tenant Owner',
                ADMINISTRATIVE_USER: 'Administrative User',
                DEVICE: 'device',
                HMX: 'HMX Service Account',
            },
            SSO_GATEWAY: mockSsoGateway,
        }))
        jest.doMock('firebase-functions/logger', () => ({ log: mockLog }))
        jest.doMock('firebase-functions/v2/https', () => ({ onRequest: (app) => app }))
        jest.doMock('axios', () => mockAxios)

        loadGateway = () => { require('../api/ssoGateway') }
        loadGateway()
    })

    const call = async (req) => {
        const response = res()
        await routes.all({ context: { role: 'Tenant Owner', identity: 'tenant-1' }, body: {}, ...req }, response)
        return response
    }

    // ---- allowlist (CWE-918) -------------------------------------------------

    test('rejects a path outside the allowlist before reaching axios', async () => {
        const r = await call({ method: 'GET', path: '/auth/secrets', originalUrl: '/auth/secrets' })
        expect(r.statusCode).toBe(404)
        expect(r.body.error.code).toBe('UNKNOWN_ROUTE')
        expect(mockAxios).not.toHaveBeenCalled()
    })

    test('rejects an absolute originalUrl pointing at another origin', async () => {
        const r = await call({ method: 'GET', path: '/auth/sso/config', originalUrl: 'https://evil.example/auth/sso/config' })
        expect(r.statusCode).toBe(404)
        expect(mockAxios).not.toHaveBeenCalled()
    })

    test('normalises traversal before applying the allowlist', async () => {
        mockAxios.mockResolvedValue({ status: 200, data: {} })
        await call({ method: 'GET', path: '/auth/admin/flags', originalUrl: '/auth/../auth/admin/flags' })
        expect(new URL(mockAxios.mock.calls[0][0].url).pathname).toBe('/auth/admin/flags')
    })

    test('blocks the public Entra redirect target', async () => {
        const r = await call({
            method: 'POST',
            path: '/auth/test-connection/oidc/callback',
            originalUrl: '/auth/test-connection/oidc/callback',
        })
        expect(r.statusCode).toBe(404)
        expect(mockAxios).not.toHaveBeenCalled()
    })

    // ---- preflight -----------------------------------------------------------

    test('OPTIONS preflight returns 204 without an Authorization header', async () => {
        const r = res()
        routes.options({ method: 'OPTIONS', headers: {} }, r)
        expect(r.statusCode).toBe(204)
        expect(r.end).toHaveBeenCalled()
    })

    // ---- tenant resolution ---------------------------------------------------

    test('responds 401 TENANT_UNRESOLVED when the token carries no tenant', async () => {
        const r = await call({
            method: 'GET', path: '/auth/sso/config', originalUrl: '/auth/sso/config',
            context: { role: 'device', uid: 'dev-1' },
        })
        expect(r.statusCode).toBe(401)
        expect(r.body.error.code).toBe('TENANT_UNRESOLVED')
        expect(mockAxios).not.toHaveBeenCalled()
    })

    test('responds 401 when the tenant claim is not a string', async () => {
        const r = await call({
            method: 'GET', path: '/auth/sso/config', originalUrl: '/auth/sso/config',
            context: { tenantId: { bad: true } },
        })
        expect(r.statusCode).toBe(401)
    })

    // ---- tenant forcing (anti-spoofing) -------------------------------------

    test('overwrites a client-supplied company_id query param with the token tenant', async () => {
        mockAxios.mockResolvedValue({ status: 200, data: {} })
        await call({
            method: 'GET', path: '/auth/sso/config',
            originalUrl: '/auth/sso/config?company_id=OTHER_TENANT',
        })
        expect(new URL(mockAxios.mock.calls[0][0].url).searchParams.get('company_id')).toBe('tenant-1')
    })

    test('overwrites a client-supplied company_id path segment with the token tenant', async () => {
        mockAxios.mockResolvedValue({ status: 200, data: {} })
        await call({
            method: 'DELETE', path: '/auth/sso/config/OTHER_TENANT',
            originalUrl: '/auth/sso/config/OTHER_TENANT',
        })
        expect(new URL(mockAxios.mock.calls[0][0].url).pathname).toBe('/auth/sso/config/tenant-1')
    })

    test('overwrites a client-supplied company_id in the body', async () => {
        mockAxios.mockResolvedValue({ status: 201, data: {} })
        await call({
            method: 'POST', path: '/auth/sso/save', originalUrl: '/auth/sso/save',
            body: { company_id: 'OTHER_TENANT', protocol: 'oidc' },
        })
        expect(mockAxios.mock.calls[0][0].data).toEqual({ company_id: 'tenant-1', protocol: 'oidc' })
    })

    test('sends no body on bodyless methods', async () => {
        mockAxios.mockResolvedValue({ status: 200, data: {} })
        await call({ method: 'GET', path: '/auth/sso/config', originalUrl: '/auth/sso/config' })
        expect(mockAxios.mock.calls[0][0].data).toBeUndefined()
    })

    // ---- body validation -----------------------------------------------------

    test('rejects an array body with 400 INVALID_BODY', async () => {
        const r = await call({
            method: 'POST', path: '/auth/sso/save', originalUrl: '/auth/sso/save', body: [1, 2, 3],
        })
        expect(r.statusCode).toBe(400)
        expect(r.body.error.code).toBe('INVALID_BODY')
        expect(mockAxios).not.toHaveBeenCalled()
    })

    test('rejects an oversized body with 413 BODY_TOO_LARGE', async () => {
        const r = await call({
            method: 'POST', path: '/auth/sso/save', originalUrl: '/auth/sso/save',
            body: { blob: 'x'.repeat(200000) },
        })
        expect(r.statusCode).toBe(413)
        expect(r.body.error.code).toBe('BODY_TOO_LARGE')
        expect(mockAxios).not.toHaveBeenCalled()
    })

    test('rejects a multi-byte body over the cap by byte length', async () => {
        const r = await call({
            method: 'POST', path: '/auth/sso/save', originalUrl: '/auth/sso/save',
            body: { blob: '\u00e9'.repeat(60000) },   // 60k chars, ~120KB utf8
        })
        expect(r.statusCode).toBe(413)
        expect(mockAxios).not.toHaveBeenCalled()
    })

    test('rejects an unserialisable body with 400 INVALID_BODY', async () => {
        const circular = {}
        circular.self = circular
        const r = await call({
            method: 'POST', path: '/auth/sso/save', originalUrl: '/auth/sso/save', body: circular,
        })
        expect(r.statusCode).toBe(400)
        expect(r.body.error.code).toBe('INVALID_BODY')
        expect(mockAxios).not.toHaveBeenCalled()
    })

    // ---- liveness probe ------------------------------------------------------

    test('health probe reports the service name', () => {
        const r = res()
        routes.get({}, r)
        expect(r.statusCode).toBe(200)
        expect(r.body).toEqual({ success: true, service: 'sso-gateway' })
    })

    // ---- header sanitisation -------------------------------------------------

    test('falls back to console-user when the email contains CRLF', async () => {
        mockAxios.mockResolvedValue({ status: 200, data: {} })
        await call({
            method: 'GET', path: '/auth/sso/config', originalUrl: '/auth/sso/config',
            context: { role: 'Tenant Owner', identity: 'tenant-1', email: 'u@x.com\r\nX-Injected: 1' },
        })
        expect(mockAxios.mock.calls[0][0].headers['X-Forwarded-User']).toBe('console-user')
    })

    test('falls back to console-user on a control character in the email', async () => {
        mockAxios.mockResolvedValue({ status: 200, data: {} })
        await call({
            method: 'GET', path: '/auth/sso/config', originalUrl: '/auth/sso/config',
            context: { role: 'Tenant Owner', identity: 'tenant-1', email: 'u@x.com\u0000evil' },
        })
        expect(mockAxios.mock.calls[0][0].headers['X-Forwarded-User']).toBe('console-user')
    })

    test('forwards a clean email unchanged', async () => {
        mockAxios.mockResolvedValue({ status: 200, data: {} })
        await call({
            method: 'GET', path: '/auth/sso/config', originalUrl: '/auth/sso/config',
            context: { role: 'Tenant Owner', identity: 'tenant-1', email: 'u@x.com' },
        })
        expect(mockAxios.mock.calls[0][0].headers['X-Forwarded-User']).toBe('u@x.com')
    })

    // ---- upstream relay ------------------------------------------------------

    test.each([
        [403, 'INVALID_API_KEY'],
        [401, 'MISSING_ID_TOKEN'],
    ])('relays upstream %i as-is', async (status, code) => {
        mockAxios.mockResolvedValue({ status, data: { error: { code } } })
        const r = await call({ method: 'POST', path: '/auth/test-connection', originalUrl: '/auth/test-connection' })
        expect(r.statusCode).toBe(status)
        expect(r.body.error.code).toBe(code)
    })

    test('returns 502 when the upstream is unreachable', async () => {
        mockAxios.mockRejectedValue(new Error('ECONNREFUSED'))
        const r = await call({ method: 'POST', path: '/auth/test-connection', originalUrl: '/auth/test-connection' })
        expect(r.statusCode).toBe(502)
        expect(r.body.error.code).toBe('UPSTREAM_UNREACHABLE')
    })

    // ---- retry on transport failures ----------------------------------------

    test('retries an idempotent GET and succeeds on a later attempt', async () => {
        mockAxios
            .mockRejectedValueOnce(new Error('ECONNREFUSED'))
            .mockRejectedValueOnce(new Error('ECONNREFUSED'))
            .mockResolvedValueOnce({ status: 200, data: { ok: true } })
        const r = await call({ method: 'GET', path: '/auth/sso/config', originalUrl: '/auth/sso/config' })
        expect(mockAxios).toHaveBeenCalledTimes(3)
        expect(r.statusCode).toBe(200)
        expect(mockLog.mock.calls.filter(([level]) => level === 'WARN')).toHaveLength(2)
    })

    test('uses the shorter per-attempt timeout on retried methods', async () => {
        mockAxios.mockResolvedValue({ status: 200, data: {} })
        await call({ method: 'GET', path: '/auth/sso/config', originalUrl: '/auth/sso/config' })
        expect(mockAxios.mock.calls[0][0].timeout).toBe(8000)
    })

    test('uses the full timeout when the method is not retried', async () => {
        mockAxios.mockResolvedValue({ status: 200, data: {} })
        await call({ method: 'POST', path: '/auth/sso/save', originalUrl: '/auth/sso/save', body: { a: 1 } })
        expect(mockAxios.mock.calls[0][0].timeout).toBe(30000)
    })

    test('does not retry a POST', async () => {
        mockAxios.mockRejectedValue(new Error('ECONNREFUSED'))
        const r = await call({ method: 'POST', path: '/auth/sso/save', originalUrl: '/auth/sso/save', body: { a: 1 } })
        expect(mockAxios).toHaveBeenCalledTimes(1)
        expect(r.statusCode).toBe(502)
        expect(mockLog.mock.calls.some(([level, msg]) => level === 'ERROR' && msg.includes('after 1 attempt'))).toBe(true)
    })

    test('gives up after three attempts on an idempotent method', async () => {
        mockAxios.mockRejectedValue(new Error('ETIMEDOUT'))
        const r = await call({ method: 'DELETE', path: '/auth/sso/config/x', originalUrl: '/auth/sso/config/x' })
        expect(mockAxios).toHaveBeenCalledTimes(3)
        expect(r.statusCode).toBe(502)
    })

    test('does not retry an upstream 4xx — it is relayed, not a transport failure', async () => {
        mockAxios.mockResolvedValue({ status: 403, data: { error: { code: 'INVALID_API_KEY' } } })
        const r = await call({ method: 'GET', path: '/auth/sso/config', originalUrl: '/auth/sso/config' })
        expect(mockAxios).toHaveBeenCalledTimes(1)
        expect(r.statusCode).toBe(403)
    })

    test('attaches the admin key to the proxied request', async () => {
        mockAxios.mockResolvedValue({ status: 200, data: {} })
        await call({ method: 'GET', path: '/auth/sso/config', originalUrl: '/auth/sso/config' })
        expect(mockAxios.mock.calls[0][0].headers['X-Admin-API-Key']).toBe('test-admin-key')
    })
})

// ---- fail-closed configuration ----------------------------------------------

describe('ssoGateway - misconfigured SSO_BASE_URL', () => {
    const loadWith = (value) => {
        jest.resetModules()
        routes = {}
        if (value === undefined) delete process.env.SSO_BASE_URL
        else process.env.SSO_BASE_URL = value

        jest.doMock('../util/additionalCommonUtil', () => ({
            expressApp: () => ({
                get: (_path, handler) => { routes.get = handler },
                options: (_path, handler) => { routes.options = handler },
                all: (_path, handler) => { routes.all = handler },
            }),
        }))
        jest.doMock('../util/constant', () => ({
            MIDDLEWARES: { AUTH_HSTS: 'authenticateHSTS' },
            ROLE: { TENANT_OWNER: 'Tenant Owner', ADMINISTRATIVE_USER: 'Administrative User' },
            SSO_GATEWAY: mockSsoGateway,
        }))
        jest.doMock('firebase-functions/logger', () => ({ log: mockLog }))
        jest.doMock('firebase-functions/v2/https', () => ({ onRequest: (app) => app }))
        jest.doMock('axios', () => mockAxios)
        require('../api/ssoGateway')
    }

    test.each([
        ['missing', undefined],
        ['malformed', 'not-a-url'],
    ])('fails closed when SSO_BASE_URL is %s', async (_name, value) => {
        mockAxios.mockReset()
        loadWith(value)
        const r = res()
        await routes.all(
            { method: 'GET', path: '/auth/sso/config', originalUrl: '/auth/sso/config', body: {},
              context: { role: 'Tenant Owner', identity: 'tenant-1' } },
            r,
        )
        expect(r.statusCode).toBe(404)
        expect(mockAxios).not.toHaveBeenCalled()
    })
})
