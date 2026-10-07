process.env.SSO_BASE_URL = 'https://sso.example.run.app'
process.env.SSO_ADMIN_API_KEY = 'test-key'

jest.mock('axios')
jest.mock('firebase-functions/v2/https', () => ({ onRequest: (app) => app }), { virtual: true })
jest.mock('firebase-functions/logger', () => ({ log: jest.fn() }), { virtual: true })
jest.mock('../util/constant', () => ({
    ROLE: { TENANT_OWNER: 'TENANT_OWNER' },
    MIDDLEWARES: {
        AUTH_HSTS: (req, res, next) => {
            req.context = JSON.parse(req.headers['x-test-context'] || '{}')
            next()
        }
    }
}), { virtual: true })
jest.mock('../util/additionalCommonUtil', () => ({
    expressApp: (name, middlewares) => {
        const express = require('express')
        const app = express()
        app.use(express.json())
        middlewares.forEach((m) => app.use(m))
        return app
    }
}), { virtual: true })

const axios = require('axios')
const request = require('supertest')
const { ssoGateway: app } = require('../api/ssoGateway')

const ctx = (c) => JSON.stringify(c)

describe('ssoGateway', () => {
    beforeEach(() => axios.mockReset())

    test('401 TENANT_UNRESOLVED when context has no tenantId, role or uid', async () => {
        const res = await request(app).get('/auth/sso').set('x-test-context', ctx({}))
        expect(res.status).toBe(401)
        expect(res.body.error.code).toBe('TENANT_UNRESOLVED')
        expect(axios).not.toHaveBeenCalled()
    })

    test('client company_id in query and path is overwritten with the token tenant', async () => {
        axios.mockResolvedValue({ status: 200, data: {} })
        await request(app)
            .get('/auth/sso/config/attacker?company_id=attacker')
            .set('x-test-context', ctx({ tenantId: 'real-tenant' }))
        const calledUrl = axios.mock.calls[0][0].url
        expect(calledUrl).toContain('/config/real-tenant')
        expect(calledUrl).toContain('company_id=real-tenant')
        expect(calledUrl).not.toContain('attacker')
    })

    test('client company_id in the body is overwritten with the token tenant', async () => {
        axios.mockResolvedValue({ status: 200, data: {} })
        await request(app)
            .post('/auth/sso/config')
            .send({ company_id: 'attacker', name: 'x' })
            .set('x-test-context', ctx({ tenantId: 'real-tenant' }))
        expect(axios.mock.calls[0][0].data).toEqual({ company_id: 'real-tenant', name: 'x' })
    })

    test('X-Forwarded-User falls back to console-user when email is absent', async () => {
        axios.mockResolvedValue({ status: 200, data: {} })
        await request(app).get('/auth/sso').set('x-test-context', ctx({ tenantId: 't1' }))
        expect(axios.mock.calls[0][0].headers['X-Forwarded-User']).toBe('console-user')
    })

    test('X-Forwarded-User uses the token email when present', async () => {
        axios.mockResolvedValue({ status: 200, data: {} })
        await request(app).get('/auth/sso').set('x-test-context', ctx({ tenantId: 't1', email: 'a@b.com' }))
        expect(axios.mock.calls[0][0].headers['X-Forwarded-User']).toBe('a@b.com')
    })

    test('connection failure returns 502 UPSTREAM_UNREACHABLE', async () => {
        axios.mockRejectedValue(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }))
        const res = await request(app).get('/auth/sso').set('x-test-context', ctx({ tenantId: 't1' }))
        expect(res.status).toBe(502)
        expect(res.body.error.code).toBe('UPSTREAM_UNREACHABLE')
    })

    test('the OIDC test callback is not reachable through the gateway', async () => {
        const res = await request(app)
            .get('/auth/test-connection/oidc/callback')
            .set('x-test-context', ctx({ tenantId: 't1' }))
        expect(res.status).toBe(404)
        expect(axios).not.toHaveBeenCalled()
    })

    test('a path that only shares a prefix is rejected', async () => {
        const res = await request(app).get('/auth/ssofoo').set('x-test-context', ctx({ tenantId: 't1' }))
        expect(res.status).toBe(404)
        expect(axios).not.toHaveBeenCalled()
    })
})
