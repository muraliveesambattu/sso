jest.mock('../src/config/logger', () => ({
  logger: { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const { EventEmitter } = require('node:events');
const https = require('node:https');
const { logger } = require('../src/config/logger');
const {
  buildDomainConsentUrl,
  getDomainConnectorToken,
  getTenantDomains,
} = require('../src/services/domainConnector.service');

const TENANT = '11111111-2222-3333-4444-555555555555';

// Replies to each https.request with responder({ url, options, body }) -> { statusCode, body } | { error } | { timeout }
const mockRequest = (responder) =>
  jest.spyOn(https, 'request').mockImplementation((url, options, callback) => {
    const request = new EventEmitter();
    let requestBody = '';
    request.write = jest.fn((chunk) => { requestBody += chunk; });
    request.destroy = jest.fn();
    request.end = jest.fn(() => {
      const result = responder({ url: String(url), options, body: requestBody });
      if (result.error) {
        process.nextTick(() => request.emit('error', result.error));
        return;
      }
      if (result.timeout) {
        process.nextTick(() => request.emit('timeout'));
        return;
      }
      const response = new EventEmitter();
      response.statusCode = result.statusCode;
      callback(response);
      process.nextTick(() => {
        if (result.body !== undefined) response.emit('data', result.body);
        response.emit('end');
      });
    });
    return request;
  });

describe('domainConnector.service', () => {
  const env = { ...process.env };

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.DOMAIN_CONNECTOR_CLIENT_ID = 'connector-client';
    process.env.DOMAIN_CONNECTOR_CLIENT_SECRET = 'connector-secret';
    process.env.DOMAIN_CONNECTOR_REDIRECT_URI = 'https://app.example.com/auth/domain-consent/callback';
    delete process.env.DOMAIN_CONNECTOR_SCOPE;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(() => {
    process.env = env;
  });

  describe('buildDomainConsentUrl', () => {
    test('builds the tenant admin-consent link with the connector client and redirect', () => {
      const url = new URL(buildDomainConsentUrl(TENANT));

      expect(`${url.origin}${url.pathname}`).toBe(`https://login.microsoftonline.com/${TENANT}/adminconsent`);
      expect(url.searchParams.get('client_id')).toBe('connector-client');
      expect(url.searchParams.get('redirect_uri')).toBe('https://app.example.com/auth/domain-consent/callback');
    });

    test.each([
      ['missing', undefined],
      ['not a GUID', 'not-a-tenant'],
      ['a path traversal', 'common/../x'],
      ['the consumers alias', 'consumers'],
    ])('rejects a tenantId that is %s', (_label, tenantId) => {
      expect(() => buildDomainConsentUrl(tenantId)).toThrow(
        expect.objectContaining({ code: 'SSO_TENANT_ID_INVALID', statusCode: 400 }),
      );
    });

    test('accepts the organizations alias', () => {
      expect(buildDomainConsentUrl('organizations')).toContain('/organizations/adminconsent');
    });
  });

  describe('getDomainConnectorToken', () => {
    test('requests an app-only token with client credentials and returns it', async () => {
      const spy = mockRequest(() => ({ statusCode: 200, body: JSON.stringify({ access_token: 'graph-token' }) }));

      await expect(getDomainConnectorToken(TENANT)).resolves.toBe('graph-token');

      const [url, options] = spy.mock.calls[0];
      expect(String(url)).toBe(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`);
      expect(options.method).toBe('POST');
      const sent = new URLSearchParams(spy.mock.results[0].value.write.mock.calls[0][0]);
      expect(Object.fromEntries(sent)).toEqual({
        client_id: 'connector-client',
        client_secret: 'connector-secret',
        scope: 'https://graph.microsoft.com/.default',
        grant_type: 'client_credentials',
      });
    });

    test('uses DOMAIN_CONNECTOR_SCOPE when it is set', async () => {
      process.env.DOMAIN_CONNECTOR_SCOPE = 'https://graph.microsoft.com/Domain.Read.All';
      const spy = mockRequest(() => ({ statusCode: 200, body: JSON.stringify({ access_token: 'graph-token' }) }));

      await getDomainConnectorToken(TENANT);

      const sent = new URLSearchParams(spy.mock.results[0].value.write.mock.calls[0][0]);
      expect(sent.get('scope')).toBe('https://graph.microsoft.com/Domain.Read.All');
    });

    test('never logs the access token', async () => {
      mockRequest(() => ({ statusCode: 200, body: JSON.stringify({ access_token: 'graph-token' }) }));

      await getDomainConnectorToken(TENANT);

      const logged = JSON.stringify([
        logger.debug.mock.calls, logger.info.mock.calls, logger.warn.mock.calls, logger.error.mock.calls,
      ]);
      expect(logged).not.toContain('graph-token');
      expect(logged).not.toContain(TENANT);
    });

    test('fails with a controlled error when the tenant has not consented', async () => {
      mockRequest(() => ({
        statusCode: 400,
        body: JSON.stringify({ error: 'invalid_client', error_description: 'AADSTS700016: not found in the directory' }),
      }));

      await expect(getDomainConnectorToken(TENANT)).rejects.toMatchObject({
        code: 'DOMAIN_CONNECTOR_TOKEN_FAILED',
        statusCode: 502,
      });
      expect(logger.warn).toHaveBeenCalledWith('[DOMAIN_CONNECTOR] Token request failed', expect.objectContaining({
        status: 400,
        error: 'invalid_client',
      }));
    });

    test('rejects an invalid tenantId before any network call', async () => {
      const spy = mockRequest(() => ({ statusCode: 200, body: '{}' }));

      await expect(getDomainConnectorToken('common/../x')).rejects.toMatchObject({ code: 'SSO_TENANT_ID_INVALID' });
      expect(spy).not.toHaveBeenCalled();
    });

    test('turns a network error into a controlled error', async () => {
      mockRequest(() => ({ error: new Error('ECONNRESET') }));

      await expect(getDomainConnectorToken(TENANT)).rejects.toMatchObject({
        code: 'DOMAIN_CONNECTOR_NETWORK_ERROR',
        statusCode: 502,
      });
    });

    test('turns a timeout into a controlled error and drops the request', async () => {
      const spy = mockRequest(() => ({ timeout: true }));

      await expect(getDomainConnectorToken(TENANT)).rejects.toMatchObject({
        code: 'DOMAIN_CONNECTOR_TIMEOUT',
        statusCode: 504,
      });
      expect(spy.mock.results[0].value.destroy).toHaveBeenCalled();
    });
  });

  describe('getTenantDomains', () => {
    test('returns only the verified domains, lower-cased', async () => {
      const spy = mockRequest(() => ({
        statusCode: 200,
        body: JSON.stringify({
          value: [
            { id: 'Contoso.COM', isVerified: true },
            { id: 'unverified.example', isVerified: false },
            { id: 'contoso.onmicrosoft.com', isVerified: true },
          ],
        }),
      }));

      await expect(getTenantDomains('graph-token')).resolves.toEqual(['contoso.com', 'contoso.onmicrosoft.com']);

      const [url, options] = spy.mock.calls[0];
      expect(String(url)).toBe('https://graph.microsoft.com/v1.0/domains?$select=id,isVerified');
      expect(options.headers.Authorization).toBe('Bearer graph-token');
    });

    test('follows @odata.nextLink pages', async () => {
      const next = 'https://graph.microsoft.com/v1.0/domains?$select=id,isVerified&$skiptoken=abc';
      mockRequest(({ url }) => (url.includes('skiptoken')
        ? { statusCode: 200, body: JSON.stringify({ value: [{ id: 'two.example', isVerified: true }] }) }
        : { statusCode: 200, body: JSON.stringify({ value: [{ id: 'one.example', isVerified: true }], '@odata.nextLink': next }) }));

      await expect(getTenantDomains('graph-token')).resolves.toEqual(['one.example', 'two.example']);
    });

    test('never follows a nextLink to a non-Microsoft host', async () => {
      const spy = mockRequest(() => ({
        statusCode: 200,
        body: JSON.stringify({ value: [], '@odata.nextLink': 'https://attacker.example/steal' }),
      }));

      await expect(getTenantDomains('graph-token')).rejects.toMatchObject({ code: 'OUTBOUND_HOST_NOT_ALLOWED' });
      expect(spy).toHaveBeenCalledTimes(1);
    });

    test('treats a response without a value list as no domains', async () => {
      mockRequest(() => ({ statusCode: 200, body: JSON.stringify({}) }));

      await expect(getTenantDomains('graph-token')).resolves.toEqual([]);
    });

    test('fails with a controlled error when Graph refuses', async () => {
      mockRequest(() => ({
        statusCode: 403,
        body: JSON.stringify({ error: { code: 'Authorization_RequestDenied' } }),
      }));

      await expect(getTenantDomains('graph-token')).rejects.toMatchObject({
        code: 'DOMAIN_CONNECTOR_GRAPH_FAILED',
        statusCode: 502,
      });
      expect(logger.warn).toHaveBeenCalledWith('[DOMAIN_CONNECTOR] Graph domains request failed', {
        status: 403,
        error: 'Authorization_RequestDenied',
      });
    });
  });
});
