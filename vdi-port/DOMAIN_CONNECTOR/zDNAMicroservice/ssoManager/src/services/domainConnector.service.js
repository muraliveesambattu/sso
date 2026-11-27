const https = require('node:https');
const { microsoft } = require('../config/constants');
const { logger } = require('../config/logger');
const { maskInput } = require('../utils/shared/maskId.util');
const { createSsoError } = require('../utils/shared/responseHandler');

const REQUEST_TIMEOUT_MS = 10000;

// tenantId goes into Microsoft URL PATHS, so only an Entra tenant GUID or one of
// the documented aliases is accepted (same rule as testConnection) — S7044.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TENANT_SCOPES = new Set(['common', 'organizations']);

const assertValidTenant = (tenantId) => {
  if (typeof tenantId !== 'string' || !(UUID_RE.test(tenantId) || TENANT_SCOPES.has(tenantId))) {
    throw createSsoError('SSO_TENANT_ID_INVALID', 'tenantId must be a valid Entra tenant ID.', 400);
  }
};

// Outbound HTTPS call to a Microsoft host only (SSRF allowlist in constants).
// Resolves { status, body } (JSON when parseable); rejects on network error or timeout.
const requestJson = (url, { method = 'GET', headers = {}, body = null } = {}) =>
  new Promise((resolve, reject) => {
    if (!microsoft.isAllowedUrl(url)) {
      reject(createSsoError('OUTBOUND_HOST_NOT_ALLOWED', 'Outbound request blocked — host not allowed', 400));
      return;
    }
    const requestHeaders = { ...headers };
    if (body) requestHeaders['Content-Length'] = Buffer.byteLength(body);

    const req = https.request(new URL(url), { method, headers: requestHeaders, timeout: REQUEST_TIMEOUT_MS }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', (err) => reject(createSsoError('DOMAIN_CONNECTOR_NETWORK_ERROR', `Microsoft request failed: ${err.message}`, 502)));
    req.on('timeout', () => {
      req.destroy();
      reject(createSsoError('DOMAIN_CONNECTOR_TIMEOUT', 'Microsoft request timed out', 504));
    });
    if (body) req.write(body);
    req.end();
  });

const buildDomainConsentUrl = (tenantId) => {
  assertValidTenant(tenantId);
  const url = new URL(`${microsoft.loginBase}/${encodeURIComponent(tenantId)}/adminconsent`);
  url.searchParams.set('client_id', process.env.DOMAIN_CONNECTOR_CLIENT_ID || '');
  url.searchParams.set('redirect_uri', process.env.DOMAIN_CONNECTOR_REDIRECT_URI || '');
  return url.toString();
};

// App-only token for the customer's tenant. Fails until the tenant admin has consented.
const getDomainConnectorToken = async (tenantId) => {
  assertValidTenant(tenantId);
  const payload = new URLSearchParams({
    client_id: process.env.DOMAIN_CONNECTOR_CLIENT_ID || '',
    client_secret: process.env.DOMAIN_CONNECTOR_CLIENT_SECRET || '',
    scope: process.env.DOMAIN_CONNECTOR_SCOPE || microsoft.graphScope,
    grant_type: 'client_credentials',
  });

  const res = await requestJson(microsoft.tokenUrl(tenantId), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: payload.toString(),
  });

  if (res.status !== 200 || !res.body?.access_token) {
    logger.warn('[DOMAIN_CONNECTOR] Token request failed', {
      tenantIdMasked: maskInput(String(tenantId)),
      status: res.status,
      error: res.body?.error,
    });
    throw createSsoError('DOMAIN_CONNECTOR_TOKEN_FAILED', 'Unable to get a Microsoft Graph token for this tenant.', 502);
  }

  // Never log the token itself.
  logger.debug('[DOMAIN_CONNECTOR] Token received', { tenantIdMasked: maskInput(String(tenantId)) });
  return res.body.access_token;
};

// Verified domains of the tenant, lower-cased. Follows @odata.nextLink pages.
const getTenantDomains = async (accessToken) => {
  const domains = [];
  let nextUrl = `${microsoft.graphBase}/v1.0/domains?$select=id,isVerified`;

  while (nextUrl) {
    const res = await requestJson(nextUrl, {
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    });
    if (res.status !== 200) {
      logger.warn('[DOMAIN_CONNECTOR] Graph domains request failed', { status: res.status, error: res.body?.error?.code });
      throw createSsoError('DOMAIN_CONNECTOR_GRAPH_FAILED', 'Unable to read the tenant domains from Microsoft Graph.', 502);
    }
    const page = Array.isArray(res.body?.value) ? res.body.value : [];
    domains.push(...page.filter((domain) => domain.isVerified).map((domain) => String(domain.id).toLowerCase()));
    nextUrl = res.body?.['@odata.nextLink'] || null;
  }

  logger.debug('[DOMAIN_CONNECTOR] Verified domains read', { count: domains.length });
  return domains;
};

module.exports = {
  buildDomainConsentUrl,
  getDomainConnectorToken,
  getTenantDomains,
};
