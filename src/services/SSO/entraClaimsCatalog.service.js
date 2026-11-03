/**
 * Entra claims catalog — the claim names and values a customer's SSO app can
 * send, read from Microsoft Graph with the ZDNA connector app.
 *
 * The connector is a multi-tenant app owned by ZDNA. A customer admin grants
 * it admin consent once (Application.Read.All, Policy.Read.ApplicationConfiguration);
 * after that the backend gets an app-only token for the customer's tenant with
 * ZDNA's own credentials. No customer secret is needed, so SAML works too.
 *
 * The catalog feeds two checks with the same rules:
 *   - the console, live while the admin types a role mapping
 *   - saveSsoConfig, so the API cannot store a mapping the console would reject
 */

const https = require('node:https');
const { microsoft, defaults } = require('../../config/constants');
const { logger } = require('../../config/logger');
const { maskInput } = require('../../utils/shared/maskId.util');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_CLAIM_NAME_LENGTH = 30; // jit_mappings.mapping_source is VARCHAR(30)

// Names the login code reads on its own (userResolution matchesMapping), so
// they are valid for every app. 'default' is the fallback-only keyword.
const BUILT_IN_CLAIM_NAMES = ['role', 'roles', 'group', 'groups', 'department', 'jobtitle'];
const ROLE_NAMES  = new Set(['role', 'roles']);
const GROUP_NAMES = new Set(['group', 'groups']);

const cache = new Map();

const catalogError = (message, code, statusCode = 400) =>
  Object.assign(new Error(message), { statusCode, code });

const isConnectorConfigured = () =>
  Boolean(process.env.ENTRA_CONNECTOR_CLIENT_ID && process.env.ENTRA_CONNECTOR_CLIENT_SECRET);

const norm = (v) => (typeof v === 'string' ? v.trim().toLowerCase() : '');

// Same SSRF guard as testConnection's fetchJson: Microsoft hosts over HTTPS only.
// Graph nextLinks are checked the same way before they are followed.
const requestJson = (url, { method = 'GET', headers = {}, body = null } = {}) =>
  new Promise((resolve, reject) => {
    if (!microsoft.isAllowedUrl(url)) {
      return reject(catalogError('Outbound request blocked — host not allowed', 'OUTBOUND_HOST_NOT_ALLOWED'));
    }
    const allHeaders = { ...headers };
    if (body) allHeaders['Content-Length'] = Buffer.byteLength(body);
    const req = https.request(new URL(url), { method, headers: allHeaders, timeout: 10000 }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Microsoft request timed out')); });
    if (body) req.write(body);
    req.end();
  });

// SAML stores no tenant field; Entra's SSO URL carries it.
const resolveTenant = ({ protocol, tenant_id, sso_url }) => {
  const fromUrl = typeof sso_url === 'string'
    ? sso_url.match(/login\.microsoftonline\.com\/([0-9a-f-]{36})\//i)?.[1]
    : null;
  const tenant = protocol === 'saml' ? (fromUrl || tenant_id) : tenant_id;
  if (!tenant || !UUID_RE.test(tenant)) {
    throw catalogError('A Microsoft Entra tenant ID (GUID) is required', 'INVALID_TENANT_ID');
  }
  return tenant.toLowerCase();
};

// How to find the customer's app: OIDC by its client id; SAML by the ?appid=
// Entra adds to some SSO URLs, otherwise by our Entity ID (unique per tenant).
const resolveAppKey = ({ protocol, client_id, sso_url, entity_id }) => {
  if (protocol === 'oidc') {
    if (!client_id || !UUID_RE.test(client_id)) {
      throw catalogError('A valid Client ID is required', 'INVALID_CLIENT_ID');
    }
    return { appId: client_id.toLowerCase() };
  }
  const appId = typeof sso_url === 'string' ? sso_url.match(/[?&]appid=([0-9a-f-]{36})\b/i)?.[1] : null;
  if (appId) return { appId: appId.toLowerCase() };
  return { entityId: entity_id || defaults.SAML_ENTITY_ID };
};

const getConnectorToken = async (tenant) => {
  const body = new URLSearchParams({
    grant_type:    'client_credentials',
    client_id:     process.env.ENTRA_CONNECTOR_CLIENT_ID,
    client_secret: process.env.ENTRA_CONNECTOR_CLIENT_SECRET,
    scope:         microsoft.graphScope,
  }).toString();
  const res = await requestJson(microsoft.tokenUrl(tenant), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (res.status === 200 && res.body?.access_token) return res.body.access_token;
  // The usual reason is that the tenant never consented to the connector
  // (AADSTS700016 — app not found in the directory).
  logger.warn('[ENTRA_CATALOG] Connector token request failed', {
    tenantIdMasked: maskInput(tenant),
    status: res.status,
    error: res.body?.error,
  });
  throw catalogError('The ZDNA connector is not approved in this Microsoft Entra tenant', 'ENTRA_CONNECTOR_NOT_CONSENTED', 403);
};

const graphGet = async (token, url) => {
  const res = await requestJson(url, { headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 200) return res.body;
  if (res.status === 401 || res.status === 403) {
    throw catalogError('The ZDNA connector is missing its Microsoft Graph permissions', 'ENTRA_CONNECTOR_NOT_CONSENTED', 403);
  }
  if (res.status === 404) return null;
  throw catalogError(`Microsoft Graph request failed (HTTP ${res.status})`, 'ENTRA_LOOKUP_FAILED', 502);
};

const graphGetAll = async (token, url) => {
  const items = [];
  let next = url;
  while (next) {
    const page = await graphGet(token, next);
    items.push(...(page?.value || []));
    next = page?.['@odata.nextLink'] || null;
  }
  return items;
};

// OData string literals escape a single quote by doubling it.
const odataString = (v) => `'${String(v).replaceAll("'", "''")}'`;

const findServicePrincipal = async (token, { appId, entityId }) => {
  const select = '$select=id,appId,appRoles';
  if (appId) {
    return graphGet(token, `${microsoft.graphV1}/servicePrincipals(appId=${odataString(appId)})?${select}`);
  }
  const filter = encodeURIComponent(`servicePrincipalNames/any(x:x eq ${odataString(entityId)})`);
  const page = await graphGet(token, `${microsoft.graphV1}/servicePrincipals?$filter=${filter}&${select}`);
  return page?.value?.[0] || null;
};

// Optional claims set on the app registration (OIDC id token or SAML token).
const getOptionalClaimNames = async (token, appId, protocol) => {
  try {
    const app = await graphGet(token, `${microsoft.graphV1}/applications(appId=${odataString(appId)})?$select=optionalClaims`);
    const list = protocol === 'saml' ? app?.optionalClaims?.saml2Token : app?.optionalClaims?.idToken;
    return (list || []).map((c) => c.name).filter(Boolean);
  } catch (err) {
    logger.debug('[ENTRA_CATALOG] Optional claims not readable', { code: err.code });
    return [];
  }
};

// SAML "Attributes & Claims". Beta API — when it fails the built-in names still apply.
// Login matches the attribute name as Entra sends it: namespace/name when a
// namespace is set, otherwise the bare name.
const getSamlClaimNames = async (token, spId) => {
  try {
    const policy = await graphGet(token, `${microsoft.graphBeta}/servicePrincipals/${encodeURIComponent(spId)}/claimsPolicy`);
    return (policy?.claims || [])
      .filter((c) => c?.name)
      .map((c) => (c.namespace ? `${c.namespace.replace(/\/$/, '')}/${c.name}` : c.name));
  } catch (err) {
    logger.debug('[ENTRA_CATALOG] SAML claims policy not readable', { code: err.code });
    return [];
  }
};

const buildCatalog = async (token, { protocol, appKey }) => {
  const sp = await findServicePrincipal(token, appKey);
  if (!sp) {
    throw catalogError('The SSO app was not found in Microsoft Entra', 'ENTRA_APP_NOT_FOUND', 404);
  }

  const assignments = await graphGetAll(
    token,
    `${microsoft.graphV1}/servicePrincipals/${encodeURIComponent(sp.id)}/appRoleAssignedTo?$select=principalId,principalDisplayName,principalType&$top=999`,
  );
  const groups = assignments
    .filter((a) => a.principalType === 'Group')
    .map((a) => ({ id: a.principalId, name: a.principalDisplayName || null }));

  const roles = [...new Set((sp.appRoles || [])
    .filter((r) => r.isEnabled !== false && r.value)
    .map((r) => r.value))];

  const configured = [
    ...(await getOptionalClaimNames(token, sp.appId, protocol)),
    ...(protocol === 'saml' ? await getSamlClaimNames(token, sp.id) : []),
  ];

  return {
    claimNames: [...new Set([...BUILT_IN_CLAIM_NAMES, ...configured])],
    roles,
    groups,
  };
};

/**
 * Reads the claims catalog for a customer's SSO app.
 *
 * @returns {Promise<{ claimNames: string[], roles: string[], groups: {id: string, name: string|null}[] }>}
 * @throws 503 ENTRA_CONNECTOR_NOT_CONFIGURED | 403 ENTRA_CONNECTOR_NOT_CONSENTED |
 *         404 ENTRA_APP_NOT_FOUND | 502 ENTRA_LOOKUP_FAILED | 400 INVALID_TENANT_ID / INVALID_CLIENT_ID
 */
const getEntraClaimsCatalog = async (config) => {
  if (!isConnectorConfigured()) {
    throw catalogError('The ZDNA connector app is not configured', 'ENTRA_CONNECTOR_NOT_CONFIGURED', 503);
  }
  const tenant = resolveTenant(config);
  const appKey = resolveAppKey(config);
  const cacheKey = `${tenant}|${appKey.appId || appKey.entityId}`;
  const hit = cache.get(cacheKey);
  if (hit && hit.expires > Date.now()) return hit.catalog;

  const token = await getConnectorToken(tenant);
  const catalog = await buildCatalog(token, { protocol: config.protocol, appKey });
  cache.set(cacheKey, { catalog, expires: Date.now() + CACHE_TTL_MS });

  logger.info('[ENTRA_CATALOG] Loaded', {
    tenantIdMasked: maskInput(tenant),
    claimNames: catalog.claimNames.length,
    roles: catalog.roles.length,
    groups: catalog.groups.length,
  });
  return catalog;
};

const buildAdminConsentUrl = (config) => {
  if (!isConnectorConfigured()) {
    throw catalogError('The ZDNA connector app is not configured', 'ENTRA_CONNECTOR_NOT_CONFIGURED', 503);
  }
  const url = new URL(microsoft.adminConsentUrl(resolveTenant(config)));
  url.searchParams.set('client_id', process.env.ENTRA_CONNECTOR_CLIENT_ID);
  url.searchParams.set('scope', microsoft.graphScope);
  url.searchParams.set('redirect_uri', defaults.ENTRA_CONNECTOR_REDIRECT_URI);
  return url.toString();
};

/**
 * Checks one mapping row against the catalog. Mirrors login matching
 * (userResolution matchesMapping) so a row that passes here can match at login.
 *
 * @returns {string|null} the problem, or null when the row is valid
 */
const checkMappingAgainstCatalog = (mapping, catalog) => {
  const name = norm(mapping.mapping_source);
  const value = typeof mapping.mapping_value === 'string' ? mapping.mapping_value.trim() : '';
  if (name === 'default') return null;
  if (name.length > MAX_CLAIM_NAME_LENGTH) {
    return `Claim name must be ${MAX_CLAIM_NAME_LENGTH} characters or fewer`;
  }
  if (!catalog.claimNames.some((n) => norm(n) === name)) {
    return `Claim "${mapping.mapping_source.trim()}" is not configured for this app in Microsoft Entra`;
  }
  if (ROLE_NAMES.has(name) && !catalog.roles.some((r) => norm(r) === norm(value))) {
    return `"${value}" is not an app role of this app in Microsoft Entra`;
  }
  if (GROUP_NAMES.has(name)
    && !catalog.groups.some((g) => g.id === value || (g.name && norm(g.name) === norm(value)))) {
    return `"${value}" is not a group assigned to this app in Microsoft Entra`;
  }
  return null;
};

const validateMappingsAgainstCatalog = (mappings, catalog) => {
  for (const m of mappings || []) {
    if (!m?.zdna_role || !m?.mapping_source) continue;
    const problem = checkMappingAgainstCatalog(m, catalog);
    if (problem) {
      const code = problem.startsWith('Claim') ? 'INVALID_CLAIM_NAME' : 'INVALID_CLAIM_VALUE';
      throw catalogError(problem, code);
    }
  }
};

const clearCatalogCache = () => cache.clear();

module.exports = {
  getEntraClaimsCatalog,
  buildAdminConsentUrl,
  checkMappingAgainstCatalog,
  validateMappingsAgainstCatalog,
  isConnectorConfigured,
  clearCatalogCache,
};
