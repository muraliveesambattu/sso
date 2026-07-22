/**
 * OIDC Token Exchange Service
 * Handles server-to-server token exchange with Microsoft Entra.
 */

const { getSsoIntegrationByCompanyId, getOidcConfig, getJitMappings } = require('../db/ssoDataService');
const { verifyJwtSignature }                      = require('../../utils/oidc/jwkValidation.util');
const { validateTokenClaims, validateUserClaims } = require('../../utils/oidc/tokenValidation.util');
const { exchangeCodeForTokens, decodeJwt, generateJwtAssertion } = require('../../utils/oidc/tokenExchange.util');
const { fetchUserGroupsFromGraph, fetchUserProfileFromGraph } = require('../../utils/oidc/GraphApi.utils');
const { resolveUser }                             = require('../SSO/userResolution.service');
const { resolvePermissions }                      = require('../SSO/permissionResolver.service');
const { generateCustomToken, getTenantFriendlyId } = require('../../utils/firebase/firebaseAdmin.util');
const { logger }                                  = require('../../config/logger');
const { microsoft }                               = require('../../config/constants');
const { resolveSecret }                           = require('../../utils/crypto.util');

const CONSUMER_MSA_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad';

const resolveAuthCredential = (oidcConfig, codeVerifier, tenantId) => {
  switch (oidcConfig.client_auth_method) {
    case 'client_secret_post':
    case 'client_secret':
    case 'secret':
      return resolveSecret(oidcConfig.client_secret);
    case 'private_key_jwt':
      return generateJwtAssertion(
        oidcConfig.client_id, tenantId,
        resolveSecret(oidcConfig.client_cert_enc),
        oidcConfig.client_cert_thumbprint
      );
    case 'none':
      if (!codeVerifier) {
        const err = new Error('PKCE flow requires code_verifier but none was found in session');
        err.statusCode = 400; err.code = 'MISSING_CODE_VERIFIER';
        throw err;
      }
      return codeVerifier;
    default:
      throw new Error(`Unsupported client_auth_method: ${oidcConfig.client_auth_method}`);
  }
};

const resolveUserGroups = async (idTokenClaims, accessToken) => {
  if (idTokenClaims.groups?.length > 0) return idTokenClaims.groups;
  if (idTokenClaims._claim_names?.groups) {
    logger.info('Group overage — fetching from Graph API', { action: 'group_overage' });
    // A Graph outage during group-overage must NOT fail the whole login: a
    // group-based JIT mapping can fall back to a 'default' mapping, and a
    // non-JIT / non-group tenant doesn't need groups at all. Degrade to no
    // groups and let role resolution decide (a tenant that requires a group
    // match with no 'default' will still be denied downstream).
    try {
      return await fetchUserGroupsFromGraph(accessToken);
    } catch (err) {
      logger.warn('Graph group lookup failed — proceeding with no groups', {
        action: 'graph_groups_fallback', error: err.message,
      });
      return [];
    }
  }
  return [];
};

// Department/job title feed the department/jobtitle JIT mapping sources. The
// id_token never carries them, so ask Graph — but only when JIT is on AND a
// mapping actually uses them. Per LLD 8.2 §7a: if the attribute is REQUIRED by a
// mapping and the Graph call fails, reject the login (the correct role can't be
// determined). If no dept/jobtitle mapping exists the attribute isn't needed, so
// a Graph blip must not block valid logins.
const resolveProfileAttributes = async (ssoIntegration, companyId, accessToken) => {
  const empty = { department: null, jobTitle: null };
  if (!ssoIntegration.jit_enabled) return empty;

  const jitMappings  = await getJitMappings(companyId);
  const needsProfile = jitMappings.some(m =>
    m.mapping_source === 'department' || m.mapping_source === 'jobtitle');
  if (!needsProfile) return empty;

  try {
    return await fetchUserProfileFromGraph(accessToken);
  } catch (err) {
    logger.warn('Graph profile fetch failed for a required department/jobtitle mapping — rejecting login', {
      action: 'graph_profile_failed', error: err.message,
    });
    const e = new Error('Failed to retrieve required user profile attributes from Microsoft Graph');
    e.statusCode = 502; e.code = 'GRAPH_PROFILE_FETCH_FAILED';
    throw e;
  }
};

const oidcTokenExchangeService = async (code, companyId, codeVerifier, nonce, clientIp) => {
  try {
    const startTime = Date.now();
    logger.info('Token exchange started', { action: 'token_exchange_start', company_id: companyId, ip: clientIp });

    // Step 1 — Load SSO integration
    const ssoIntegration = await getSsoIntegrationByCompanyId(companyId);
    if (!ssoIntegration || ssoIntegration.protocol !== 'oidc') {
      const err = new Error('OIDC integration not found for this company');
      err.statusCode = 404; err.code = 'INTEGRATION_NOT_FOUND'; throw err;
    }
    logger.debug('Step 1 OK: Integration found', { action: 'step_integration', tenant: ssoIntegration.entra_tenant_id });

    // Step 2 — Load OIDC config
    const oidcConfig = await getOidcConfig(companyId);
    if (!oidcConfig) {
      const err = new Error('OIDC configuration not found for this company');
      err.statusCode = 404; err.code = 'CONFIG_NOT_FOUND'; throw err;
    }
    logger.debug('Step 2 OK: Config found', { action: 'step_config', method: oidcConfig.client_auth_method });

    // Step 3 — Resolve auth credential
    const authCredential = resolveAuthCredential(oidcConfig, codeVerifier, ssoIntegration.entra_tenant_id);
    logger.debug('Step 3 OK: Credential resolved', { action: 'step_credential' });

    // Step 4 — Exchange code for tokens
    const tokenEndpoint = microsoft.tokenUrl(ssoIntegration.entra_tenant_id);
    const tokens = await exchangeCodeForTokens(
      code, oidcConfig.client_id, oidcConfig.client_auth_method,
      authCredential, resolveSecret(oidcConfig.redirect_uri), tokenEndpoint
    );
    logger.debug('Step 4 OK: Tokens received', { action: 'step_tokens', token_type: tokens.token_type });

    // Step 5 — Decode id_token
    const { header: idTokenHeader, payload: idTokenClaims } = decodeJwt(tokens.id_token);
    logger.debug('Step 5 OK: id_token decoded', { action: 'step_decode', alg: idTokenHeader.alg });

    // Step 6 — Verify RS256 signature
    await verifyJwtSignature(tokens.id_token, ssoIntegration.entra_tenant_id);
    logger.debug('Step 6 OK: Signature verified', { action: 'step_signature' });

    // Step 7 — Validate security claims
    validateTokenClaims(idTokenClaims, oidcConfig, ssoIntegration.entra_tenant_id, nonce);
    logger.debug('Step 7 OK: Claims valid', { action: 'step_claims' });

    // Step 7.5 — Cross-validate tenant
    const storedTenantId = ssoIntegration.entra_tenant_id;
    const tokenTenantId  = idTokenClaims.tid;
    const tenantMatches  =
      storedTenantId === 'common' ||
      (storedTenantId === 'consumers' && tokenTenantId === CONSUMER_MSA_TENANT) ||
      storedTenantId === tokenTenantId;

    if (!tenantMatches) {
      const err = new Error(`Tenant mismatch: token tid=${tokenTenantId}, expected: ${storedTenantId}`);
      err.statusCode = 401; err.code = 'TENANT_MISMATCH'; throw err;
    }
    logger.debug('Step 7.5 OK: Tenant validated', { action: 'step_tenant', stored: storedTenantId });

    // Step 8 — Resolve groups + identity
    const groups  = await resolveUserGroups(idTokenClaims, tokens.access_token);
    const profile = await resolveProfileAttributes(ssoIntegration, companyId, tokens.access_token);

    const enrichedClaims = {
      ...idTokenClaims,
      groups,
      department: profile.department,
      jobTitle:   profile.jobTitle,
    };
    const userClaims    = validateUserClaims(enrichedClaims, null);
    logger.info('Step 8 OK: Identity extracted', {
      action: 'step_identity', groups: groups.length,
      source: idTokenClaims._claim_names?.groups ? 'graph_api' : 'jwt_claim',
    });

    // Step 9 — Resolve user (JIT or non-JIT)
    const resolution = await resolveUser(companyId, enrichedClaims, 'oidc');
    logger.info('Step 9 OK: User resolved', { action: 'step_user', userAction: resolution.action });

    // Step 9.5 — Resolve permissions (RMS when configured, zdna_roles union
    // otherwise — see permissionResolver.service.js)
    const resolvedPerms = await resolvePermissions(resolution.roles, resolution.user);
    logger.info('Step 9.5 OK: Permissions resolved', {
      action: 'step_permissions',
      company_id: companyId,
      userAction: resolution.action,
      permissionSource: resolvedPerms.source,
      permissionCount: Array.isArray(resolvedPerms.permissions) ? resolvedPerms.permissions.length : 0,
      roleName: resolvedPerms.roleName || null,
    });
    logger.debug('Step 9.5 DEBUG: Full resolved permissions', {
      action: 'step_permissions_detail',
      company_id: companyId,
      resolvedPerms,
    });

    // Step 10 — Generate Firebase Custom Token
    const zdnaTenantId = resolution.user.user_id;
    // Mirror the native login's "Company ID" alias so SSO users show the same
    // friendlyId as the owner tenant (companyId === owner tenant here).
    const friendlyId   = await getTenantFriendlyId(companyId);
    const customToken  = await generateCustomToken(zdnaTenantId, {
      email:       userClaims.email,
      role:        resolution.roles[0]?.role_name || 'user',
      roles:       resolution.roles,
      permissions: resolvedPerms.permissions,
      companyId,
      friendlyId,
      displayName: userClaims.name || userClaims.preferred_username || '',
    });
    logger.debug('Step 10 OK: Firebase token generated', { action: 'step_firebase' });

    // Step 11 — Zero raw tokens
    tokens.access_token = null;
    tokens.id_token     = null;

    const processingTimeMs = Date.now() - startTime;
    logger.info('Token exchange complete', { action: 'token_exchange_complete', ms: processingTimeMs });

    return {
      customToken,
      user:       resolution.user,
      roles:      resolution.roles,
      userAction: resolution.action,
      session: {
        protocol:         'oidc',
        authMethod:       oidcConfig.client_auth_method,
        groupSource:      groups.length > 0 && idTokenClaims._claim_names?.groups ? 'graph_api' : 'jwt_claim',
        tenantScope:      storedTenantId,
        processingTimeMs,
        validatedAt:      new Date().toISOString(),
      },
    };

  } catch (err) {
    logger.error('Token exchange error', { action: 'token_exchange_error', code: err.code, error: err.message });
    if (!err.statusCode) { err.statusCode = 500; err.code = 'TOKEN_EXCHANGE_FAILED'; }
    throw err;
  }
};

module.exports = { oidcTokenExchangeService };
