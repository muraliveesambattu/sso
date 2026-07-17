jest.mock('../src/config/logger', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

jest.mock('../src/services/db/ssoDataService', () => ({
  getSsoIntegrationByCompanyId: jest.fn(),
  getOidcConfig: jest.fn(),
}));

jest.mock('../src/utils/oidc/jwkValidation.util', () => ({
  verifyJwtSignature: jest.fn(),
}));

jest.mock('../src/utils/oidc/tokenValidation.util', () => ({
  validateTokenClaims: jest.fn(),
  validateUserClaims: jest.fn(),
}));

jest.mock('../src/utils/oidc/tokenExchange.util', () => ({
  exchangeCodeForTokens: jest.fn(),
  decodeJwt: jest.fn(),
  generateJwtAssertion: jest.fn(),
}));

jest.mock('../src/utils/oidc/GraphApi.utils', () => ({
  fetchUserGroupsFromGraph: jest.fn(),
}));

jest.mock('../src/services/SSO/userResolution.service', () => ({
  resolveUser: jest.fn(),
}));

jest.mock('../src/services/SSO/permissionResolver.service', () => ({
  resolvePermissions: jest.fn(),
}));

jest.mock('../src/utils/firebase/firebaseAdmin.util', () => ({
  generateCustomToken: jest.fn(),
}));

jest.mock('../src/config/constants', () => ({
  microsoft: {
    tokenUrl: jest.fn((tenantId) => `https://token.example.test/${tenantId}`),
  },
}));

const { oidcTokenExchangeService } = require('../src/services/oidc/oidcTokenExchange.service');
const { getSsoIntegrationByCompanyId, getOidcConfig } = require('../src/services/db/ssoDataService');
const { verifyJwtSignature } = require('../src/utils/oidc/jwkValidation.util');
const { validateTokenClaims, validateUserClaims } = require('../src/utils/oidc/tokenValidation.util');
const { exchangeCodeForTokens, decodeJwt, generateJwtAssertion } = require('../src/utils/oidc/tokenExchange.util');
const { fetchUserGroupsFromGraph } = require('../src/utils/oidc/GraphApi.utils');
const { resolveUser } = require('../src/services/SSO/userResolution.service');
const { resolvePermissions } = require('../src/services/SSO/permissionResolver.service');
const { generateCustomToken } = require('../src/utils/firebase/firebaseAdmin.util');
const { logger } = require('../src/config/logger');

describe('oidcTokenExchange.service', () => {
  const originalEnv = {
    OIDC_CLIENT_SECRET_ZDNA: process.env.OIDC_CLIENT_SECRET_ZDNA,
    OIDC_REDIRECT_URI: process.env.OIDC_REDIRECT_URI,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.OIDC_CLIENT_SECRET_ZDNA = 'resolved-secret';
    process.env.OIDC_REDIRECT_URI = 'http://localhost:3000/auth/oidc/callback';

    validateTokenClaims.mockReturnValue(undefined);
    validateUserClaims.mockReturnValue({ email: 'user@example.com', name: 'User One' });
    resolveUser.mockResolvedValue({
      user: { user_id: 'user-1', email: 'user@example.com' },
      roles: [{ role_name: 'Admin' }],
      action: 'created',
    });
    resolvePermissions.mockResolvedValue({ permissions: [], source: 'zdna_roles' });
    generateCustomToken.mockResolvedValue('firebase-custom-token');
    verifyJwtSignature.mockResolvedValue(undefined);
    generateJwtAssertion.mockReturnValue('signed-assertion');
  });

  afterAll(() => {
    process.env.OIDC_CLIENT_SECRET_ZDNA = originalEnv.OIDC_CLIENT_SECRET_ZDNA;
    process.env.OIDC_REDIRECT_URI = originalEnv.OIDC_REDIRECT_URI;
  });

  test('throws 404 when the company does not have an OIDC integration', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue(null);

    await expect(oidcTokenExchangeService('code-1', 'company-1', 'verifier', 'nonce', '1.2.3.4')).rejects.toMatchObject({
      statusCode: 404,
      code: 'INTEGRATION_NOT_FOUND',
    });
  });

  test('throws 404 when the OIDC config is missing for a valid integration', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({
      company_id: 'company-missing-config',
      protocol: 'oidc',
      entra_tenant_id: 'tenant-missing',
    });
    getOidcConfig.mockResolvedValue(null);

    await expect(
      oidcTokenExchangeService('code-missing-config', 'company-missing-config', null, 'nonce', '1.2.3.4')
    ).rejects.toMatchObject({
      statusCode: 404,
      code: 'CONFIG_NOT_FOUND',
    });
  });

  test('exchanges code with client_secret auth and returns a custom token session', async () => {
    const tokens = {
      token_type: 'Bearer',
      access_token: 'access-token',
      id_token: 'id-token',
    };

    getSsoIntegrationByCompanyId.mockResolvedValue({
      company_id: 'company-1',
      protocol: 'oidc',
      entra_tenant_id: 'tenant-1',
    });
    getOidcConfig.mockResolvedValue({
      client_id: 'client-1',
      client_auth_method: 'client_secret',
      client_secret: 'env:OIDC_CLIENT_SECRET_ZDNA',
      redirect_uri: 'env:OIDC_REDIRECT_URI',
    });
    exchangeCodeForTokens.mockResolvedValue(tokens);
    decodeJwt.mockReturnValue({
      header: { alg: 'RS256' },
      payload: {
        tid: 'tenant-1',
        email: 'user@example.com',
        name: 'User One',
        groups: ['group-a'],
      },
    });

    const result = await oidcTokenExchangeService('code-2', 'company-1', null, 'nonce-1', '1.2.3.4');

    expect(exchangeCodeForTokens).toHaveBeenCalledWith(
      'code-2',
      'client-1',
      'client_secret',
      'resolved-secret',
      'http://localhost:3000/auth/oidc/callback',
      'https://token.example.test/tenant-1'
    );
    expect(resolveUser).toHaveBeenCalledWith('company-1', expect.objectContaining({
      tid: 'tenant-1',
      groups: ['group-a'],
    }), 'oidc');
    expect(resolvePermissions).toHaveBeenCalledWith(
      [{ role_name: 'Admin' }],
      { user_id: 'user-1', email: 'user@example.com' }
    );
    expect(generateCustomToken).toHaveBeenCalledWith('user-1', {
      email: 'user@example.com',
      role: 'Admin',
      roles: [{ role_name: 'Admin' }],
      permissions: [],
      companyId: 'company-1',
      displayName: 'User One',
    });
    expect(tokens.access_token).toBeNull();
    expect(tokens.id_token).toBeNull();
    expect(result).toEqual(expect.objectContaining({
      customToken: 'firebase-custom-token',
      userAction: 'created',
      session: expect.objectContaining({
        protocol: 'oidc',
        authMethod: 'client_secret',
        groupSource: 'jwt_claim',
        tenantScope: 'tenant-1',
      }),
    }));
    expect(logger.info).toHaveBeenCalledWith('Step 9.5 OK: Permissions resolved', {
      action: 'step_permissions',
      company_id: 'company-1',
      userAction: 'created',
      permissionSource: 'zdna_roles',
      permissionCount: 0,
      roleName: null,
    });
    expect(logger.debug).toHaveBeenCalledWith('Step 9.5 DEBUG: Full resolved permissions', {
      action: 'step_permissions_detail',
      company_id: 'company-1',
      resolvedPerms: { permissions: [], source: 'zdna_roles' },
    });
  });

  test('fetches groups from Graph API when group overage claims are present', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({
      company_id: 'company-2',
      protocol: 'oidc',
      entra_tenant_id: 'common',
    });
    getOidcConfig.mockResolvedValue({
      client_id: 'client-2',
      client_auth_method: 'client_secret_post',
      client_secret: 'env:OIDC_CLIENT_SECRET_ZDNA',
      redirect_uri: 'env:OIDC_REDIRECT_URI',
    });
    exchangeCodeForTokens.mockResolvedValue({
      token_type: 'Bearer',
      access_token: 'graph-access-token',
      id_token: 'id-token',
    });
    decodeJwt.mockReturnValue({
      header: { alg: 'RS256' },
      payload: {
        tid: 'another-tenant',
        email: 'user@example.com',
        _claim_names: { groups: 'src1' },
      },
    });
    fetchUserGroupsFromGraph.mockResolvedValue(['group-from-graph']);

    const result = await oidcTokenExchangeService('code-3', 'company-2', null, 'nonce-2', '1.2.3.4');

    expect(fetchUserGroupsFromGraph).toHaveBeenCalledWith('graph-access-token');
    expect(resolveUser).toHaveBeenCalledWith('company-2', expect.objectContaining({
      groups: ['group-from-graph'],
    }), 'oidc');
    expect(result.session.groupSource).toBe('graph_api');
  });

  test('supports private_key_jwt auth and accepts the consumers tenant alias', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({
      company_id: 'company-consumers',
      protocol: 'oidc',
      entra_tenant_id: 'consumers',
    });
    getOidcConfig.mockResolvedValue({
      client_id: 'client-consumers',
      client_auth_method: 'private_key_jwt',
      client_cert_enc: 'plain-cert-key',
      client_cert_thumbprint: 'thumbprint-1',
      redirect_uri: 'http://localhost:3000/auth/oidc/callback',
    });
    exchangeCodeForTokens.mockResolvedValue({
      token_type: 'Bearer',
      access_token: 'access-token',
      id_token: 'id-token',
    });
    decodeJwt.mockReturnValue({
      header: { alg: 'RS256' },
      payload: {
        tid: '9188040d-6c67-4c5b-b112-36a304b66dad',
        preferred_username: 'consumer@example.com',
      },
    });
    validateUserClaims.mockReturnValue({
      email: 'consumer@example.com',
      preferred_username: 'consumer@example.com',
    });

    const result = await oidcTokenExchangeService('code-consumers', 'company-consumers', null, 'nonce-consumers', '1.2.3.4');

    expect(generateJwtAssertion).toHaveBeenCalledWith(
      'client-consumers',
      'consumers',
      'plain-cert-key',
      'thumbprint-1'
    );
    expect(exchangeCodeForTokens).toHaveBeenCalledWith(
      'code-consumers',
      'client-consumers',
      'private_key_jwt',
      'signed-assertion',
      'http://localhost:3000/auth/oidc/callback',
      'https://token.example.test/consumers'
    );
    expect(result.session).toEqual(expect.objectContaining({
      authMethod: 'private_key_jwt',
      tenantScope: 'consumers',
      groupSource: 'jwt_claim',
    }));
  });

  test('rejects PKCE flows that are missing the server-side code verifier', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({
      company_id: 'company-3',
      protocol: 'oidc',
      entra_tenant_id: 'tenant-3',
    });
    getOidcConfig.mockResolvedValue({
      client_id: 'client-3',
      client_auth_method: 'none',
      redirect_uri: 'env:OIDC_REDIRECT_URI',
    });

    await expect(oidcTokenExchangeService('code-4', 'company-3', null, 'nonce-3', '1.2.3.4')).rejects.toMatchObject({
      statusCode: 400,
      code: 'MISSING_CODE_VERIFIER',
    });
    expect(exchangeCodeForTokens).not.toHaveBeenCalled();
  });

  test('rejects tokens whose tenant does not match the configured tenant scope', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({
      company_id: 'company-4',
      protocol: 'oidc',
      entra_tenant_id: 'tenant-expected',
    });
    getOidcConfig.mockResolvedValue({
      client_id: 'client-4',
      client_auth_method: 'client_secret',
      client_secret: 'env:OIDC_CLIENT_SECRET_ZDNA',
      redirect_uri: 'env:OIDC_REDIRECT_URI',
    });
    exchangeCodeForTokens.mockResolvedValue({
      token_type: 'Bearer',
      access_token: 'access-token',
      id_token: 'id-token',
    });
    decodeJwt.mockReturnValue({
      header: { alg: 'RS256' },
      payload: {
        tid: 'tenant-other',
        email: 'user@example.com',
      },
    });

    await expect(oidcTokenExchangeService('code-5', 'company-4', null, 'nonce-4', '1.2.3.4')).rejects.toMatchObject({
      statusCode: 401,
      code: 'TENANT_MISMATCH',
    });
  });

  test('passes through unsupported auth-method setup errors as TOKEN_EXCHANGE_FAILED', async () => {
    getSsoIntegrationByCompanyId.mockResolvedValue({
      company_id: 'company-unsupported',
      protocol: 'oidc',
      entra_tenant_id: 'tenant-unsupported',
    });
    getOidcConfig.mockResolvedValue({
      client_id: 'client-unsupported',
      client_auth_method: 'certificate_chain',
      redirect_uri: 'http://localhost:3000/auth/oidc/callback',
    });

    await expect(
      oidcTokenExchangeService('code-unsupported', 'company-unsupported', null, 'nonce', '1.2.3.4')
    ).rejects.toMatchObject({
      statusCode: 500,
      code: 'TOKEN_EXCHANGE_FAILED',
    });
  });
});
