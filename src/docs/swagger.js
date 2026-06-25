/**
 * Swagger / OpenAPI 3.0 Configuration
 *
 * Docs available at:
 *   Development: http://localhost:5000/api-docs
 *   JSON spec:   http://localhost:5000/api-docs.json
 *
 * Protected in production — requires X-Admin-API-Key header.
 */

const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title:       'ZDNA SSO Microservice API',
      version:     '1.0.0',
      description: `
SSO (Single Sign-On) microservice for ZDNA / MDNA Console.

Allows company employees to log in using their existing Microsoft Entra (Azure AD) credentials.
No separate ZDNA account creation needed — JIT provisioning auto-creates users on first login.

## Authentication
Admin endpoints (\`/auth/sso/save\`, \`/auth/test-connection\`) require:
\`\`\`
X-Admin-API-Key: <your-admin-api-key>
\`\`\`

## Flows
- **OIDC (OpenID Connect)** — client_secret, PKCE, or certificate auth
- **SAML 2.0** — Microsoft Entra SAML federation
      `,
      contact: {
        name:  'ZDNA Platform Team',
        email: 'platform@zdna.io',
      },
    },
    servers: [
      {
        url:         'http://localhost:5000',
        description: 'Local development',
      },
      {
        url:         'https://sso.zdna.io',
        description: 'Production (Cloud Run)',
      },
    ],
    tags: [
      { name: 'Health',    description: 'Service health and readiness' },
      { name: 'Domain',    description: 'SSO domain lookup — entry point for login' },
      { name: 'OIDC',      description: 'OpenID Connect token exchange' },
      { name: 'SAML',      description: 'SAML 2.0 assertion callback' },
      { name: 'Admin',     description: 'Admin endpoints — require X-Admin-API-Key' },
    ],
    components: {
      securitySchemes: {
        AdminApiKey: {
          type: 'apiKey',
          in:   'header',
          name: 'X-Admin-API-Key',
          description: 'Admin API key required for /auth/sso/save and /auth/test-connection',
        },
      },
      schemas: {
        // ── Common ──────────────────────────────────────────────────────────
        ErrorResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            error: {
              type: 'object',
              properties: {
                code:    { type: 'string', example: 'INVALID_EMAIL' },
                message: { type: 'string', example: 'Invalid email format.' },
              },
            },
          },
        },

        // ── Health ───────────────────────────────────────────────────────────
        HealthResponse: {
          type: 'object',
          properties: {
            status:  { type: 'string', enum: ['healthy', 'degraded'], example: 'healthy' },
            uptime:  { type: 'number', example: 120 },
            version: { type: 'string', example: '1.0.0' },
            checks: {
              type: 'object',
              properties: {
                database: {
                  type: 'object',
                  properties: {
                    status:         { type: 'string', enum: ['healthy', 'unhealthy', 'not_configured'] },
                    responseTimeMs: { type: 'number', example: 12 },
                  },
                },
              },
            },
          },
        },

        // ── Domain Check ─────────────────────────────────────────────────────
        DomainCheckRequest: {
          type: 'object',
          properties: {
            email:  { type: 'string', format: 'email', example: 'john@gmail-local.com', description: 'User email — domain extracted automatically' },
            domain: { type: 'string', example: 'gmail-local.com', description: 'Organisation domain — used if email not provided' },
          },
        },
        DomainCheckResponse: {
          type: 'object',
          properties: {
            found:              { type: 'boolean', example: true },
            protocol:           { type: 'string', enum: ['oidc', 'saml'] },
            message:            { type: 'string', example: 'Redirecting to Microsoft Entra...' },
            company_id:         { type: 'string', example: 'zdna-gmail-local-com-123' },
            client_auth_method: { type: 'string', example: 'client_secret_post' },
            config: {
              type: 'object',
              properties: {
                client_id:    { type: 'string', example: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
                sso_url:      { type: 'string', example: 'https://login.microsoftonline.com/{tid}/oauth2/v2.0/authorize' },
                redirect_uri: { type: 'string', example: 'http://localhost:3000/auth/oidc/callback' },
                scope:        { type: 'string', example: 'openid profile email' },
                state:        { type: 'string', example: 'abc123...' },
                nonce:        { type: 'string', example: 'xyz789...' },
              },
            },
          },
        },

        // ── Token Exchange ───────────────────────────────────────────────────
        TokenExchangeRequest: {
          type: 'object',
          required: ['code', 'company_id', 'state'],
          properties: {
            code:       { type: 'string', description: 'Authorization code from Microsoft Entra callback' },
            company_id: { type: 'string', example: 'zdna-gmail-local-com-123' },
            state:      { type: 'string', description: 'State value from the original domain-check response' },
          },
        },
        TokenExchangeResponse: {
          type: 'object',
          properties: {
            customToken: { type: 'string', description: 'Firebase Custom Token — use with signInWithCustomToken()' },
            user: {
              type: 'object',
              properties: {
                user_id:      { type: 'string', format: 'uuid' },
                email:        { type: 'string', format: 'email' },
                display_name: { type: 'string' },
                roles:        { type: 'array', items: { type: 'string' } },
                jit_provisioned: { type: 'boolean' },
              },
            },
            roles: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  role_id:   { type: 'string', example: 'role-admin' },
                  role_name: { type: 'string', example: 'Administrator' },
                },
              },
            },
            userAction: { type: 'string', enum: ['created', 'updated', 'login'] },
          },
        },

        // ── Save SSO Config ──────────────────────────────────────────────────
        SaveSsoConfigRequest: {
          type: 'object',
          required: ['protocol', 'domains', 'tenant_id'],
          properties: {
            protocol:      { type: 'string', enum: ['oidc', 'saml'], example: 'oidc' },
            idp:           { type: 'string', example: 'microsoft_entra' },
            domains:       { type: 'string', example: 'gmail-local.com' },
            tenant_id:     { type: 'string', format: 'uuid', example: '00000000-0000-0000-0000-000000000000' },
            client_id:     { type: 'string', format: 'uuid', example: '11111111-1111-1111-1111-111111111111' },
            auth_method:   { type: 'string', enum: ['client_secret_post', 'private_key_jwt', 'none'], example: 'client_secret_post' },
            client_secret: { type: 'string', description: 'Azure App client secret — stored encrypted in DB', example: 'REDACTED_CLIENT_SECRET' },
            redirect_uri:  { type: 'string', example: 'http://localhost:3000/auth/oidc/callback' },
            jit_enabled:   { type: 'boolean', example: true },
            jit_mappings: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  zdna_role:      { type: 'string', example: 'role-admin' },
                  mapping_source: { type: 'string', enum: ['group', 'default'], example: 'default' },
                  mapping_value:  { type: 'string', nullable: true, example: 'zdna-admins' },
                },
              },
            },
          },
        },
        SaveSsoConfigResponse: {
          type: 'object',
          properties: {
            success:    { type: 'boolean', example: true },
            company_id: { type: 'string', example: 'zdna-gmail-local-com-123' },
            message:    { type: 'string', example: 'SSO configuration saved and activated successfully' },
          },
        },

        // ── Test Connection ──────────────────────────────────────────────────
        TestConnectionRequest: {
          type: 'object',
          required: ['protocol', 'tenant_id'],
          properties: {
            protocol:      { type: 'string', enum: ['oidc', 'saml'], example: 'oidc' },
            tenant_id:     { type: 'string', format: 'uuid' },
            client_id:     { type: 'string', format: 'uuid' },
            auth_method:   { type: 'string', example: 'client_secret_post' },
            client_secret: { type: 'string' },
          },
        },
        TestConnectionResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            message: { type: 'string', example: 'Connection successful — credentials verified with Microsoft Entra' },
          },
        },
      },
    },
  },
  apis: ['./src/docs/paths/*.js'],
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = swaggerSpec;
