/**
 * @openapi
 * /auth/sso/save:
 *   post:
 *     tags: [Admin]
 *     summary: Save and activate SSO configuration
 *     description: |
 *       Creates or updates an SSO integration for a company domain.
 *       If the domain already exists, the existing record is updated.
 *
 *       **What gets saved:**
 *       - `sso_integrations` — domain → protocol mapping
 *       - `oidc_configurations` or `saml_configurations` — credentials (secret stored encrypted)
 *       - `jit_mappings` — role mapping rules (replaced on update)
 *
 *       **Takes effect immediately** — domain-check will return the new config
 *       as soon as this call completes.
 *
 *       🔐 **Requires X-Admin-API-Key header**
 *     security:
 *       - AdminApiKey: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SaveSsoConfigRequest'
 *           example:
 *             protocol: oidc
 *             idp: microsoft_entra
 *             domains: gmail-local.com
 *             tenant_id: 00000000-0000-0000-0000-000000000000
 *             client_id: 11111111-1111-1111-1111-111111111111
 *             auth_method: client_secret_post
 *             client_secret: "REDACTED_CLIENT_SECRET"
 *             redirect_uri: http://localhost:3000/auth/oidc/callback
 *             jit_enabled: true
 *             jit_mappings:
 *               - zdna_role: role-admin
 *                 mapping_source: default
 *                 mapping_value: null
 *     responses:
 *       201:
 *         description: SSO configuration saved and activated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SaveSsoConfigResponse'
 *       400:
 *         description: Missing required fields
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       401:
 *         description: Missing API key
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       403:
 *         description: Invalid API key
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *
 * /auth/test-connection:
 *   post:
 *     tags: [Admin]
 *     summary: Test SSO credentials against Microsoft Entra
 *     description: |
 *       Verifies that the provided credentials can authenticate with Microsoft Entra
 *       **before** saving the config.
 *
 *       - **OIDC + client_secret** → calls Entra token endpoint with client_credentials grant
 *       - **OIDC + PKCE/cert** → calls Entra OpenID discovery to confirm tenant exists
 *       - **SAML** → fetches Entra federation metadata
 *
 *       🔐 **Requires X-Admin-API-Key header**
 *     security:
 *       - AdminApiKey: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/TestConnectionRequest'
 *           example:
 *             protocol: oidc
 *             auth_method: client_secret_post
 *             tenant_id: 00000000-0000-0000-0000-000000000000
 *             client_id: 11111111-1111-1111-1111-111111111111
 *             client_secret: "REDACTED_CLIENT_SECRET"
 *     responses:
 *       200:
 *         description: Connection test result
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TestConnectionResponse'
 *             examples:
 *               success:
 *                 value: { success: true, message: "Connection successful — credentials verified with Microsoft Entra" }
 *               failure:
 *                 value: { success: false, message: "invalid_client: The client secret provided is invalid." }
 *       401:
 *         description: Missing API key
 *       403:
 *         description: Invalid API key
 */
