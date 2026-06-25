/**
 * @openapi
 * /auth/domain-check:
 *   post:
 *     tags: [Domain]
 *     summary: Check if SSO is configured for a domain
 *     description: |
 *       Entry point for the SSO login flow.
 *       Accepts either an email address or a domain name.
 *       - If email is provided, the domain is extracted automatically.
 *       - Returns OIDC config (state, nonce, sso_url) the frontend uses to build the /authorize URL.
 *       - Returns SAML redirect URL for SAML-configured domains.
 *
 *       **Rate limited:** 10 requests / IP / minute.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/DomainCheckRequest'
 *           examples:
 *             byEmail:
 *               summary: Provide email
 *               value: { email: "john@gmail-local.com" }
 *             byDomain:
 *               summary: Provide domain directly
 *               value: { domain: "gmail-local.com" }
 *     responses:
 *       200:
 *         description: SSO config found or not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/DomainCheckResponse'
 *             examples:
 *               found:
 *                 summary: SSO configured
 *                 value:
 *                   found: true
 *                   protocol: oidc
 *                   company_id: zdna-gmail-local-com-123
 *                   client_auth_method: client_secret_post
 *                   config:
 *                     client_id: 85078fbc-xxxx
 *                     sso_url: https://login.microsoftonline.com/.../oauth2/v2.0/authorize
 *                     redirect_uri: http://localhost:3000/auth/oidc/callback
 *                     scope: openid profile email
 *                     state: abc123
 *                     nonce: xyz789
 *               notFound:
 *                 summary: SSO not configured
 *                 value:
 *                   found: false
 *                   promptOrgDomain: false
 *                   message: SSO is not available for this domain. Please contact your administrator.
 *       400:
 *         description: Invalid input
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       429:
 *         description: Rate limit exceeded
 *
 * /v1/auth/domain-check:
 *   post:
 *     tags: [Domain]
 *     summary: Check if SSO is configured for a domain (v1)
 *     description: Same as /auth/domain-check — versioned endpoint for new clients.
 *     requestBody:
 *       $ref: '#/paths/~1auth~1domain-check/post/requestBody'
 *     responses:
 *       200:
 *         $ref: '#/paths/~1auth~1domain-check/post/responses/200'
 */
