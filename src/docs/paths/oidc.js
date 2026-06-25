/**
 * @openapi
 * /auth/oidc/token-exchange:
 *   post:
 *     tags: [OIDC]
 *     summary: Exchange Microsoft authorization code for Firebase token
 *     description: |
 *       **Step 2 of the OIDC login flow.**
 *
 *       After Microsoft Entra redirects to the frontend callback URL with a `code`,
 *       the frontend POSTs that code here for server-to-server token exchange.
 *
 *       Steps performed:
 *       1. Validate state against the state store (CSRF protection)
 *       2. Exchange code for tokens at Entra /token endpoint
 *       3. Verify RS256 JWT signature using Entra JWKS
 *       4. Validate all security claims (iss, aud, exp, nonce, tenant)
 *       5. JIT-provision or update user in PostgreSQL
 *       6. Generate Firebase Custom Token
 *
 *       Frontend uses the returned `customToken` with Firebase `signInWithCustomToken()`.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/TokenExchangeRequest'
 *     responses:
 *       200:
 *         description: Token exchange successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TokenExchangeResponse'
 *       400:
 *         description: Missing required fields
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       401:
 *         description: Session expired or state not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example:
 *               success: false
 *               error:
 *                 code: SESSION_EXPIRED
 *                 message: Authentication session expired. Please sign in again.
 *       403:
 *         description: User not provisioned for this company
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *
 * /auth/oidc/callback:
 *   get:
 *     tags: [OIDC]
 *     summary: OIDC redirect relay (dev mode only)
 *     description: |
 *       Receives the authorization code redirect from Microsoft Entra.
 *       - **Production**: serves React SPA directly (same-origin)
 *       - **Development**: relays code to frontend dev server (localhost:3000)
 *
 *       Not called directly by clients — Microsoft Entra calls this automatically.
 *     parameters:
 *       - in: query
 *         name: code
 *         required: true
 *         schema: { type: string }
 *       - in: query
 *         name: state
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       302:
 *         description: Redirect to frontend callback
 */
