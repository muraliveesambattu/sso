/**
 * @openapi
 * /auth/callback:
 *   post:
 *     tags: [SAML]
 *     summary: SAML 2.0 Assertion Consumer Service (ACS) endpoint
 *     description: |
 *       Receives the SAML assertion POST from Microsoft Entra after successful login.
 *       - Validates the SAML response XML signature
 *       - Extracts user identity claims
 *       - JIT-provisions or updates user in PostgreSQL
 *       - Generates Firebase Custom Token
 *       - Redirects frontend with token
 *
 *       Not called directly by clients — Microsoft Entra POSTs here automatically.
 *
 *       **Rate limited:** 20 requests / IP / 5 minutes.
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             properties:
 *               SAMLResponse:
 *                 type: string
 *                 description: Base64-encoded SAML assertion from Microsoft Entra
 *               RelayState:
 *                 type: string
 *                 description: Session relay state
 *     responses:
 *       302:
 *         description: Redirect to frontend with Firebase token
 *       401:
 *         description: SAML assertion validation failed
 *
 * /auth/metadata:
 *   get:
 *     tags: [SAML]
 *     summary: SAML Service Provider metadata
 *     description: |
 *       Returns SP metadata XML for registration in Microsoft Entra.
 *       Upload this XML to Azure Portal → Enterprise Applications → SAML Setup.
 *     responses:
 *       200:
 *         description: SP metadata XML
 *         content:
 *           application/xml:
 *             schema:
 *               type: string
 */
