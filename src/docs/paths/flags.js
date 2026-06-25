/**
 * @openapi
 * /auth/admin/flags/{company_id}:
 *   get:
 *     tags: [Admin]
 *     summary: Get feature flags for a company
 *     description: |
 *       Returns current state of all feature flags for a company.
 *
 *       **Flag priority (highest wins):**
 *       1. `FEATURE_<FLAG>_DISABLED=true` env var → global kill switch
 *       2. DB row per company → per-company control
 *       3. Default (true) → if no DB row found
 *
 *       🔐 **Requires X-Admin-API-Key header**
 *     security:
 *       - AdminApiKey: []
 *     parameters:
 *       - in: path
 *         name: company_id
 *         required: true
 *         schema: { type: string }
 *         example: zdna-gmail-local-com-123
 *     responses:
 *       200:
 *         description: Feature flags for company
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:     { type: boolean, example: true }
 *                 company_id:  { type: string }
 *                 valid_flags: { type: array, items: { type: string } }
 *                 flags:
 *                   type: object
 *                   properties:
 *                     sso_enabled:
 *                       type: object
 *                       properties:
 *                         enabled: { type: boolean, example: true }
 *                         source:  { type: string, enum: [database, default, env_override] }
 *                     jit_enabled:
 *                       type: object
 *                       properties:
 *                         enabled: { type: boolean, example: true }
 *                         source:  { type: string, enum: [database, default, env_override] }
 *             example:
 *               success: true
 *               company_id: zdna-gmail-local-com-123
 *               valid_flags: [sso_enabled, jit_enabled]
 *               flags:
 *                 sso_enabled: { enabled: true, source: default }
 *                 jit_enabled: { enabled: false, source: database }
 *       401:
 *         description: Missing API key
 *       403:
 *         description: Invalid API key
 *
 * /auth/admin/flags:
 *   post:
 *     tags: [Admin]
 *     summary: Set a feature flag for a company
 *     description: |
 *       Enables or disables a feature flag for a specific company.
 *       Takes effect **immediately** — no restart required.
 *       Every change is recorded in the audit log.
 *
 *       **Available flags:**
 *       - `sso_enabled` — master SSO switch. When false, all SSO login attempts
 *         for this company return "SSO not configured" immediately.
 *       - `jit_enabled` — JIT user provisioning. When false, only pre-provisioned
 *         users can log in via SSO. New users are blocked.
 *
 *       **Emergency kill switch (all companies):**
 *       Set env var `FEATURE_SSO_ENABLED_DISABLED=true` on Cloud Run to
 *       immediately disable SSO for ALL companies without a DB change.
 *
 *       🔐 **Requires X-Admin-API-Key header**
 *     security:
 *       - AdminApiKey: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [company_id, flag, enabled]
 *             properties:
 *               company_id: { type: string, example: zdna-gmail-local-com-123 }
 *               flag:       { type: string, enum: [sso_enabled, jit_enabled], example: sso_enabled }
 *               enabled:    { type: boolean, example: false }
 *           examples:
 *             disableSSO:
 *               summary: Disable SSO for a company
 *               value: { company_id: zdna-gmail-local-com-123, flag: sso_enabled, enabled: false }
 *             disableJIT:
 *               summary: Disable JIT provisioning
 *               value: { company_id: zdna-gmail-local-com-123, flag: jit_enabled, enabled: false }
 *             enableSSO:
 *               summary: Re-enable SSO
 *               value: { company_id: zdna-gmail-local-com-123, flag: sso_enabled, enabled: true }
 *     responses:
 *       200:
 *         description: Flag updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:    { type: boolean, example: true }
 *                 company_id: { type: string }
 *                 flag:       { type: string }
 *                 enabled:    { type: boolean }
 *                 message:    { type: string }
 *             example:
 *               success: true
 *               company_id: zdna-gmail-local-com-123
 *               flag: sso_enabled
 *               enabled: false
 *               message: "Flag 'sso_enabled' set to false for company 'zdna-gmail-local-com-123'"
 *       400:
 *         description: Invalid flag name or missing fields
 *       401:
 *         description: Missing API key
 *       403:
 *         description: Invalid API key
 */
