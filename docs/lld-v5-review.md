# SSO OIDC LLD V5 — Design ↔ Implementation Review

Review of `SSO OIDC_LLD_V5.docx` against the actual backend implementation in this
repo (`zdna-sso-latest`). Based on document screens 1–28 (screen 29 tail not
reviewed). Date: 2026-07-20.

Files cross-referenced:
- `src/services/oidc/oidcTokenExchange.service.js`
- `src/services/SSO/userResolution.service.js`
- `src/services/SSO/permissionResolver.service.js`
- `src/utils/firebase/firebaseAdmin.util.js`
- `src/utils/oidc/tokenValidation.util.js`
- `src/utils/oidc/jwkValidation.util.js`
- `src/utils/oidc/GraphApi.utils.js`
- `src/utils/oidc/tokenExchange.util.js`
- `src/services/SSO/saveSsoConfig.service.js`, `src/routers/sso.routes.js`

Summary: the **security-critical crypto/validation path matches the LLD closely**.
The **drift is concentrated in JIT/role resolution, session issuance, and an
undocumented permission-resolution layer.** Two behavioral conflicts are
security-relevant and should be resolved deliberately.

---

## ✅ Strong alignment — crypto / validation path

| LLD § | Implementation | Status |
|---|---|---|
| 7.3 three auth methods (secret / cert / PKCE) | `tokenExchange.util.js` `buildRequestParams` + `resolveAuthCredential` | Match |
| 7.3 Method B JWT assertion (RS256, `x5t`, `aud/iss/sub/jti/exp`) | `generateJwtAssertion` | Match (exact) |
| 7.4 RS256 algorithm pinning (reject none/HS256) | `jwkValidation.util.js` `if (header.alg !== 'RS256') throw` | Match |
| 7.4 JWKS `kid` match + RSA-SHA256 verify | `verifyJwtSignature` | Match |
| 7.5 iss / aud / exp / nbf / iat / nonce | `tokenValidation.util.js` `validateTokenClaims` | Match |
| 7.5 tid cross-check | `oidcTokenExchange.service.js` Step 7.5 | Match (in service, not util) |
| 7.7 email + oid required, `preferred_username`/`upn` fallback | `validateUserClaims` | Match |
| 8.2 groups overage → Graph `/me/memberOf` pagination | `GraphApi.utils.js` `fetchUserGroupsFromGraph` | Match |
| 7.6 / step 11 zero id_token/access_token after use | Step 11 nulls tokens | Match |

Also correct: nonce/state single-use, TLS `rejectUnauthorized` in prod, no-retry
on single-use auth code, `iss` handling for `common`/`consumers`
(MSA `9188040d-6c67-4c5b-b112-36a304b66dad`).

---

## ⚠️ Discrepancies (spec ↔ code drift), ranked

### 1. JIT "no matching rule" — doc REJECTS, code allows login with NO role (fail-open)  [HIGH]
- LLD 8.2 §7c: "No Matching Rule → Authentication rejected."
- Code: `resolveRoles` (userResolution.service.js) — no match falls to a `default`
  mapping; if no default, returns **empty roles and login proceeds** (user gets no
  role). This is the fail-open behavior.
- Action: decide whether to reject (match LLD) or document default-allow. Security-relevant.

### 2. Graph attribute failure — doc REJECTS, code CONTINUES  [MED-HIGH]
- LLD 8.2 §7a/b: Graph failure / missing attributes → "Authentication rejected."
- Code: `fetchUserProfileFromGraph` (department/jobtitle) is wrapped in try/catch in
  `oidcTokenExchange.service.js` — on failure it **logs and continues**; login is not
  rejected. Direct contradiction.

### 3. JIT-OFF role source — doc says Firestore, code uses Postgres  [MED]
- LLD 8.3: `admin.firestore().collection('users').where('email'==).where('tenant_id'==)`.
- Code: `resolveUser` JIT-OFF path uses `findUserByOid`/`findUserByEmail` → **Postgres
  `sso_users`** (via `ssoDataService`/`postgresSSO`), not Firestore.

### 4. Table name: `jit_configurations` (doc) vs `jit_mappings` (code)  [LOW]
- LLD 8.2 SQL selects `FROM jit_configurations`; code table is `jit_mappings`.
  The LLD's own §2.1 schema diagram labels it `jit_mapping` — internally inconsistent.

### 5. Firebase custom token — uid and claims differ  [MED]
- LLD 8.2/9: `createCustomToken(ssoContext.oid, { email, tenant_id, role_id })`.
- Code (`firebaseAdmin.util.js` `generateCustomToken`): uid = `resolution.user.user_id`
  (ZDNA id, not `oid`); claims are richer — `companyId`, `role`, `loginType:'entra'`,
  `zdnaRoles`, `zdnaPermissions` (+ `zdnaPermissionsRef` when oversized). Doc shape
  doesn't reflect what's minted.

### 6. Clock skew: doc ±60s, code ±300s  [LOW]
- LLD 7.5 says ±60 seconds; code `CLOCK_SKEW_SECONDS = 300` (5 min). `MAX_TOKEN_AGE_SECONDS
  = 3600`. The LLD's "5-minute window" refers to the session/state TTL, not token age.

### 7. LLD 7.5 table typo — `aud` failure code shows `NONCE_MISMATCH`  [LOW]
- Code returns `INVALID_AUDIENCE` (and `INVALID_NONCE`/`MISSING_NONCE` for nonce).
  Table failure codes need a cleanup pass to match `tokenValidation.util.js`.

### 8. Potential cert-path bug — field-name mismatch  [MED, verify]
- `resolveAuthCredential` reads `oidcConfig.client_cert_enc`; the save path
  (`buildOidcRow`) stores the key as `private_key_enc`. Unless `postgresSSO.getOidcConfig`
  re-maps it, the `private_key_jwt` (certificate) flow reads `undefined`. Needs a direct
  test with the certificate auth method.

---

## 🕳️ Gaps (implemented but undocumented, or vice-versa)

- **Permission resolution is entirely undocumented.** LLD's role model stops at `role_id`.
  Code has `permissionResolver.service.js` (RMS → Firestore role-config → `zdna_roles`
  union) and writes a per-user Firestore `userPermissions/permissionList` doc via
  `writeUserPermissions`. Add a "Permission Resolution" section to the LLD.
- **Undocumented JIT sources:** code's `matchesMapping` also supports `jobtitle`, a
  `default` fallback, and arbitrary Entra claim names; LLD lists only group/dept/role.
- **Graph `appRoleAssignments`:** LLD 8.2 lists `GET /me/appRoleAssignments`; code gets
  app roles from the id_token `roles` claim, not Graph. (Graph is used only for
  groups-overage and department/jobtitle.)
- **Gateway / ID-token frontend architecture** (ssoGateway, same-origin rewrites, admin
  key kept off the browser) isn't in the LLD — arguably out of this doc's OIDC-login scope.

---

## Recommendations

1. Resolve the two behavioral conflicts (#1, #2) deliberately — decide reject vs proceed
   for no-role and Graph-failure, then make doc and code agree.
2. Fix the data-source/table/uid drifts (#3, #4, #5) in the LLD to reflect Postgres
   `sso_users`, `jit_mappings`, and the real custom-token uid/claims.
3. Add a "Permission Resolution" section to the LLD (RMS/role-config/zdna_roles +
   Firestore `permissionList` write).
4. Verify the cert-path field name (#8) with an actual `private_key_jwt` test.
5. Tidy the 7.5 failure codes and the ±60s/±300s skew (#6, #7).
