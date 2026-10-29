# SAML Test Connection popup — files to change

The SAML popup is kept out of `master` on purpose. It lives on the branch
`saml-test-popup-clean` (= `master` + two commits: backend, console). This page
records every file that branch changes, so it can be reviewed, shipped or ported
to the VDI without opening the branch.

Regenerate the list at any time:

```bash
git diff --name-status master saml-test-popup-clean
```

## How the popup flow works

1. The console calls `POST /test-connection` (admin key) with `protocol: saml` and
   `company_id`. The microservice creates a test session and returns the IdP login
   URL plus a single-use `sessionRef`.
2. The console opens the login URL in a popup. After sign-in the IdP posts to the ACS
   URL; the SAML callback sees a test session, stores the result against the
   `sessionRef`, and redirects the popup to `${FRONTEND_URL}/auth/oidc/callback?saml_test=1`.
3. The popup page tells the opener it is done. The console then calls
   `POST /test-connection/saml/result` with `{ sessionRef }`. No admin key: the
   single-use `sessionRef` is the credential, as in the OIDC test callback.
4. The gateway blocks that result path (the console calls the microservice directly),
   and the Hosting rewrite routes it to the SSO service.

## Microservice (`ssoManager`, deployed as `sso-container`)

| File | Change |
|---|---|
| `src/services/Saml/samlAuthRequest.service.js` | test-session store for the AuthnRequest, result hand-off (`takeSamlTestResult`) |
| `src/services/Saml/samlCallback.service.js` | handles the SAML response for a test session |
| `src/controllers/samlCallback.Controller.js` | test branch: redirect the popup to `/auth/oidc/callback?saml_test=1` instead of minting a login |
| `src/controllers/samlTestResult.controller.js` (new) | `handleSamlTestResult` for `POST /test-connection/saml/result` |
| `src/controllers/testConnection.controller.js` | passes `company_id` through to the service |
| `src/services/SSO/testConnection.service.js` | SAML branch starts a popup test session |
| `src/routers/sso.routes.js` | registers `/test-connection/saml/result` |

## Gateway (`mdna-server-gateway`)

| File | Change |
|---|---|
| `api/ssoGateway.js` | adds `/auth/test-connection/saml/result` and `/v1/...` to `BLOCKED_PATHS` |
| `README.md` | one-line note for the blocked result path |
| `test/ssoGateway.test.js` | covers the new blocked paths |

## Console

| Mac file | Where it goes in the VDI console |
|---|---|
| `mdna-console/rewrites.sso.template` | Hosting rewrite: `/auth/test-connection/saml/result` → `${SSO_SERVICE}` / `${REGION}` |
| `vdi-reference/mdna-console/src/hooks/useTestConnection.js` | `src/hooks/useTestConnection.js` — popup flow, `tc_saml_done` handshake, result call |
| `vdi-reference/mdna-console/src/services/ssoApi.js` (`testSamlResultApi` export only) | add `testSamlResultApi` to `src/services/ssoApi.js`, after `testConnectionCallbackApi` |
| `vdi-reference/mdna-console/src/views/auth-views/authentication/oidc-callback/index.js` | `src/views/auth-views/authentication/oidc-callback/index.js` — recognise `?saml_test=1` and signal done |

Port hunks only. A whole-file paste from the Mac copy drops VDI-only lines (this
happened with `saveSsoConfig.controller.js` and `client_secret_enc`).

## Tests

`test/samlAuthRequest.service.test.js`, `test/samlCallback.controller.test.js`,
`test/samlCallback.service.test.js`, `test/samlTestResult.controller.test.js` (new),
`test/sso.routes.test.js`, `test/testConnection.controller.test.js`,
`test/testConnection.service.test.js`.

## Deploy notes

- Microservice: build and deploy `sso-container` per `docs/guide/SSO_Deployment_Guide.md`
  (sections 2.4 to 2.6, subsequent deploy).
- Hosting: the rewrite template change needs the console hosting deploy.
- Not yet done: end-to-end gateway test, and the popup flow test on emc.
