# SSO Gateway — drop-in for MDNA-Server monolith

Single choke-point where the MDNA Console reaches the SSO microservice's ADMIN
endpoints. Verifies the console user's Firebase ID token, then forwards the
request to the SSO service with `X-Admin-API-Key` attached server-side (the key
never reaches the browser).

## 1. Place the file
Copy `api/ssoGateway.js` into the monolith at:
```
MDNA-Server/CloudFunctions/functions/api/ssoGateway.js
```

## 2. Wire it into index.js
```js
const ssoGateway = require('./api/ssoGateway')
// ... alongside the other exports ...
exports.ssogateway = ssoGateway.ssoGateway
```

## 3. Add the two env values to env/application.properties.js
Follow the exact pattern of an existing secret in that file:
```
SSO_BASE_URL        = https://sso-323173671147.us-central1.run.app   # emc SSO service Cloud Run URL
SSO_ADMIN_API_KEY   = <the SSO service's ADMIN_API_KEY>              # store like other secrets (encrypt/placeholder)
```

## 4. Deploy via Gerrit → Jenkins (NOT manual firebase deploy)
This is the shared monolith; deploys go through the normal pipeline
(`jenkindeployment-demo`).

## 5. Smoke test after deploy
```bash
# a) health — no auth → 200
curl https://<gateway-url>/gateway/health
# b) allowed route, no token → 401 UNAUTHENTICATED
curl -X POST https://<gateway-url>/auth/domain-check
# c) with a real Firebase ID token → proxied SSO response
curl -X POST https://<gateway-url>/auth/test-connection \
     -H "Authorization: Bearer <idToken>" -H "Content-Type: application/json" -d '{}'
```
If (a) returns 404 instead of 200, the Express app is seeing a function-name
prefix in `req.path` — adjust `ALLOWED_PREFIXES` (or the mount) accordingly.
This is the one runtime unknown; the health probe surfaces it immediately.

## Verified against the monolith snapshot
- `STATUS` imports from `../util/constant` (used by validatorService) ✓
- `createExpressApp` applies the shared `CORSOPTIONS` (same CORS as every other
  console-facing function) ✓
- `isAuthenticatedHSTS` ALWAYS resolves with `{ status }` (never throws) — the
  auth check tests `status === STATUS.SUCCESS`, so anonymous callers are rejected ✓

## Design note — what is NOT routed here
Login/browser flows call the SSO service directly and must not go through the
authenticated gateway:
`/auth/domain-check`, `/auth/oidc/callback`, `/auth/oidc/token-exchange`,
`/auth/callback` (SAML ACS), `/auth/test-connection/oidc/callback`.
