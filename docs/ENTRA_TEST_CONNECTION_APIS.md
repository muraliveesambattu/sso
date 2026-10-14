# Entra APIs Called by Test Connection, and Their Responses

All calls go to `login.microsoftonline.com`. `{t}` is the tenant ID.
Test Connection makes no Microsoft Graph calls.

The response shapes below are the standard Entra formats plus what our code reads
from each. They are not captured from a live tenant.

Source files:
- `src/services/SSO/testConnection.service.js`
- `src/controllers/testConnection.controller.js`
- `src/controllers/oidcTestCallback.controller.js`
- `src/utils/oidc/jwkValidation.util.js`
- `src/config/constants.js` (endpoint builders)

## Summary

| # | Protocol | When | Endpoint | Called by |
|---|----------|------|----------|-----------|
| 1 | OIDC | Phase 1, client-secret auth | POST `/{t}/oauth2/v2.0/token` (client_credentials) | Backend |
| 2 | OIDC | Phase 1, PKCE or certificate auth | GET `/{t}/v2.0/.well-known/openid-configuration` | Backend |
| 3 | OIDC | Popup | GET `/{t}/oauth2/v2.0/authorize` | Admin's browser |
| 4 | OIDC | Phase 2 | POST `/{t}/oauth2/v2.0/token` (authorization_code) | Backend |
| 5 | OIDC | Phase 2 | GET `/{t}/discovery/v2.0/keys` (JWKS) | Backend |
| 6 | SAML | Test | GET `/{t}/federationmetadata/2007-06/federationmetadata.xml` | Backend |

Safety limits on every backend call: HTTPS only, hosts restricted to the Microsoft
allowlist (SSRF guard), and `tenant_id` must be a UUID or common/consumers/organizations.

## 1. Token endpoint, client_credentials (OIDC Phase 1, client secret)

Purpose: proves the tenant, client_id and client secret are valid, before any user logs in.

Request: POST `https://login.microsoftonline.com/{t}/oauth2/v2.0/token`
Body: `grant_type=client_credentials`, `client_id`, `client_secret`, Graph `.default` scope.
The returned access token is not used; no call is made to graph.microsoft.com.

Success: HTTP 200. Our code checks `status == 200` and `access_token` present.

    { "token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599, "access_token": "eyJ0eXAi..." }

Failure: HTTP 400 or 401. Our code returns `"<error>: <first line of error_description>"`.

    { "error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret ...",
      "error_codes": [7000215], "timestamp": "...", "trace_id": "...", "correlation_id": "..." }

Common errors:
- AADSTS700016: application not found in the tenant
- AADSTS7000215: wrong client secret
- AADSTS90002: tenant not found

## 2. OpenID discovery (OIDC Phase 1, PKCE or certificate)

Purpose: proves the tenant exists and is reachable. A PKCE or certificate app has no
secret to check yet.

Request: GET `https://login.microsoftonline.com/{t}/v2.0/.well-known/openid-configuration`

Success: HTTP 200. Our code checks that `issuer` is present.
Message returned: "Tenant reachable - PKCE flow ready".

    { "issuer": "https://login.microsoftonline.com/{t}/v2.0",
      "authorization_endpoint": ".../oauth2/v2.0/authorize",
      "token_endpoint": ".../oauth2/v2.0/token",
      "jwks_uri": ".../discovery/v2.0/keys",
      "id_token_signing_alg_values_supported": ["RS256"] }

Failure: HTTP 400 with AADSTS90002 (unknown tenant).
Message returned: "Tenant not found or unreachable".

## 3. Authorize endpoint (popup)

Purpose: proves the app registration, the redirect URI and a real user login.

Request: the admin's browser opens
`https://login.microsoftonline.com/{t}/oauth2/v2.0/authorize` with `client_id`,
`response_type=code`, `redirect_uri`, scope, `state`, `nonce`, `prompt=login`,
and `code_challenge` (S256) for PKCE apps.

This is a browser redirect, not an API response.

Success: redirect to `redirect_uri?code=...&state=...&session_state=...`.

Failure, either of:
- redirect to `redirect_uri?error=access_denied&error_description=...`
- an Entra error page shown in the popup, with no redirect. A redirect URI mismatch
  (AADSTS50011) is this case, so our callback page never loads.

## 4. Token endpoint, authorization_code (OIDC Phase 2)

Purpose: proves the code, redirect URI and credentials are accepted by Entra.

Request: POST `https://login.microsoftonline.com/{t}/oauth2/v2.0/token`
Body: `grant_type=authorization_code`, `code`, `client_id`, `redirect_uri`, plus one of:
- `code_verifier` (PKCE, auth method none)
- `client_secret` (client secret)
- `client_assertion` + `client_assertion_type` (certificate; JWT signed with the private key)

Success: HTTP 200. Our code requires `id_token` in the body.

    { "token_type": "Bearer", "scope": "openid profile email", "expires_in": 3599,
      "access_token": "...", "refresh_token": "...", "id_token": "eyJ..." }

The id_token payload contains iss, aud, tid, oid, sub, nonce, and email or
preferred_username. roles or groups appear only if the app is configured to emit them.
Only the email is logged.

Failure: HTTP 400. Typical errors:
- `invalid_grant`: code expired or reused (AADSTS70008), or PKCE mismatch
- `invalid_client`: wrong secret or certificate

Our API then returns HTTP 400 `{ success:false, error:{ message, code } }`.
5xx and network errors are retried with exponential backoff; 400/401/403 are not.

## 5. JWKS keys (OIDC Phase 2)

Purpose: proves the id_token was genuinely signed by this tenant.

Request: GET `https://login.microsoftonline.com/{t}/discovery/v2.0/keys`

Success: HTTP 200.

    { "keys": [ { "kty": "RSA", "use": "sig", "kid": "...", "n": "...", "e": "AQAB", "x5c": ["..."] } ] }

Our code finds the key whose `kid` matches the id_token header and verifies the RS256
signature. If no key matches, or the signature is wrong, the test fails.

## 6. SAML federation metadata (SAML test)

Purpose: proves the tenant and app exist and the uploaded certificate matches Entra.
This is the only Entra call in the SAML test. There is no login in the SAML test today.

Request: GET `https://login.microsoftonline.com/{t}/federationmetadata/2007-06/federationmetadata.xml`
For a per-app certificate, `?appid={app-id}` is appended (taken from the sso_url).

Success: HTTP 200, XML.

    <EntityDescriptor entityID="https://sts.windows.net/{tenant-guid}/">
      ... <X509Certificate>MIIC...</X509Certificate> ... <SingleSignOnService .../>

Our code extracts the tenant GUID from `entityID` and compares every `X509Certificate`
entry with the uploaded certificate.

Failure: HTTP 400 or 404 for an unknown tenant or app.

## What our API returns to the console

- Phase 1 success: `{ success:true, message, data:{ sessionRef, config, ... } }`
- Phase 1 failure: `{ success:false, message:"<error>: <description>" }`
- Phase 2 success: `{ success:true, data:{ protocol:"oidc", sso_status:"active" } }`
- Phase 2 failure: `{ success:false, error:{ message, code } }`
  (codes include TC_STORE_EXPIRED, STATE_MISMATCH, NONCE_MISMATCH, plus Entra's own error code)
- SAML: success or failure with a message about the certificate or tenant

## What the test does not check

- Roles, groups, or JIT mappings (checked only at real login)
- Graph permissions or consent
- User assignment to the app, beyond the admin's own login in the popup
