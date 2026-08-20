# Required Environment Variables

Minimum set to run. Full reference: [ENVIRONMENT.md](ENVIRONMENT.md).

## SSO Microservice

```bash
# Server
SESSION_SECRET=

# Crypto — exactly 64 hex chars
ENCRYPTION_KEY=

# Admin API key — same value as the gateway's SSO_ADMIN_API_KEY
ADMIN_API_KEY=

# CORS — comma-separated console origins
CLIENT_URL=

# Database — Cloud Run
DATABASE_URL=postgresql://USER:PASS@localhost/DB?host=/cloudsql/PROJECT:REGION:INSTANCE
# Database — local dev (use instead of DATABASE_URL)
# DB_HOST=localhost
# DB_PORT=5432
# DB_NAME=
# DB_USER=
# DB_PASSWORD=

# Firebase Admin SDK
FIREBASE_PROJECT_ID=
FIREBASE_CLIENT_EMAIL=
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"

# URLs — have localhost defaults, so always set these when deployed
FRONTEND_URL=
OIDC_REDIRECT_URI=
SAML_ENTITY_ID=
SAML_ACS_URL=
```

Generate the secrets:

```bash
# SESSION_SECRET
node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"
# ENCRYPTION_KEY
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# ADMIN_API_KEY
node -e "console.log('zdna_' + require('crypto').randomBytes(32).toString('hex'))"
```

## Gateway (MDNA-Server monolith)

In `env/application.properties.js`:

```
SSO_BASE_URL        = https://sso-xxxxx.us-central1.run.app
SSO_ADMIN_API_KEY   = <same value as the microservice's ADMIN_API_KEY>
```

## Gotchas

- `ADMIN_API_KEY` and `SSO_ADMIN_API_KEY` must be **byte-identical** — a
  mismatch (including a trailing newline) gives `403 INVALID_API_KEY`.
- Empty `CLIENT_URL` rejects every browser request with `CORS_ERROR`.
- No database vars set → in-memory fallback: writes return `201` but nothing
  persists.
- On Cloud Run, pin explicit secret versions, not `latest`.
