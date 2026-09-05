# SSO Deployment Guide

Two components deploy independently:

- **Section 1 — MDNA-Console** (React app + `ssoGateway` function). Deployed by
  `Deployment.bat`, which generates `firebase.json` from a template.
- **Section 2 — ssoManager** (the SSO microservice). Deployed as a **container
  on Cloud Run**. Database migrations run automatically at container start.
- **Section 3 — MDNA-Server**, for the SSO invitation email function.

Placeholders: `<PROJECT_ID>` target project · `<REGION>` e.g. `us-central1` ·
`<INSTANCE>` Cloud SQL instance · `<REPO>` Artifact Registry repository ·
`<BASE_URL>` Console origin, e.g. `https://<PROJECT_ID>.web.app`.

---

# Section 1: MDNA-Console

## 1.1 Feature flags

Three flags gate the SSO UI. Create each as a system flag, then a tenant flag:

```bash
curl -X POST 'https://<REGION>-<PROJECT_ID>.cloudfunctions.net/createSystemFeatureFlag/<FLAG>' \
  -H 'Authorization: Bearer <WHITE_LISTED_TOKEN>' -H 'Content-Type: application/json' \
  -d '{ "systemEnabled": 1, "isSystemOverride": 1, "status": "beta", "description": "<desc>" }'

curl -X POST 'https://<REGION>-<PROJECT_ID>.cloudfunctions.net/addTenantFeatureFlag/<FLAG>' \
  -H 'Authorization: Bearer <WHITE_LISTED_TOKEN>' -H 'Content-Type: application/json' \
  -d '{ "value": 1 }'
```

| `<FLAG>` | Controls |
|---|---|
| `Integration_module` | SSO Integration card in Connected Services |
| `login_method_enabled` | Login Method column and dropdown in User Management |
| `sso_enabled` | Availability of Microsoft Entra SSO authentication |

`isSystemOverride = 1` means the system flag overrides tenant configuration;
`0` means tenant configuration decides.

Then add them to the Console build:

```bash
REACT_APP_FEATURE_FLAGS=<existing>,Integration_module,login_method_enabled,sso_enabled
```

> These Console flags are a **different mechanism** from the microservice's own
> `sso_enabled` / `jit_enabled` flags. Console flags control UI visibility; the
> microservice flags control whether SSO login is honoured at request time.

## 1.2 Console environment variables

Every URL derives from one value — the Console origin. Only that first value is
a decision; the rest follow.

| Variable | Value |
|---|---|
| `REACT_APP_MICROSERVICE_API_URL` | `/` |
| `REACT_APP_SSO_API_BASE` | *(empty)* |
| `REACT_APP_SSO_API_BASE_GATEWAY` | *(empty)* |
| `REACT_APP_OIDC_REDIRECT_URI` | `<BASE_URL>/auth/oidc/callback` |
| `REACT_APP_SAML_ACS_URL` | `<BASE_URL>/auth/callback` |
| `REACT_APP_SAML_ENTITY_ID` | `<BASE_URL>/auth/metadata2` |
| `REACT_APP_VALID_HOST` | `<BASE_URL>/` |

The two `SSO_API_BASE*` templates already include the trailing slash;
`MICROSERVICE_API_URL` does not. A missing value produces the literal string
`undefined/auth/...`.

> **Keep `REACT_APP_SSO_API_BASE_GATEWAY` empty.** That makes admin calls
> same-origin so the Hosting rewrites route them. An absolute Cloud Run URL
> bypasses the rewrites and introduces a cross-origin preflight — which fails if
> the gateway build predates its `app.options('*')` handler.

> **Check for duplicate definitions.** A second `REACT_APP_MICROSERVICE_API_URL`
> later in `.env` silently wins. A value of `/` satisfies `domain-check` (which
> uses the Hosting rewrite) while failing the `https://` guard in
> `OIDCCallback`, so login redirects to `/auth/login` with no network call and no
> error — one of the hardest failures here to diagnose.

## 1.3 Hosting rewrites

`firebase.json` is **generated at deploy time** and gitignored. The tracked
sources are:

| File | Purpose |
|---|---|
| `firebase.json.template` | Whole file, with `${REGION}` / `${SSO_SERVICE}` / `${GATEWAY_FUNCTION}` placeholders and `__SSO_REWRITES__` where the SSO routes go |
| `rewrites.sso.template` | The 7 SSO rewrites, injected only when SSO is enabled |

The assembled rewrite table:

| Path | Target |
|---|---|
| `/auth/sso/**` `/auth/test-connection` `/auth/admin/flags/**` | `ssoGateway` function |
| `/auth/domain-check` `/auth/test-connection/oidc/callback` `/auth/oidc/token-exchange` `/auth/callback` | `sso-container` Cloud Run service |
| `**` | `/index.html` (SPA) |

> `/auth/oidc/callback` must **not** be rewritten — it is the SPA route the
> Entra redirect URL targets.

> The gateway's `SSO_BASE_URL` and these `run` rewrites must name the **same
> service**. If they diverge, a login flow starts on one service and completes on
> another; the in-process session store then fails with `TC_STORE_EXPIRED`.

### Creating the template (one-time)

Generate it from the real file rather than hand-writing it — the `headers` block
contains a long `Feature-Policy` value that must not be retyped. In PowerShell:

```powershell
copy firebase.json firebase.json.template

$t = Get-Content firebase.json.template -Raw
$t = $t.Replace('"us-central1"', '"${REGION}"')
$t = $t.Replace('"serviceId": "sso-container"', '"serviceId": "${SSO_SERVICE}"')
$t = $t.Replace('"functionId": "ssoGateway"', '"functionId": "${GATEWAY_FUNCTION}"')
Set-Content firebase.json.template -Value $t -NoNewline
```

`.Replace()` rather than `-replace`: the latter treats the pattern as a regex and
expands `$` in the replacement as a capture-group reference, so `${REGION}`
would not survive.

Then replace the `"rewrites": [ ... ],` block in the template with:

```
    "rewrites": [
__SSO_REWRITES__
      {
        "source": "**",
        "destination": "/index.html"
      }
    ],
```

and move the 7 SSO entries into `rewrites.sso.template`, each ending with a
comma.

Finally, stop tracking the generated file:

```powershell
git rm --cached -f firebase.json
Add-Content .gitignore "firebase.json"
```

`Add-Content`, not `>>` — PowerShell 5.1's `>>` writes UTF-16 and corrupts a
UTF-8 `.gitignore`.

## 1.4 Deploying the Console

```
Deployment.bat <GCP_PROJECT_ID> [sso_enabled]
```

| Command | Result |
|---|---|
| `Deployment.bat dnacloud-demo2-t sso_enabled` | 8 rewrites — SSO routes live |
| `Deployment.bat dnacloud-demo2-t` | 1 rewrite — SPA routing only, no `/auth/**` |
| `Deployment.bat <unknown-project>` | Aborts before doing anything |
| `Deployment.bat <project> sso-enabled` | Aborts — unrecognised option |

### What the script does

1. Confirms the project-ID interactively
2. Parses the SSO flag. An unrecognised second argument **aborts**, so a typo
   cannot silently deploy without the SSO routes
3. Resolves `REGION`, `SSO_SERVICE`, `GATEWAY_FUNCTION` from a per-project block.
   Adding an environment means adding one block; nothing else in the file changes
4. Installs the Firebase CLI, logs out and back in, selects the project
5. Generates `firebase.json` from the template, injecting `rewrites.sso.template`
   only if the flag was passed
6. Validates the generated file parses as JSON — aborts if not
7. `npm install`, `npm run build`, `firebase deploy`

### Adding a new environment

```bat
) else if /I "%1"=="<project-id>" (
    set "REGION=<region>"
    set "SSO_SERVICE=<cloud-run-service>"
    set "GATEWAY_FUNCTION=ssoGateway"
```

### Local development

`firebase serve` and the emulators need `firebase.json` present. Generate it
once:

```powershell
$c = Get-Content firebase.json.template -Raw
$c = $c.Replace('__SSO_REWRITES__', (Get-Content rewrites.sso.template -Raw))
$c = $c.Replace('${REGION}','us-central1').Replace('${SSO_SERVICE}','sso-container').Replace('${GATEWAY_FUNCTION}','ssoGateway')
Set-Content firebase.json -Value $c -NoNewline
```

## 1.5 Console verification

1. Sign in to the Console
2. Connected Services → the SSO Integration card is displayed
3. User Management → the Login Method column and dropdown are displayed
4. Microsoft Entra SSO is offered as a login method
5. Complete one SSO login end to end

---

# Section 2: ssoManager (the microservice)

## 2.1 Prerequisites

| Prerequisite | Notes |
|---|---|
| Cloud SQL Postgres | Private IP, to match `--vpc-egress=private-ranges-only` |
| VPC network + subnet | `<PROJECT_ID>-gke-vpc` / `-gke-subnet`. Confirm whether these are per-project or shared GKE infrastructure, and who owns them |
| Database + DB role | Migrations run *against* an existing database; they don't create one |
| Artifact Registry repo | **Never `gcf-artifacts`** — Firebase's cleanup policy deletes images and strands the service. Creating a repo needs `artifactregistry.repositories.create`, often not granted; verify before planning a new environment |
| 4 Secret Manager secrets | `ADMIN_API_KEY`, `SESSION_SECRET`, `ENCRYPTION_KEY`, `DATABASE_URL` |
| IAM | Cloud Run runtime service account needs `roles/secretmanager.secretAccessor` |

### Create the database and role

```sql
CREATE DATABASE "SSO_Microservice";
CREATE USER sso_user WITH PASSWORD '<STRONG_PASSWORD>';
GRANT ALL PRIVILEGES ON DATABASE "SSO_Microservice" TO sso_user;
```

> **Percent-encode** `: / ? # @` in the password when building `DATABASE_URL`
> (`@` → `%40`). `src/config/db.js` parses with `new URL(...)`, which reads an
> unencoded `@` as the userinfo delimiter and silently points the connection at
> the wrong host. The discrete `DB_*` variables take the plain password.

### Generate and store the secrets

Use `printf '%s'`, never `echo` — a trailing newline changes the byte length and
breaks the timing-safe comparison in `requireAdminKey` with no useful error.

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"        # SESSION_SECRET
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"           # ENCRYPTION_KEY — exactly 64 hex chars
node -e "console.log('zdna_' + require('crypto').randomBytes(32).toString('hex'))" # ADMIN_API_KEY
```

`DATABASE_URL` is the Cloud SQL socket form:

```
postgresql://sso_user:<URL_ENCODED_PASSWORD>@localhost/SSO_Microservice?host=/cloudsql/<PROJECT_ID>:<REGION>:<INSTANCE>
```

```bash
gcloud secrets create <NAME> --replication-policy=automatic --project=<PROJECT_ID>
printf '%s' '<value>' | gcloud secrets versions add <NAME> --data-file=- --project=<PROJECT_ID>
```

> **Pin explicit versions** in the deploy command (`ADMIN_API_KEY:2`), never
> `latest` — otherwise a new secret version silently changes the running config.
>
> **Never rotate `ENCRYPTION_KEY`.** It decrypts client secrets already stored in
> Postgres; a new value makes every saved SSO config undecryptable.
>
> `ADMIN_API_KEY` must be **byte-identical** to the gateway's
> `SSO_ADMIN_API_KEY`. A mismatch gives `403 INVALID_API_KEY`; an absent header
> gives `401 MISSING_ID_TOKEN`, because the gateway does not forward the caller's
> `Authorization` header.

## 2.2 Service environment variables

**Always required**

| Variable | Purpose |
|---|---|
| `NODE_ENV` | `production` |
| `FRONTEND_URL` | Post-login redirect target |
| `CLIENT_URL` | CORS allowlist, comma-separated |
| `DEFAULT_ORIGINS` | CORS baseline, merged with `CLIENT_URL` |
| `OIDC_REDIRECT_URI` | Must match the Entra app registration |
| `DATABASE_URL` | Secret Manager |
| `ADMIN_API_KEY` `SESSION_SECRET` `ENCRYPTION_KEY` | Secret Manager |

> With `CLIENT_URL` and `DEFAULT_ORIGINS` both empty the service starts and
> rejects **every** browser request with `CORS_ERROR`, logging only a
> `cors_allowlist_empty` warning. There is no deploy-time error.

**Required only if SAML is enabled**

| Variable | Purpose |
|---|---|
| `SAML_ENTITY_ID` / `SAML_ACS_URL` | SP identifier and ACS URL — must match Entra exactly |
| `SP_PRIVATE_KEY_B64` | Only when signed AuthnRequests are required. Without it the startup log reads `[SAML] SP private key not found — AuthnRequest will be unsigned` |

**Required only if RMS integration is enabled**

`ROLE_MANAGEMENT_SERVICE_URL` · `RMS_OAUTH_TOKEN_URL` ·
`RMS_OAUTH_AUTHORIZATION_KEY` — all three, or RMS is skipped entirely. Optional
`RMS_TIMEOUT_MS` (3000), `DNS_URL`.

**Optional** `PORT`, `LOG_LEVEL`. **Local development only** `DB_HOST` `DB_PORT`
`DB_NAME` `DB_USER` `DB_PASSWORD`, and the `FIREBASE_*` Admin SDK trio.

An OIDC-only launch needs the always-required block and nothing else.

## 2.3 The Dockerfile

Three requirements are non-obvious; each was found by failure.

| Requirement | Why |
|---|---|
| `apt-get install openssl` | `pkcs12.util.js` spawns the openssl **CLI** for `.pfx` bundles (certificate auth). `node:22-slim` ships libssl but not the binary — this fails at runtime on cert configs, not at build |
| `mkdir -p /app/logs && chown -R node:node /app` **before** `USER node` | `logger.js` adds a file transport under `NODE_ENV=production`; without the directory it throws `EACCES` before `app.listen()`, and Cloud Run reports only "failed to start and listen on PORT" |
| `CMD ["sh","-c","node scripts/migrate.js && node server.js"]` | Runs migrations, then the server. Bypasses `index.js` (the Functions wrapper); `server.js` guards its listener with `require.main === module` |

## 2.4 Get the source to a build machine

Gerrit is an internal host with no public DNS, so `git clone` fails from Cloud
Shell. Archive on the VDI and upload.

```powershell
cd MDNA-Server\zDNAMicroservice
tar -a -c -f ssoManager.zip --exclude=node_modules --exclude=.git ssoManager
```

Cloud Shell **⋮ → Upload**, then:

```bash
rm -rf ~/build; mkdir -p ~/build; cd ~/build; unzip -o ~/ssoManager.zip; chmod -R u+rwX .
```

> The `chmod` is **required**. A Windows-created zip loses the execute bit on
> directories; without it `ls`, `rm` and the build all fail with
> `Permission denied`, and `&&` chains silently stop at the first failure.

Confirm what you're about to build:

```bash
ls src/database/migrations | wc -l && tail -1 Dockerfile
```

## 2.5 Build

```bash
gcloud builds submit --tag <REGION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/sso-container:<TAG> .
```

Cloud Build does the work — no local Docker needed. Bump `<TAG>` every build;
reusing one loses your rollback target.

> `gcloud run deploy --source` does **not** work here — it insists on creating a
> `cloud-run-source-deploy` repository, which needs a permission you may not
> have. `builds submit --tag` lets you name an existing repo.

> `ERROR: The build is running, and logs are being written to the default logs
> bucket. This tool can only stream logs if you are Viewer/Owner` is **not a
> build failure** — only log streaming is blocked. Confirm the result with:
>
> ```bash
> gcloud artifacts docker images list <REGION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/sso-container --include-tags
> ```

## 2.6 Deploy

**First deploy on an environment** — establishes everything:

```bash
gcloud run deploy sso-container \
  --image <REGION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/sso-container:<TAG> \
  --region <REGION> --project <PROJECT_ID> \
  --allow-unauthenticated --memory 1Gi --cpu 2 --timeout 300 --max-instances 1 \
  --add-cloudsql-instances <PROJECT_ID>:<REGION>:<INSTANCE> \
  --network=<PROJECT_ID>-gke-vpc --subnet=<PROJECT_ID>-gke-subnet \
  --vpc-egress=private-ranges-only \
  --set-secrets 'ADMIN_API_KEY=ADMIN_API_KEY:<VER>,SESSION_SECRET=SESSION_SECRET:<VER>,ENCRYPTION_KEY=ENCRYPTION_KEY:<VER>,DATABASE_URL=DATABASE_URL:<VER>' \
  --set-env-vars '^|^NODE_ENV=production|FRONTEND_URL=<BASE_URL>|CLIENT_URL=<BASE_URL>|DEFAULT_ORIGINS=<BASE_URL>|OIDC_REDIRECT_URI=<BASE_URL>/auth/oidc/callback|SAML_ACS_URL=<BASE_URL>/auth/callback|SAML_ENTITY_ID=<BASE_URL>/auth/metadata2'
```

**Subsequent deploys** — `--image` alone preserves env vars, secrets, Cloud SQL
and VPC settings:

```bash
gcloud run deploy sso-container --image <...>:<TAG> --region <REGION> --project <PROJECT_ID>
```

### Why these flags

**`--max-instances 1` is load-bearing, not a cost control.** The service holds
OIDC state, SAML request IDs, admin test-connection sessions and express-session
data in **in-process memory**. A login flow starts on one request and completes
on another; if those land on different instances it fails, typically as
`TC_STORE_EXPIRED` or a lost OIDC state. Do not raise it until those stores are
backed by Postgres or Redis.

**`--set-env-vars` and `--set-secrets` replace the entire set** — they do not
merge. Omit a variable and it is gone from the next revision.

**`^|^` is the delimiter** because `DATABASE_URL` contains `@`; the more common
`^@^` truncates it into an invalid URL.

**All three network flags are required.** The Cloud SQL socket alone is not
enough on a private-IP instance — without VPC egress the connection fails with
`read ECONNRESET` after roughly eight seconds and the database reports unhealthy.

## 2.7 Database migrations

**They run automatically at container start** — the last line of the Dockerfile:

```dockerfile
CMD ["sh", "-c", "node scripts/migrate.js && node server.js"]
```

Same pattern as `roleManagement`. On each start the migrator compares the files
in `src/database/migrations/` against the `SequelizeMeta` table, applies anything
pending, then starts the server. Nothing pending costs one lookup.

**A failed migration exits non-zero, so the container never starts and the
revision never takes traffic** — the deploy fails rather than serving against a
schema the code does not expect.

> `node scripts/migrate.js`, not `npx sequelize-cli db:migrate`: `sequelize-cli`
> is a devDependency and is stripped by `npm ci --omit=dev`. The script uses
> `umzug`, a runtime dependency.

### The schema

Nine tables: `sso_integrations`, `oidc_configurations`, `saml_configurations`,
`jit_mappings`, `sso_users`, `audit_logs`, `feature_flags`, `sso_domains`, and
`SequelizeMeta` — the ledger, capital S and M.

### Running them anywhere else

Generally you can't, and don't need to. On a private-IP instance **no
workstation can reach the database** — not Cloud Shell, not a corporate machine.
The Cloud SQL Auth Proxy fails with `instance does not have IP of type "PUBLIC"`
or `dial tcp <ip>:3307: i/o timeout`. The container runs inside the VPC, which is
why startup is the right trigger.

For read-only inspection use **Cloud SQL Studio**, which runs inside Google's
network:

```sql
SELECT name FROM "SequelizeMeta" ORDER BY name;
SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;
```

`npm run migrate:status` is unavailable in the image for the `sequelize-cli`
reason above.

### Adopting a database whose schema was created by hand

If the tables exist but `SequelizeMeta` is empty, the next container start fails
on `CREATE TABLE ... already exists` — and with migrations in the startup chain
that means the revision will not come up.

Baseline first, in Cloud SQL Studio — insert the filenames of the migrations the
existing schema already satisfies:

```sql
INSERT INTO "SequelizeMeta" (name) VALUES
  ('20260101000001-create-sso-integrations.js'),
  ('20260101000002-create-oidc-configurations.js')
  -- ... one row per satisfied migration
ON CONFLICT DO NOTHING;
```

Check column-level migrations individually before baselining them, e.g.:

```sql
SELECT column_name FROM information_schema.columns
WHERE table_name = 'sso_users' AND column_name = 'login_method';
```

## 2.8 Verify

Startup logs are the record:

```bash
gcloud logging read 'resource.labels.service_name="sso-container"' \
  --project=<PROJECT_ID> --limit=30 --freshness=10m \
  --format='value(timestamp,textPayload)'
```

Fresh environment:

```text
[MIGRATE] Connection OK
[MIGRATE] migrating: 20260101000001-create-sso-integrations.js
...
[MIGRATE] All migrations complete ✓
SSO Microservice started
Database connected successfully
```

Already migrated:

```text
[MIGRATE] Connection OK
[MIGRATE] No pending migrations — schema is up to date
```

Then confirm the annotations survived, and exercise a real request:

```bash
gcloud run services describe sso-container --region=<REGION> --project=<PROJECT_ID> \
  --format='value(status.latestReadyRevisionName,spec.template.metadata.annotations)'
```

You want `cloudsql-instances`, `network-interfaces` and `vpc-access-egress` all
present. Then run an SSO login from the Console and check it reached the
database:

```bash
gcloud logging read 'resource.labels.service_name="sso-container" AND jsonPayload.path=~"domain-check"' \
  --project=<PROJECT_ID> --limit=5 --freshness=10m \
  --format='value(jsonPayload.timestamp,jsonPayload.path,jsonPayload.status)'
```

A `200` proves the image, secrets, VPC egress and migrated schema all work
together. Skipping this check is how a broken environment gets signed off.

## 2.9 Rollback

```bash
gcloud run revisions list --service sso-container --region <REGION> --project <PROJECT_ID> \
  --format='table(name,active,creationTimestamp)'

gcloud run services update-traffic sso-container --region <REGION> --project <PROJECT_ID> \
  --to-revisions=<PREVIOUS_REVISION>=100
```

Instant, no rebuild. Note the schema does **not** roll back with the image — if
the previous image predates a migration, that mismatch remains.

## 2.10 Entra SAML setup

Only needed when SAML is offered alongside OIDC. Entity ID and ACS URL identify
*this environment*, so every customer onboarding to it uses the same two values.

1. Entra → **Enterprise applications** → **New application** → **Create your own
   application** → *Integrate any other application you don't find in the gallery*
2. **Single sign-on** → **SAML**
3. Basic SAML Configuration:
   - **Identifier (Entity ID)** — `<BASE_URL>/auth/metadata2`
   - **Reply URL (ACS)** — `<BASE_URL>/auth/callback`
4. **Attributes & Claims** — confirm the Name ID, and for JIT role mapping add a
   claim named `role` with **namespace empty** and source `user.assignedroles`.
   A namespaced claim arrives under its full URI and the `role` mapping source
   never matches
5. **SAML Certificates** → download **Certificate (Base64)**. It is PEM despite
   the `.cer` extension — paste its contents into the Console's `saml_cert` field
6. Copy the **Login URL** from section 4 — that is `sso_url`
7. **Users and groups** → assign the user. For an Admin role, define the app role
   on the app registration (`Value` e.g. `Zebra.Admin`, **Enabled**), then
   **remove and re-add** the assignment — editing an existing assignment keeps
   "Default Access"
8. In the Console, the JIT mapping is Role `Admin` · Claim Name `role` · Claim
   Value `Zebra.Admin`. The role name must be exactly `Admin`; the SSO admin
   buttons gate on that string

Leave signed AuthnRequests off for the first test. If you later enable
**Require verification certificates** in Entra, you must also set
`SP_PRIVATE_KEY_B64` or every login fails.

---

# Section 3: MDNA-Server (invitation email)

The SSO invitation email flow lives in the MDNA-Server monolith, which is
Firebase Functions.

```bash
firebase deploy --only functions:createFirebaseUser
```

> MDNA-Server's `firebase.json` uses the default codebase, so no codebase
> qualifier is needed here.

Covers the Entra SSO invitation template, onboarding instructions, seven-day
expiry messaging and login-method specific content.

**Validate:** create a user with login method **Microsoft Entra SSO**; confirm
the email arrives with the login URL, the Continue-with-SSO instruction, the
Entra authentication steps and the seven-day expiry message; confirm non-SSO
invitations are unchanged.

**Rollback:** `firebase functions:log --only createFirebaseUser`, then redeploy
the previous stable version.

---

# Checklists

**New environment — ssoManager**

- [ ] Cloud SQL instance, VPC network and subnet exist
- [ ] Artifact Registry repository exists (not `gcf-artifacts`)
- [ ] Database and DB role created
- [ ] Four secrets stored; versions noted for the deploy command
- [ ] Runtime service account has `roles/secretmanager.secretAccessor`
- [ ] Source uploaded, image built and pushed
- [ ] Deployed with the full flag set
- [ ] Startup logs show migrations applied and the server started

**New environment — MDNA-Console**

- [ ] Three system flags and three tenant flags created
- [ ] `.env` values set, all URLs derived from one base URL
- [ ] `firebase.json.template` and `rewrites.sso.template` present;
      `firebase.json` gitignored
- [ ] Per-project block added to `Deployment.bat`
- [ ] `Deployment.bat <project> sso_enabled` completes
- [ ] Gateway `SSO_BASE_URL` names the same service as the rewrites

**Every deploy**

- [ ] ssoManager: new tag built, `gcloud run deploy --image`, startup logs clean
- [ ] Console: `Deployment.bat <project> sso_enabled`
- [ ] One real SSO login end to end

---

# Appendix: retiring the `sso` Firebase function

Some environments still carry an `sso` Cloud Function deployed with
`firebase deploy --only functions:zdna-sso:sso`. (The codebase qualifier is
required because `firebase.json` there declares `"codebase": "zdna-sso"`; without
it firebase-tools ~13+ reports *No function matches given --only filters*.)

It is the same source built a different way, and **it does not run migrations** —
`index.js` has no `CMD`. Two services running one application also produces the
split-brain described in 1.3.

Confirm nothing routes there for a full week, then delete it:

```bash
gcloud logging read 'resource.labels.service_name="sso"' --project=<PROJECT_ID> \
  --limit=20 --freshness=7d --format='value(jsonPayload.timestamp,jsonPayload.path)'
```
