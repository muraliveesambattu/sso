# Firebase SSO Manager Deployment Guide

Deployment steps for the `sso` Firebase function and post-deployment Cloud Run configuration.

## 1. Get into the right folder

Change to the SSO Manager directory:

```bash
cd /MDNA-Server/zDNAMicroservice/ssoManager
```

Confirm you're in the right place. `firebase.json` and `index.js` should be listed:

```bash
ls firebase.json index.js src
```

---

## 2. Log in

Log in to Firebase:

```bash
firebase login
```

This opens a browser for Google authentication.

If you're already logged in with the wrong account:

```bash
firebase login --reauth
```

---

## 3. Point at the right project

List available Firebase projects:

```bash
firebase projects:list
```

Select the target project:

```bash
firebase use dnacloud-demo2-t
```

> ⚠️ **Important:** Deploying to the wrong Firebase project deploys to the wrong environment. Always verify that the selected project is `dnacloud-demo2-t`.

---

## 4. Pre-flight — catch syntax errors before the build

Run syntax checks on the affected JavaScript files before starting the deployment:

```bash
node --check src/services/db/postgresSSO.service.js && \
node --check src/services/SSO/userResolution.service.js && \
node --check src/utils/oidc/tokenExchange.util.js && \
echo "all parse OK"
```

You should see:

```text
all parse OK
```

---

## 5. Deploy

Deploy only the `sso` Firebase function:

```bash
firebase deploy --only functions:sso
```

A bare deployment also works:

```bash
firebase deploy
```

However, `firebase deploy` can also push hosting and rules, so prefer the function-specific command when only the SSO function needs to be deployed.

Wait for:

```text
Deploy complete!
```

---

## 6. Restore the environment variables the deploy wipes ⚠️

> ⚠️ **Important:** Every `firebase deploy` drops `DATABASE_URL` and VPC egress configuration on this service.
>
> If this step is skipped, the service may come up unable to reach PostgreSQL.

Run the following in **Google Cloud Shell using Bash**.

> **Do not use PowerShell for this command.** The `$(...)` command substitution and `jq` usage are intended for Bash.

```bash
gcloud run services update sso \
  --region us-central1 \
  --project dnacloud-demo2-t \
  --network=dnacloud-demo2-t-gke-vpc \
  --subnet=dnacloud-demo2-t-gke-subnet \
  --vpc-egress=private-ranges-only \
  --max-instances=1 \
  --update-env-vars "^|^DATABASE_URL=$(gcloud run revisions describe sso-00150-nob \
    --region us-central1 \
    --project dnacloud-demo2-t \
    --format='json' | \
    jq -r '.. | objects | select(.name=="DATABASE_URL") | .value' | head -1)"
```

### Confirm `DATABASE_URL` was restored

Run:

```bash
gcloud run services describe sso \
  --region us-central1 \
  --project dnacloud-demo2-t \
  --format=json | \
  jq -r '.spec.template.spec.containers[0].env[] | select(.name=="DATABASE_URL") | .value'
```

If the command returns an empty output, re-run the restore command from the previous section.

---

## 7. Verify the new revision is serving

List the latest Cloud Run revisions:

```bash
gcloud run revisions list \
  --service sso \
  --region us-central1 \
  --project dnacloud-demo2-t \
  --limit 3 \
  --format='table(name,active,creationTimestamp)'
```

### Expected result

The newest revision should:

- Be marked `active`
- Have a creation timestamp from the current deployment
- Be serving traffic successfully

---

## 8. SAML ACS URL and Entity ID

Use the Firebase Hosting URL for the SAML ACS URL and Entity ID, not the Cloud Run `run.app` URL. Hosting already sends `/auth/callback` to the SSO service (`mdna-console/rewrites.sso.template`), so no code change is needed. This keeps the project number out of the ACS URL.

| Setting | Value |
|---|---|
| ACS URL (Reply URL) | `https://<project-id>.web.app/auth/callback` |
| Entity ID (Identifier) | `https://<project-id>.web.app/auth/metadata2` |

> ⚠️ **Important:** The backend and the console must use the **same** values. Test Connection uses the backend values; Save stores the console values.

### 8.1 Add the new URLs in Microsoft Entra first

In the customer's Entra app (**Enterprise applications → app → Single sign-on → Basic SAML Configuration**):

- Add the new **Identifier (Entity ID)**.
- Add the new **Reply URL (ACS URL)**.
- Keep the old `run.app` values until section 8.5 passes.

### 8.2 Update the backend (Cloud Run)

Run in **Google Cloud Shell using Bash**. `--update-env-vars` changes only these two variables and keeps the others:

```bash
gcloud run services update <sso-service> \
  --region us-central1 \
  --project <project-id> \
  --update-env-vars "SAML_ACS_URL=https://<project-id>.web.app/auth/callback,SAML_ENTITY_ID=https://<project-id>.web.app/auth/metadata2"
```

Confirm:

```bash
gcloud run services describe <sso-service> \
  --region us-central1 \
  --project <project-id> \
  --format=json | \
  jq -r '.spec.template.spec.containers[0].env[] | select(.name=="SAML_ACS_URL" or .name=="SAML_ENTITY_ID") | "\(.name)=\(.value)"'
```

> ⚠️ After every `firebase deploy`, re-run the confirm command. If the values are missing, run the update command again (see section 6).

### 8.3 Update the console

In the console `.env` for the environment, set:

```text
REACT_APP_SAML_ACS_URL=https://<project-id>.web.app/auth/callback
REACT_APP_SAML_ENTITY_ID=https://<project-id>.web.app/auth/metadata2
```

Rebuild and deploy the console with the standard console deployment command. The new values appear in **My Services → Entra SAML 2.0 → Zebra DNA Configuration Values**.

### 8.4 Re-save existing SAML configurations

Each saved SAML configuration keeps the ACS URL from when it was saved. Open each one in the console and click **Save** again.

### 8.5 Verify

Check that Hosting forwards the ACS URL to the SSO service:

```bash
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" -X POST https://<project-id>.web.app/auth/callback
```

Expected:

```text
302 ...?error=MISSING_SAML_RESPONSE
```

A `404` or the console's HTML means the `/auth/callback` rewrite is missing from the hosting deploy.

Then run **Test Connection** and one real SSO login.

### 8.6 Clean up

After section 8.5 passes, remove the old `run.app` Identifier and Reply URL from the Entra app.

---

## Quick Deployment Checklist

- [ ] Navigate to `/MDNA-Server/zDNAMicroservice/ssoManager`
- [ ] Confirm `firebase.json`, `index.js`, and `src` exist
- [ ] Log in to the correct Firebase account
- [ ] Select `dnacloud-demo2-t`
- [ ] Run JavaScript syntax checks
- [ ] Deploy `functions:sso`
- [ ] Restore `DATABASE_URL`
- [ ] Restore VPC egress configuration
- [ ] Verify `DATABASE_URL`
- [ ] Verify the newest Cloud Run revision is active
- [ ] Add the `web.app` Identifier and Reply URL in the Entra app
- [ ] Set `SAML_ACS_URL` / `SAML_ENTITY_ID` on Cloud Run and `REACT_APP_SAML_*` in the console `.env` (same values)
- [ ] Re-save SAML configs, verify `/auth/callback` returns 302, run Test Connection
