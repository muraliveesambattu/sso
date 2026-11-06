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
