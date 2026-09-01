# MDNA-Console deployment — drop-in changes

Parameterises the console deployment so region and Cloud Run service name come
from the project-ID argument instead of being hardcoded across `firebase.json`.

Usage is unchanged:

```
Deployment.bat dnacloud-demo2-t
```

## 1. Replace Deployment.bat

Copy `Deployment.bat` from this folder over `MDNA-Console/Deployment.bat`.

Three changes from the original:
- A per-environment block after `:CONTINUE` mapping project-ID to `REGION`,
  `SSO_SERVICE`, `GATEWAY_FUNCTION`. An unrecognised project-ID aborts instead
  of deploying with the wrong region.
- A generation step before `npm run build` that writes `firebase.json` from
  `firebase.json.template` and validates it parses as JSON.
- A `:Error` label. The original had two `GOTO Error` statements but no label,
  so the error path failed with "cannot find the batch label specified".

## 2. Create firebase.json.template

Generate it from the real file rather than hand-writing it — the `headers`
block contains a long `Feature-Policy` value that must not be retyped.

From `MDNA-Console/`:

```bat
copy firebase.json firebase.json.template
powershell -NoProfile -Command "(Get-Content firebase.json.template -Raw) -replace '\"us-central1\"','\"${REGION}\"' -replace '\"serviceId\": \"sso\"','\"serviceId\": \"${SSO_SERVICE}\"' -replace '\"functionId\": \"ssoGateway\"','\"functionId\": \"${GATEWAY_FUNCTION}\"' | Set-Content firebase.json.template -NoNewline"
```

Verify only the intended lines changed:

```bat
fc firebase.json firebase.json.template
```

Expect 7 `${REGION}`, 4 `${SSO_SERVICE}`, 3 `${GATEWAY_FUNCTION}` — nothing else.

## 3. Stop tracking the generated file

```bat
git rm --cached firebase.json
echo firebase.json>> .gitignore
```

Commit `firebase.json.template`, `Deployment.bat` and `.gitignore`.

## 4. Local development

`firebase serve` and the emulators need `firebase.json` present. Either run
`Deployment.bat <project-id>` once, or generate it directly:

```bat
powershell -NoProfile -Command "(Get-Content firebase.json.template -Raw) -replace '\$\{REGION\}','us-central1' -replace '\$\{SSO_SERVICE\}','sso-container' -replace '\$\{GATEWAY_FUNCTION\}','ssoGateway' | Set-Content firebase.json -NoNewline"
```

## Open decision — SSO_SERVICE

`Deployment.bat` sets `SSO_SERVICE=sso-container`, matching the value the
`ssoGateway` function proxies to (`SSO_BASE_URL`). The current `firebase.json`
in the repo says `sso`.

Those two must name the same service. `/auth/test-connection` reaches the
microservice through the gateway while the OIDC test callback goes through a
Hosting rewrite; if they resolve to different services the test-connection
session is written to one process and read from another, which fails with
`TC_STORE_EXPIRED`.

Confirm which service is canonical before deploying, and align the gateway's
`SSO_BASE_URL` to match if `sso` is chosen.

## Adding a new deployment target

Add one block to `Deployment.bat`:

```bat
) else if /I "%1"=="<project-id>" (
    set "REGION=<region>"
    set "SSO_SERVICE=<cloud-run-service>"
    set "GATEWAY_FUNCTION=ssoGateway"
```

No other file changes.
