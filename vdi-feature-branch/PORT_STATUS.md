# SAML popup → `master_zdna_edcl_700_feature1`

This folder is a Mac copy of the VDI feature branch, kept on the Mac branch
`vdi/master_zdna_edcl_700_feature1`. Gerrit can't be reached from the Mac, so each file
is transcribed from a VDI upload.

`MDNA-Server/` mirrors the VDI repo paths. Each file gets two commits:

1. **"VDI copy: …"**: the file exactly as it is on the feature branch.
2. **"SAML popup: …"**: the SAML Test Connection changes from `saml-test-popup-clean`.

To see only the SAML changes made so far:

```bash
git log -p --grep "^SAML popup" -- vdi-feature-branch/MDNA-Server
```

Copy each file to the same path on the VDI. Then compare it with the VDI file (in VS Code: Select for Compare). Only the SAML lines should differ. If anything else differs, the screenshot transcription got it wrong.

## ssoManager (`MDNA-Server/zDNAMicroservice/ssoManager`)

| File | VDI copy | SAML changes |
|---|---|---|
| src/controllers/samlCallback.Controller.js | done | done (+6) |
| src/controllers/samlTestResult.controller.js | not needed (new file) | done (copied from Mac) |
| src/controllers/testConnection.controller.js | waiting | pending |
| src/routers/sso.routes.js | waiting | pending |
| src/services/SSO/testConnection.service.js | waiting | pending |
| src/services/Saml/samlAuthRequest.service.js | waiting | pending |
| src/services/Saml/samlCallback.service.js | waiting | pending |
| test/samlTestResult.controller.test.js | not needed (new file) | done (copied from Mac) |
| test/samlAuthRequest.service.test.js | waiting | pending |
| test/samlCallback.controller.test.js | waiting | pending |
| test/samlCallback.service.test.js | waiting | pending |
| test/sso.routes.test.js | waiting | pending |
| test/testConnection.controller.test.js | waiting | pending |
| test/testConnection.service.test.js | waiting | pending |

## ssoGateway

| File | VDI copy | SAML changes |
|---|---|---|
| api/ssoGateway.js | waiting | pending |
| test/ssoGateway.test.js | waiting | pending |
| README.md | waiting | pending |

## MDNA-Console

| File | VDI copy | SAML changes |
|---|---|---|
| src/hooks/useTestConnection.js | waiting | pending |
| src/views/auth-views/authentication/oidc-callback/index.js | waiting | pending |
| src/services/ssoApi.js (add `testSamlResultApi`) | waiting | pending |
| rewrites.sso.template | waiting | pending |
