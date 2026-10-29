# VDI reference copies (transcribed from screenshots)

These files were typed out from screenshots of the MDNA-Console workspace on the
VDI (2026-10-13), because the VDI files cannot be copied to this machine.

- They are **not** the real files. A misread character or a missed line is possible.
  Diff against the VDI file before relying on any detail.
- Whitespace and line wrapping may differ from the originals. Line numbers match the
  VDI editor where the whole file was visible.
- They are reference only: nothing here is imported or run, and `package.json`'s jest
  config ignores `vdi-reference/`.

| File | Lines on VDI | Coverage |
|---|---|---|
| `mdna-console/src/hooks/useTestConnection.js` | 232 | complete |
| `mdna-console/src/views/auth-views/authentication/oidc-callback/index.js` | 196 | complete |
| `mdna-console/src/views/user-views/myServices/sso/components/OidcConfigForm.js` | 188 | complete |
| `mdna-console/src/views/user-views/myServices/sso/components/TestConnectionPanel.js` | 58+ | lines 1-58 seen; `export default TestConnectionPanel;` added from the Mac copy |
| `mdna-console/src/views/user-views/myServices/sso/sso-integration-card-service.js` | 530 | complete |
| `mdna-console/src/constants/SsoConstants.js` | 33 | complete |
| `mdna-console/src/layouts/auth-layout/index.js` | 16 | complete |
| `mdna-console/src/views/auth-views/index.js` | 59+ | lines 1-58 only; the tail (likely `export default`) was not seen |

Checked: for every file, key landmarks (function and export lines) fall on the same line
numbers as in the VDI editor, so no whole lines were dropped or added. Character-level
accuracy was not verified.

Not captured: `AuthProvider`, `FirebaseAuth`, `ssoApi.js` (VDI version), top-level routing
(`Views` / `App.js`), `firebase.json` rewrites, `SamlConfigForm.js`.

## SAML Test Connection popup (applied on top)

`useTestConnection.js` and `oidc-callback/index.js` include the SAML popup changes
(backend polling, `?saml_test=1`). `ssoApi.js` has the `testSamlResultApi` export.

## Merged from the old `frontend/` folder (2026-10-29)

These files are the Mac's own console code (Aug 2026), not transcriptions. They have
**not** been checked against the VDI and may be older than it. Where a file existed in
both folders, the VDI transcription above was kept.

- `mdna-console/src/services/ssoApi.js` (+ `ssoApi.test.js`), now with `testSamlResultApi`
- `mdna-console/src/hooks/useSsoForm.js`, `useJitMappings.js` (+ tests)
- `mdna-console/src/utils/sso-integration-field-validator.js` (+ test)
- `mdna-console/src/views/auth-views/authentication/login-v2/SSOLogin.js`
- `mdna-console/src/views/user-views/myServices/sso/SsoIntegrationPage.js`
- `mdna-console/src/views/user-views/myServices/sso/components/`: `ActiveConfigView.js`,
  `IdpProtocolSelector.js`, `JitMappingSection.js`, `SamlConfigForm.js`, `TestConnectionPanel.test.js`
