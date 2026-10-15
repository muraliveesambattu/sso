// SNIPPET — not the whole file. Add this export to src/services/ssoApi.js, directly after
// testConnectionCallbackApi (same imports/helpers: API_BASE, fetchWithRetry, REQUEST_TIMEOUT_MS).
//
// SAML test popup: parent window posts { sessionRef } after the popup closes. Hits the SSO
// service DIRECTLY (no gateway, no admin key) — the single-use sessionRef is the credential.
// Responses: 202 { pending:true } | 200 { success, data:{ claims } } | 400/401 { error:{ message, code } }
export const testSamlResultApi = (payload) =>
  fetchWithRetry(
    `${API_BASE}/auth/test-connection/saml/result`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(payload),
    },
    REQUEST_TIMEOUT_MS
  );
