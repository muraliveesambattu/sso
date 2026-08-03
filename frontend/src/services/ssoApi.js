import { API_BASE, API_BASE_GATEWAY } from '../constants/SsoConstants';
// ⬇️ Import your app's initialized Firebase auth. Adjust the path to wherever
//    firebase.initializeApp() runs. If you use the compat SDK, replace
//    `auth.currentUser` below with `firebase.auth().currentUser`.
import { auth } from '../auth/FirebaseAuth';

// Admin operations go through the SSO gateway. The gateway authenticates the
// signed-in console user via their Firebase ID token, then attaches the admin
// key server-side. The browser must NEVER hold the admin key — so there is no
// REACT_APP_ADMIN_API_KEY and no X-Admin-Api-Key header here.
const getAuthHeaders = async () => {
  const user = auth.currentUser;
  if (!user) throw new Error('Not authenticated');
  const idToken = await user.getIdToken();
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${idToken}`,
  };
};

const REQUEST_TIMEOUT_MS = 60000;
const CRUD_TIMEOUT_MS = 15000;
const MAX_RETRIES = 3;
const BASE_DELAY_MS = 500;
const RETRYABLE_STATUS = new Set([408, 429, 500, 502, 503, 504]);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const validateCompanyId = (companyId) => {
  if (!companyId || typeof companyId !== 'string' || !companyId.trim()) {
    throw new Error('companyId is required');
  }
  if (companyId.trim().length > 128) {
    throw new Error('companyId is too long');
  }
};

const fetchWithTimeout = async (
  url,
  options = {},
  timeoutMs = REQUEST_TIMEOUT_MS
) => {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    console.error('[ssoApi] fetchWithTimeout error:', err);
    if (err.name === 'AbortError') {
      const timeoutError = new Error('Request timed out.');
      timeoutError.code = 'TIMEOUT';
      timeoutError.cause = err;
      throw timeoutError;
    }
    const networkError = new Error(err.message || 'Network error');
    networkError.code = 'NETWORK_ERROR';
    networkError.cause = err;
    throw networkError;
  } finally {
    clearTimeout(timer);
  }
};

const fetchWithRetry = async (
  url,
  options = {},
  timeoutMs = REQUEST_TIMEOUT_MS,
  maxRetries = MAX_RETRIES
) => {
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const result = await fetchWithTimeout(url, options, timeoutMs);
      if (!result.ok && RETRYABLE_STATUS.has(result.status) && attempt < maxRetries) {
        const delay = BASE_DELAY_MS * Math.pow(2, attempt);
        console.warn(`[ssoApi] Retry ${attempt + 1}/${maxRetries} after ${delay}ms — HTTP ${result.status}`);
        await sleep(delay);
        continue;
      }
      return result;
    } catch (err) {
      lastError = err;
      const isRetryable = err?.code === 'TIMEOUT' || err?.code === 'NETWORK_ERROR';
      if (isRetryable && attempt < maxRetries) {
        const delay = BASE_DELAY_MS * Math.pow(2, attempt);
        console.warn(`[ssoApi] Retry ${attempt + 1}/${maxRetries} after ${delay}ms:`, err.message);
        await sleep(delay);
      } else {
        throw err;
      }
    }
  }
  throw lastError;
};

// Shared response handler
const handleResponse = ({ ok, data }) => {
  if (!ok || data?.success === false) {
    throw new Error(data?.error?.message || data?.message || 'Request failed');
  }
  return data;
};

// ── SSO configuration test — verifies credentials against Microsoft Entra ─────
export const testConnectionApi = async (payload) =>
  fetchWithRetry(
    `${API_BASE_GATEWAY}/auth/test-connection`,
    {
      method: 'POST',
      headers: await getAuthHeaders(),
      body: JSON.stringify(payload),
    },
    REQUEST_TIMEOUT_MS
  );

// ── OIDC test connection callback — called from parent window after popup ──────
// Hits the SSO service DIRECTLY (public Entra redirect target). No admin key,
// no gateway. Left as-is.
export const testConnectionCallbackApi = (payload) =>
  fetchWithRetry(
    `${API_BASE}/auth/test-connection/oidc/callback`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(payload),
    },
    REQUEST_TIMEOUT_MS
  );

// ── Save & activate SSO configuration with optional JIT mappings ──────────────
export const saveConfigApi = async (payload) =>
  fetchWithRetry(
    `${API_BASE_GATEWAY}/auth/sso/save`,
    {
      method: 'POST',
      headers: await getAuthHeaders(),
      body: JSON.stringify(payload),
    },
    CRUD_TIMEOUT_MS
  );

// ── 1. Retrieve SSO config — by domain OR companyId ───────────────────────────
export const getSsoConfig = async ({ domain, companyId }) => {
  const param = companyId
    ? `company_id=${encodeURIComponent(companyId)}`
      : `domain=${encodeURIComponent(domain)}`;
  const res = await fetchWithRetry(
    `${API_BASE_GATEWAY}/auth/sso/config?${param}`,
    { method: 'GET', headers: await getAuthHeaders() },
    CRUD_TIMEOUT_MS
  );
  const body = handleResponse(res);
  return body.data;
};

// ── 2. Save SSO config ────────────────────────────────────────────────────────
export const saveSsoConfig = async (payload) => {
  const res = await fetchWithRetry(
    `${API_BASE_GATEWAY}/auth/sso/save`,
    {
      method: 'POST',
      headers: await getAuthHeaders(),
      body: JSON.stringify(payload),
    },
    CRUD_TIMEOUT_MS
  );
  return handleResponse(res);
};

// ── 3. Activate SSO ───────────────────────────────────────────────────────────
export const activateSso = async (companyId) => {
  validateCompanyId(companyId);
  const res = await fetchWithRetry(
    `${API_BASE_GATEWAY}/auth/sso/config/${encodeURIComponent(companyId)}/status`,
    {
      method: 'PATCH',
      headers: await getAuthHeaders(),
      body: JSON.stringify({ status: 'active' }),
    },
    CRUD_TIMEOUT_MS
  );
  return handleResponse(res);
};

// ── 4. Deactivate SSO ─────────────────────────────────────────────────────────
export const deactivateSso = async (companyId) => {
  const res = await fetchWithRetry(
    `${API_BASE_GATEWAY}/auth/sso/config/${encodeURIComponent(companyId)}/status`,
    {
      method: 'PATCH',
      headers: await getAuthHeaders(),
      body: JSON.stringify({ status: 'inactive' }),
    },
    CRUD_TIMEOUT_MS
  );
  return handleResponse(res);
};

// ── 5. Delete SSO config ──────────────────────────────────────────────────────
export const deleteSsoConfig = async (companyId) => {
  validateCompanyId(companyId);
  const res = await fetchWithRetry(
    `${API_BASE_GATEWAY}/auth/sso/config/${encodeURIComponent(companyId)}`,
    {
      method: 'DELETE',
      headers: await getAuthHeaders(),
    },
    CRUD_TIMEOUT_MS
  );
  return handleResponse(res);
};

// ── 6. List roles (for the JIT role dropdown) ─────────────────────────────────
export const listRolesApi = async () => {
  const res = await fetchWithRetry(
    `${API_BASE_GATEWAY}/auth/sso/roles`,
    { method: 'GET', headers: await getAuthHeaders() },
    CRUD_TIMEOUT_MS
  );
  const body = handleResponse(res);
  return body.data; // [{ role_id, role_name, permissions }]
};
