/**
 * useTestConnection — Activate (handleTestConnection(true)) must open the
 * Entra login popup and succeed only after a real sign-in (DLM-100022).
 *
 * Stack: React 16 + @testing-library/react-hooks v8. The API, Firebase and
 * window.open are mocked; fake timers drive the result polling.
 */

import { renderHook, act } from '@testing-library/react-hooks';
import { useTestConnection } from './useTestConnection';
import { testConnectionApi, testConnectionCallbackApi, testSamlResultApi } from '../services/ssoApi';

jest.mock('../services/ssoApi', () => ({
  testConnectionApi: jest.fn(),
  testConnectionCallbackApi: jest.fn(),
  testSamlResultApi: jest.fn(),
}));
jest.mock('../constants/SsoConstants', () => ({
  AUTH_METHOD_MAP: { secret: 'client_secret' },
  REDIRECT_URI: 'https://console.example.test/sso/redirect',
}));
jest.mock('auth/FirebaseAuth', () => ({ getTenantId: () => 'company-1' }));
jest.mock('auth/AuthProvider', () => ({ AuthContext: require('react').createContext({}) }));

const SESSION_REF = 'session-ref-1';
const REDIRECT_URL = 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/saml2?SAMLRequest=abc';
const POLL_MS = 2000; // SAML_POLL_INTERVAL_MS in useTestConnection

const form = { getFieldsValue: () => ({}) };
let popup;
let setIsTestReady;

const flush = async () => {
  for (let i = 0; i < 10; i += 1) await Promise.resolve();
};

const renderActivate = (protocol = 'saml') =>
  renderHook(() => useTestConnection(form, protocol, {}, setIsTestReady));

// Start Activate, then let the first API call settle and the popup open.
const startActivate = async (result) => {
  let pending;
  await act(async () => {
    pending = result.current.handleTestConnection(true);
    await flush();
  });
  // Wrapped so `await startActivate()` does not wait for the whole flow.
  return { pending };
};

// Run one poll tick of the SAML result.
const pollOnce = async () => {
  await act(async () => {
    jest.advanceTimersByTime(POLL_MS);
    await flush();
  });
};

const samlSession = () => ({
  ok: true,
  status: 200,
  data: { success: true, data: { sessionRef: SESSION_REF, redirectUrl: REDIRECT_URL } },
});

beforeEach(() => {
  jest.useFakeTimers();
  localStorage.clear();
  [testConnectionApi, testConnectionCallbackApi, testSamlResultApi].forEach((fn) => fn.mockReset());
  setIsTestReady = jest.fn();
  popup = { closed: false, close: jest.fn(() => { popup.closed = true; }) };
  jest.spyOn(window, 'open').mockImplementation(() => popup);
  ['log', 'debug', 'error', 'warn'].forEach((level) => jest.spyOn(console, level).mockImplementation(() => {}));
});

afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
});

describe('Activate SAML — popup first, then activate', () => {
  test('sends only the company and protocol, so the backend uses the saved config', async () => {
    testConnectionApi.mockResolvedValue(samlSession());
    testSamlResultApi.mockResolvedValue({ ok: true, status: 200, data: { success: true, data: {} } });
    const { result } = renderActivate();

    const { pending } = await startActivate(result);
    await pollOnce();
    await act(async () => { await pending; });

    expect(testConnectionApi).toHaveBeenCalledWith({ company_id: 'company-1', protocol: 'saml', is_existing_test: true });
  });

  test('opens the Entra popup and waits; nothing is ready before the sign-in finishes', async () => {
    testConnectionApi.mockResolvedValue(samlSession());
    testSamlResultApi.mockResolvedValue({ ok: false, status: 202, data: { pending: true } });
    const { result } = renderActivate();

    await startActivate(result);
    await pollOnce();

    expect(window.open).toHaveBeenCalledWith(REDIRECT_URL, 'ssoOidcValidation', expect.any(String));
    expect(localStorage.getItem('tc_session_ref')).toBe(SESSION_REF);
    expect(testSamlResultApi).toHaveBeenCalledWith({ sessionRef: SESSION_REF });
    expect(result.current.testLoading).toBe(true);
    expect(result.current.testPassed).toBe(false);
    expect(setIsTestReady).not.toHaveBeenCalled();
  });

  test('succeeds only after Entra reports a successful sign-in', async () => {
    testConnectionApi.mockResolvedValue(samlSession());
    testSamlResultApi
      .mockResolvedValueOnce({ ok: false, status: 202, data: { pending: true } })
      .mockResolvedValueOnce({ ok: true, status: 200, data: { success: true, data: { claims: { roles: ['Zebra.Admin'] } } } });
    const { result } = renderActivate();

    const { pending } = await startActivate(result);
    await pollOnce();
    expect(setIsTestReady).not.toHaveBeenCalled();
    await pollOnce();
    let outcome;
    await act(async () => { outcome = await pending; });

    expect(outcome).toEqual({ success: true, message: 'Test Connection successful.' });
    expect(result.current.testPassed).toBe(true);
    expect(result.current.testResult).toMatchObject({ status: 'passed', claims: { roles: ['Zebra.Admin'] } });
    expect(result.current.testLoading).toBe(false);
    expect(setIsTestReady).toHaveBeenCalledWith(true);
    expect(popup.close).toHaveBeenCalled();
    expect(localStorage.getItem('tc_session_ref')).toBeNull();
  });

  test('does not activate when the sign-in fails', async () => {
    testConnectionApi.mockResolvedValue(samlSession());
    testSamlResultApi.mockResolvedValue({
      ok: false, status: 400, data: { success: false, error: { message: 'User is not assigned to the app.' } },
    });
    const { result } = renderActivate();

    const { pending } = await startActivate(result);
    await pollOnce();
    let outcome;
    await act(async () => { outcome = await pending; });

    expect(outcome).toEqual({ success: false, message: 'User is not assigned to the app.' });
    expect(result.current.testPassed).toBe(false);
    expect(result.current.testResult).toMatchObject({ status: 'failed' });
    expect(setIsTestReady).not.toHaveBeenCalled();
  });

  test('does not activate when the user closes the popup', async () => {
    testConnectionApi.mockResolvedValue(samlSession());
    testSamlResultApi.mockResolvedValue({ ok: false, status: 202, data: { pending: true } });
    const { result } = renderActivate();

    const { pending } = await startActivate(result);
    popup.closed = true;
    await pollOnce();
    let outcome;
    await act(async () => { outcome = await pending; });

    expect(outcome).toEqual({ success: false, message: 'Test Connection was cancelled. Please try again.' });
    expect(setIsTestReady).not.toHaveBeenCalled();
  });

  test('does not activate when the popup is blocked', async () => {
    testConnectionApi.mockResolvedValue(samlSession());
    window.open.mockImplementation(() => null);
    const { result } = renderActivate();

    let outcome;
    await act(async () => { outcome = await result.current.handleTestConnection(true); });

    expect(outcome).toEqual({ success: false, message: 'Popup was blocked. Please allow popups and try again.' });
    expect(testSamlResultApi).not.toHaveBeenCalled();
    expect(setIsTestReady).not.toHaveBeenCalled();
    expect(localStorage.getItem('tc_session_ref')).toBeNull();
  });

  test('does not open the popup when the saved config fails its check', async () => {
    testConnectionApi.mockResolvedValue({
      ok: false, status: 400, data: { success: false, error: { message: 'The SAML certificate has expired.' } },
    });
    const { result } = renderActivate();

    let outcome;
    await act(async () => { outcome = await result.current.handleTestConnection(true); });

    expect(outcome).toEqual({ success: false, message: 'The SAML certificate has expired.' });
    expect(window.open).not.toHaveBeenCalled();
    expect(setIsTestReady).not.toHaveBeenCalled();
  });

  test('uses the activation fallback message when the check fails without one', async () => {
    testConnectionApi.mockResolvedValue({ ok: false, status: 500, data: {} });
    const { result } = renderActivate();

    let outcome;
    await act(async () => { outcome = await result.current.handleTestConnection(true); });

    expect(outcome.message).toBe('Unable to validate the saved SSO configuration.');
  });

  // Line 808: `if (!samlSessionRef || !samlRedirectUrl)`. An older backend that
  // returns no login session is accepted without a popup.
  test('without a login session from the backend, verifies without a popup', async () => {
    testConnectionApi.mockResolvedValue({ ok: true, status: 200, data: { success: true, data: {} } });
    const { result } = renderActivate();

    let outcome;
    await act(async () => { outcome = await result.current.handleTestConnection(true); });

    expect(window.open).not.toHaveBeenCalled();
    expect(outcome).toEqual({ success: true, message: 'Saved SAML configuration verified successfully.' });
  });

  test('opens no popup when only the session ref is returned (no redirect URL)', async () => {
    testConnectionApi.mockResolvedValue({ ok: true, status: 200, data: { success: true, data: { sessionRef: SESSION_REF } } });
    const { result } = renderActivate();

    // Not awaited to the end: if a popup opened, the flow would wait for a sign-in.
    await startActivate(result);

    expect(window.open).not.toHaveBeenCalled();
    expect(result.current.testLoading).toBe(false);
  });
});

describe('Activate OIDC — popup first, then activate', () => {
  const OIDC_POLL_MS = 500; // OIDC_POLL_INTERVAL_MS in useTestConnection
  const AUTHORIZE_URL = 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize';

  const oidcSession = (config = {}) => ({
    ok: true,
    status: 200,
    data: {
      success: true,
      data: {
        sessionRef: SESSION_REF,
        config: {
          sso_url: AUTHORIZE_URL,
          client_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
          redirect_uri: 'https://console.example.test/sso/redirect',
          scope: 'openid profile email',
          state: 'state-1',
          nonce: 'nonce-1',
          code_challenge: 'challenge-1',
          ...config,
        },
      },
    },
  });

  const pollOidc = async () => {
    await act(async () => {
      jest.advanceTimersByTime(OIDC_POLL_MS);
      await flush();
    });
  };

  // What the redirect page does after Entra sends the browser back.
  const signInFinishes = () => {
    localStorage.setItem('tc_oidc_code', 'code-1');
    localStorage.setItem('tc_oidc_state', 'state-1');
  };

  test('opens the Entra login with the server values and marks the flow as activation', async () => {
    testConnectionApi.mockResolvedValue(oidcSession());
    const { result } = renderActivate('oidc');

    await startActivate(result);
    await pollOidc();

    const url = new URL(window.open.mock.calls[0][0]);
    expect(`${url.origin}${url.pathname}`).toBe(AUTHORIZE_URL);
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      client_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      response_type: 'code',
      state: 'state-1',
      nonce: 'nonce-1',
      prompt: 'login',
      code_challenge: 'challenge-1',
      code_challenge_method: 'S256',
    });
    expect(localStorage.getItem('tc_flow_type')).toBe('activation');
    expect(result.current.testLoading).toBe(true);
    expect(testConnectionCallbackApi).not.toHaveBeenCalled();
    expect(setIsTestReady).not.toHaveBeenCalled();
  });

  test('activates only after the sign-in code is verified', async () => {
    testConnectionApi.mockResolvedValue(oidcSession());
    testConnectionCallbackApi.mockResolvedValue({ ok: true, status: 200, data: { success: true, data: { claims: { roles: ['Zebra.Admin'] } } } });
    const { result } = renderActivate('oidc');

    const { pending } = await startActivate(result);
    await pollOidc();
    signInFinishes();
    await pollOidc();
    let outcome;
    await act(async () => { outcome = await pending; });

    expect(testConnectionCallbackApi).toHaveBeenCalledTimes(1);
    expect(testConnectionCallbackApi).toHaveBeenCalledWith({
      code: 'code-1', state: 'state-1', company_id: 'company-1', sessionRef: SESSION_REF, is_activation: true,
    });
    expect(outcome).toEqual({ success: true, message: 'SSO credentials verified successfully.' });
    expect(result.current.testResult).toMatchObject({ status: 'passed', claims: { roles: ['Zebra.Admin'] } });
    expect(setIsTestReady).toHaveBeenCalledWith(true);
    expect(popup.close).toHaveBeenCalled();
    expect(localStorage.getItem('tc_oidc_code')).toBeNull();
  });

  test('does not activate when the code is rejected', async () => {
    testConnectionApi.mockResolvedValue(oidcSession());
    testConnectionCallbackApi.mockResolvedValue({ ok: false, status: 400, data: { success: false } });
    const { result } = renderActivate('oidc');

    const { pending } = await startActivate(result);
    signInFinishes();
    await pollOidc();
    let outcome;
    await act(async () => { outcome = await pending; });

    expect(outcome).toEqual({ success: false, message: 'Unable to verify SSO credentials.' });
    expect(setIsTestReady).not.toHaveBeenCalled();
  });

  test('does not activate when Entra reports an error', async () => {
    testConnectionApi.mockResolvedValue(oidcSession());
    const { result } = renderActivate('oidc');

    const { pending } = await startActivate(result);
    localStorage.setItem('tc_result', JSON.stringify({ message: 'AADSTS50105: user not assigned.' }));
    await pollOidc();
    let outcome;
    await act(async () => { outcome = await pending; });

    expect(outcome).toEqual({ success: false, message: 'AADSTS50105: user not assigned.' });
    expect(testConnectionCallbackApi).not.toHaveBeenCalled();
    expect(setIsTestReady).not.toHaveBeenCalled();
  });

  test('says "Reactivation was cancelled" when the user closes the popup', async () => {
    testConnectionApi.mockResolvedValue(oidcSession());
    const { result } = renderActivate('oidc');

    const { pending } = await startActivate(result);
    popup.closed = true;
    await pollOidc();
    let outcome;
    await act(async () => { outcome = await pending; });

    expect(outcome).toEqual({ success: false, message: 'Reactivation was cancelled. Please try again.' });
    expect(setIsTestReady).not.toHaveBeenCalled();
  });

  test('opens no popup when the server sends no state or nonce', async () => {
    testConnectionApi.mockResolvedValue(oidcSession({ nonce: undefined }));
    const { result } = renderActivate('oidc');

    let outcome;
    await act(async () => { outcome = await result.current.handleTestConnection(true); });

    expect(outcome).toEqual({ success: false, message: 'Invalid OIDC state or nonce received from server.' });
    expect(window.open).not.toHaveBeenCalled();
  });

  test('opens no popup when the server sends no session', async () => {
    const response = oidcSession();
    delete response.data.data.sessionRef;
    testConnectionApi.mockResolvedValue(response);
    const { result } = renderActivate('oidc');

    let outcome;
    await act(async () => { outcome = await result.current.handleTestConnection(true); });

    expect(outcome).toEqual({ success: false, message: 'Session reference is missing. Please try again.' });
    expect(window.open).not.toHaveBeenCalled();
  });
});

describe('Activate OIDC — saved config fails its check', () => {
  test('shows the backend error and opens no popup (e.g. rejected client secret)', async () => {
    testConnectionApi.mockResolvedValue({
      ok: false, status: 400,
      data: { success: false, error: { code: 'INVALID_CLIENT_SECRET', message: 'The client secret was rejected by Microsoft Entra.' } },
    });
    const { result } = renderActivate('oidc');

    let outcome;
    await act(async () => { outcome = await result.current.handleTestConnection(true); });

    expect(testConnectionApi).toHaveBeenCalledWith({ company_id: 'company-1', protocol: 'oidc', is_existing_test: true });
    expect(outcome).toEqual({ success: false, message: 'The client secret was rejected by Microsoft Entra.' });
    expect(window.open).not.toHaveBeenCalled();
    expect(testConnectionCallbackApi).not.toHaveBeenCalled();
    expect(setIsTestReady).not.toHaveBeenCalled();
  });
});
