import { render, waitFor, act } from '@testing-library/react';
import OIDCCallback from './index';
import { getAuth, signInWithCustomToken } from 'firebase/auth';
import { useLocation } from 'react-router-dom';

jest.mock('firebase/auth', () => ({
  getAuth: jest.fn(),
  signInWithCustomToken: jest.fn(),
}));

const mockReplace = jest.fn();

// The page calls history.replace() with a location object, not a plain path.
const toLogin = (errorMessage) => ({ pathname: '/auth/login', state: { errorMessage } });
const toHome = { pathname: '/app/home', state: {} };

jest.mock('react-router-dom', () => ({
  useHistory: () => ({ replace: mockReplace }),
  useLocation: jest.fn(),
}));

beforeEach(() => {
  mockReplace.mockReset();
  jest.clearAllMocks();
  process.env.REACT_APP_MICROSERVICE_API_URL = 'https://test-api.com/';
  globalThis.fetch = jest.fn();
  Storage.prototype.getItem = jest.fn().mockReturnValue(null);
  Storage.prototype.setItem = jest.fn();
  Storage.prototype.removeItem = jest.fn();
  globalThis.close = jest.fn();
  globalThis.history.replaceState = jest.fn();
  getAuth.mockReturnValue({});
});

// ─── Normal window: no params ────────────────────────────────────────────────

it('redirects to login when no query params', async () => {
  useLocation.mockReturnValue({ search: '' });
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(
    toLogin('Invalid callback. Please try signing in again.')
  ));
});

// ─── Normal window: invalid API URL ──────────────────────────────────────────

// The page does not check for https; with no stored OIDC company it reports an expired session.
it('redirects to login with an http API URL when no OIDC company is stored', async () => {
  process.env.REACT_APP_MICROSERVICE_API_URL = 'http://localhost';
  useLocation.mockReturnValue({ search: '?code=abc&state=xyz' });
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(
    toLogin('Authentication session expired. Please try signing in again.')
  ));
  expect(fetch).not.toHaveBeenCalled();
});

it('redirects to login when REACT_APP_MICROSERVICE_API_URL is missing', async () => {
  delete process.env.REACT_APP_MICROSERVICE_API_URL;
  useLocation.mockReturnValue({ search: '?code=abc&state=xyz' });
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(
    toLogin('Service configuration error. Please contact support.')
  ));
});

// ─── Normal window: SAML token login ─────────────────────────────────────────

it('signs in and redirects home when token param is present', async () => {
  signInWithCustomToken.mockResolvedValue();
  useLocation.mockReturnValue({ search: '?token=test-token' });
  render(<OIDCCallback />);
  await waitFor(() => {
    expect(signInWithCustomToken).toHaveBeenCalledWith({}, 'test-token');
    expect(mockReplace).toHaveBeenCalledWith(toHome);
  });
});

it('redirects to login when firebase signIn fails on token param', async () => {
  signInWithCustomToken.mockRejectedValue(new Error('firebase error'));
  useLocation.mockReturnValue({ search: '?token=test-token' });
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(
    toLogin('Failed to sign in to the application. Please try again.')
  ));
});

// ─── Normal window: error param ──────────────────────────────────────────────

it('redirects to login when error param is present', async () => {
  useLocation.mockReturnValue({ search: '?error=INVALID_TOKEN' });
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(
    toLogin('Your session token has expired. Please sign in again.')
  ));
});

// ─── Normal window: OIDC code+state ──────────────────────────────────────────

it('redirects to login when oidc_company_id is missing', async () => {
  useLocation.mockReturnValue({ search: '?code=123&state=456' });
  localStorage.getItem.mockReturnValue(null);
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(
    toLogin('Authentication session expired. Please try signing in again.')
  ));
});

it('exchanges token and redirects home on success', async () => {
  useLocation.mockReturnValue({ search: '?code=123&state=456' });
  localStorage.getItem.mockImplementation(key =>
    key === 'oidc_company_id' ? 'company123' : null
  );
  fetch.mockResolvedValue({
    ok: true,
    json: jest.fn().mockResolvedValue({ customToken: 'custom-token' }),
  });
  signInWithCustomToken.mockResolvedValue();
  render(<OIDCCallback />);
  await waitFor(() => {
    expect(fetch).toHaveBeenCalled();
    expect(signInWithCustomToken).toHaveBeenCalledWith({}, 'custom-token');
    expect(localStorage.removeItem).toHaveBeenCalledWith('oidc_company_id');
    expect(mockReplace).toHaveBeenCalledWith(toHome);
  });
});

it('redirects to login when token exchange response is not ok', async () => {
  useLocation.mockReturnValue({ search: '?code=123&state=456' });
  localStorage.getItem.mockImplementation(key =>
    key === 'oidc_company_id' ? 'company123' : null
  );
  fetch.mockResolvedValue({
    ok: false,
    json: jest.fn().mockResolvedValue({ code: 'INVALID_TOKEN' }),
  });
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(
    toLogin('Your session token has expired. Please sign in again.')
  ));
});

it('redirects to login on network error during token exchange', async () => {
  useLocation.mockReturnValue({ search: '?code=123&state=456' });
  localStorage.getItem.mockImplementation(key =>
    key === 'oidc_company_id' ? 'company123' : null
  );
  fetch.mockRejectedValue(new Error('Network Error'));
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(
    toLogin('Network error. Please check your connection and try again.')
  ));
});

it('redirects to login when firebase signIn fails after token exchange', async () => {
  useLocation.mockReturnValue({ search: '?code=123&state=456' });
  localStorage.getItem.mockImplementation(key =>
    key === 'oidc_company_id' ? 'company123' : null
  );
  fetch.mockResolvedValue({
    ok: true,
    json: jest.fn().mockResolvedValue({ customToken: 'custom-token' }),
  });
  const firebaseError = new Error('auth failed');
  firebaseError.code = 'auth/invalid-token';
  signInWithCustomToken.mockRejectedValue(firebaseError);
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(
    toLogin('Failed to sign in to the application. Please try again.')
  ));
});

// ─── Popup: error param ───────────────────────────────────────────────────────

it('stores TEST_CONNECTION_FAILED and closes window on popup error', async () => {
  useLocation.mockReturnValue({ search: '?error=INVALID_TOKEN' });
  localStorage.getItem.mockImplementation(key =>
    key === 'tc_session_ref' ? 'ref123' : null
  );
  render(<OIDCCallback />);
  await waitFor(() => {
    expect(localStorage.setItem).toHaveBeenCalledWith(
      'tc_result',
      expect.stringContaining('TEST_CONNECTION_FAILED')
    );
    expect(globalThis.close).toHaveBeenCalled();
  });
});

// ─── Popup: SAML token success ────────────────────────────────────────────────

it('stores TEST_CONNECTION_SUCCESS and closes window on popup token', async () => {
  useLocation.mockReturnValue({ search: '?token=test-token' });
  localStorage.getItem.mockImplementation(key =>
    key === 'tc_session_ref' ? 'ref123' : null
  );
  render(<OIDCCallback />);
  await waitFor(() => {
    expect(localStorage.setItem).toHaveBeenCalledWith(
      'tc_result',
      expect.stringContaining('TEST_CONNECTION_SUCCESS')
    );
    expect(globalThis.close).toHaveBeenCalled();
  });
});

// ─── Popup: OIDC code+state ───────────────────────────────────────────────────

it('saves oidc code and state then closes window in popup flow', async () => {
  useLocation.mockReturnValue({ search: '?code=abc&state=xyz' });
  localStorage.getItem.mockImplementation(key =>
    key === 'tc_session_ref' ? 'ref123' : null
  );
  render(<OIDCCallback />);
  await waitFor(() => {
    expect(localStorage.setItem).toHaveBeenCalledWith('tc_oidc_code', 'abc');
    expect(localStorage.setItem).toHaveBeenCalledWith('tc_oidc_state', 'xyz');
    expect(globalThis.close).toHaveBeenCalled();
  });
});

// ─── Popup: no valid params ───────────────────────────────────────────────────

it('closes window silently when popup has no valid params', async () => {
  useLocation.mockReturnValue({ search: '' });
  localStorage.getItem.mockImplementation(key =>
    key === 'tc_session_ref' ? 'ref123' : null
  );
  render(<OIDCCallback />);
  await waitFor(() => expect(globalThis.close).toHaveBeenCalled());
});

// ─── Loading spinner ──────────────────────────────────────────────────────────

it('renders loading spinner on initial mount', () => {
  useLocation.mockReturnValue({ search: '' });
  localStorage.getItem.mockReturnValue(null);
  // Delay resolution so component stays in loading state during assertion
  mockReplace.mockImplementation(() => {});
  const { container } = render(<OIDCCallback />);
  expect(container.querySelector('.anticon-loading')).toBeTruthy();
});

// ─── Popup: SAML Test Connection (?saml_test=1) ─────────────────────────────

// localStorage and sessionStorage share the Storage.prototype mock; answer by key.
const storageWith = (values) => {
  localStorage.getItem.mockImplementation((key) => (key in values ? values[key] : null));
};
const samlDoneWrites = () => localStorage.setItem.mock.calls
  .filter(([key]) => String(key).startsWith('tc_saml_done:'));
const flushPromises = async () => {
  for (let i = 0; i < 10; i += 1) await Promise.resolve();
};

it('tells the parent tab the SAML sign-in finished and closes the popup', async () => {
  useLocation.mockReturnValue({ search: '?saml_test=1&state=s1' });
  storageWith({ tc_session_ref: 'ref123' });
  render(<OIDCCallback />);
  await waitFor(() => expect(globalThis.close).toHaveBeenCalled());
  expect(localStorage.setItem).toHaveBeenCalledWith('tc_saml_done:ref123', '1');
  expect(sessionStorage.removeItem).toHaveBeenCalledWith('oidc_exchange_started_s1');
  expect(localStorage.setItem).not.toHaveBeenCalledWith('tc_result', expect.anything());
  expect(localStorage.removeItem).not.toHaveBeenCalledWith('tc_session_ref');
  expect(signInWithCustomToken).not.toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled();
  expect(mockReplace).not.toHaveBeenCalled();
});

it('closes the SAML popup without a signal when no test session is stored', async () => {
  useLocation.mockReturnValue({ search: '?saml_test=1' });
  storageWith({});
  render(<OIDCCallback />);
  await waitFor(() => expect(globalThis.close).toHaveBeenCalled());
  expect(samlDoneWrites()).toEqual([]);
  expect(mockReplace).not.toHaveBeenCalled();
});

it('does nothing when the same callback already ran in this tab', async () => {
  useLocation.mockReturnValue({ search: '?saml_test=1' });
  storageWith({ tc_session_ref: 'ref123', oidc_exchange_started_default: '1' });
  render(<OIDCCallback />);
  await flushPromises();
  expect(samlDoneWrites()).toEqual([]);
  expect(globalThis.close).not.toHaveBeenCalled();
});

it('treats a saml_test value other than 1 as a normal popup callback', async () => {
  useLocation.mockReturnValue({ search: '?saml_test=true&code=abc&state=xyz' });
  storageWith({ tc_session_ref: 'ref123' });
  render(<OIDCCallback />);
  await waitFor(() => expect(localStorage.setItem).toHaveBeenCalledWith('tc_oidc_code', 'abc'));
  expect(samlDoneWrites()).toEqual([]);
});

it('does not send the SAML signal on a normal token sign-in', async () => {
  signInWithCustomToken.mockResolvedValue();
  useLocation.mockReturnValue({ search: '?token=test-token' });
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(toHome));
  expect(samlDoneWrites()).toEqual([]);
  expect(globalThis.close).not.toHaveBeenCalled();
});

// ─── Error messages ─────────────────────────────────────────────────────────

it('shows the message from the URL when one is given', async () => {
  useLocation.mockReturnValue({ search: '?error=SOMETHING&message=Custom%20reason' });
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(toLogin('Custom reason')));
});

it('shows a generic message for an unknown error code', async () => {
  useLocation.mockReturnValue({ search: '?error=SOMETHING_NEW' });
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(
    toLogin('Sign-in failed. Please try again.')
  ));
});

it('stores a generic failure for an unknown error code in the popup', async () => {
  useLocation.mockReturnValue({ search: '?error=SOMETHING_NEW' });
  storageWith({ tc_session_ref: 'ref123' });
  render(<OIDCCallback />);
  await waitFor(() => expect(globalThis.close).toHaveBeenCalled());
  expect(localStorage.setItem).toHaveBeenCalledWith('tc_result', JSON.stringify({
    type: 'TEST_CONNECTION_FAILED',
    message: 'Sign-in failed.',
  }));
});

it('shows the backend message when the token exchange fails with an unknown code', async () => {
  useLocation.mockReturnValue({ search: '?code=123&state=456' });
  storageWith({ oidc_company_id: 'company123' });
  fetch.mockResolvedValue({
    ok: false,
    json: jest.fn().mockResolvedValue({ error: { code: 'OTHER', message: 'Tenant is disabled.' } }),
  });
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(toLogin('Tenant is disabled.')));
});

it('shows a generic message when the token exchange fails with no details', async () => {
  useLocation.mockReturnValue({ search: '?code=123&state=456' });
  storageWith({ oidc_company_id: 'company123' });
  fetch.mockResolvedValue({ ok: false, json: jest.fn().mockResolvedValue({}) });
  render(<OIDCCallback />);
  await waitFor(() => expect(mockReplace).toHaveBeenCalledWith(
    toLogin('Sign-in failed. Please try again.')
  ));
});

// ─── Token exchange timeout and leaving the page ────────────────────────────

it('aborts the token exchange after 30 seconds and shows a timeout message', async () => {
  jest.useFakeTimers();
  try {
    useLocation.mockReturnValue({ search: '?code=123&state=456' });
    storageWith({ oidc_company_id: 'company123' });
    // fetch settles only when the page aborts it, like a request that never answers.
    fetch.mockImplementation((url, { signal }) => new Promise((resolve, reject) => {
      signal.addEventListener('abort', () => {
        const abortError = new Error('aborted');
        abortError.name = 'AbortError';
        reject(abortError);
      });
    }));
    render(<OIDCCallback />);
    await flushPromises();
    expect(mockReplace).not.toHaveBeenCalled();

    act(() => {
      jest.advanceTimersByTime(30000);
    });
    await flushPromises();

    expect(mockReplace).toHaveBeenCalledWith(toLogin('Request timed out. Please try again.'));
  } finally {
    jest.useRealTimers();
  }
});

it('does not redirect when the page is left during the token exchange', async () => {
  useLocation.mockReturnValue({ search: '?code=123&state=456' });
  storageWith({ oidc_company_id: 'company123' });
  let answer;
  fetch.mockReturnValue(new Promise((resolve) => { answer = resolve; }));
  const { unmount } = render(<OIDCCallback />);
  unmount();
  answer({ ok: true, json: jest.fn().mockResolvedValue({ customToken: 'custom-token' }) });
  await flushPromises();
  expect(signInWithCustomToken).not.toHaveBeenCalled();
  expect(mockReplace).not.toHaveBeenCalled();
});

it('does not redirect when the page is left before the token exchange fails', async () => {
  useLocation.mockReturnValue({ search: '?code=123&state=456' });
  storageWith({ oidc_company_id: 'company123' });
  let fail;
  fetch.mockReturnValue(new Promise((resolve, reject) => { fail = reject; }));
  const { unmount } = render(<OIDCCallback />);
  unmount();
  fail(new Error('Network Error'));
  await flushPromises();
  expect(mockReplace).not.toHaveBeenCalled();
});

it('does not redirect when the page is left before a token sign-in fails', async () => {
  useLocation.mockReturnValue({ search: '?token=test-token' });
  let fail;
  signInWithCustomToken.mockReturnValue(new Promise((resolve, reject) => { fail = reject; }));
  const { unmount } = render(<OIDCCallback />);
  unmount();
  fail(new Error('firebase error'));
  await flushPromises();
  expect(mockReplace).not.toHaveBeenCalled();
});
