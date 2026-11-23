import { renderHook, act } from '@testing-library/react-hooks';
/**
 * useTestConnection — SAML Test Connection asks the backend for the result only
 * after the callback page signals (tc_saml_done:<sessionRef>) or the popup closes.
 */

jest.mock('../services/ssoApi', () => ({
  testConnectionApi: jest.fn(),
  testConnectionCallbackApi: jest.fn(),
  testSamlResultApi: jest.fn(),
}));
jest.mock('../constants/SsoConstants', () => ({
  AUTH_METHOD_MAP: {},
  SAML_ACS_URL: 'https://acs.example.test',
  SAML_ENTITY_ID: 'https://entity.example.test',
  REDIRECT_URI: 'https://console.example.test/sso/redirect',
}));
jest.mock('auth/FirebaseAuth', () => ({ getTenantId: () => 'tenant-1' }));
jest.mock('auth/AuthProvider', () => ({ AuthContext: require('react').createContext({}) }));
import { testConnectionApi, testSamlResultApi } from '../services/ssoApi';
import { useTestConnection } from './useTestConnection';

const form = { getFieldsValue: () => ({
  sso_url: 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/saml2',
  entra_domain: 'a.com',
}) };

let popup;
const flush = async () => { for (let i = 0; i < 6; i += 1) await Promise.resolve(); };
const tick = async (ms) => { await act(async () => { jest.advanceTimersByTime(ms); await flush(); }); };

const start = async (isExistingTest = false) => {
  const hook = renderHook(() => useTestConnection(form, 'saml', {}, jest.fn()));
  let p;
  await act(async () => { p = hook.result.current.handleTestConnection(isExistingTest); await flush(); });
  return { hook, p };
};

beforeEach(() => {
  jest.useFakeTimers();
  ['log', 'debug', 'error', 'warn'].forEach((level) => jest.spyOn(console, level).mockImplementation(() => {}));
  localStorage.clear();
  testSamlResultApi.mockReset();
  testConnectionApi.mockResolvedValue({ ok: true, data: { success: true, data: { sessionRef: 's1', redirectUrl: 'https://login/x' } } });
  popup = { closed: false, close: jest.fn(() => { popup.closed = true; }) };
  window.open = jest.fn(() => popup);
});
afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
});

test('no backend call while the user is signing in', async () => {
  await start();
  await tick(60000);
  expect(testSamlResultApi).not.toHaveBeenCalled();
});

test('signal -> exactly one call -> success, signal key removed', async () => {
  const { hook } = await start();
  await tick(5000);
  testSamlResultApi.mockResolvedValue({ ok: true, status: 200, data: { success: true, data: { claims: { a: 1 } } } });
  localStorage.setItem('tc_saml_done:s1', '1');
  popup.closed = true;
  await tick(300);
  await tick(3000);
  expect(testSamlResultApi).toHaveBeenCalledTimes(1);
  expect(hook.result.current.testResult).toEqual({ status: 'passed', message: 'Test Connection successful.' });
  expect(localStorage.getItem('tc_saml_done:s1')).toBeNull();
});

test('signal but backend still pending -> retries 1 s apart until 200', async () => {
  const { hook } = await start();
  testSamlResultApi
    .mockResolvedValueOnce({ ok: false, status: 401, data: {} })
    .mockResolvedValueOnce({ ok: true, status: 202, data: { pending: true } })
    .mockResolvedValue({ ok: true, status: 200, data: { success: true, data: {} } });
  localStorage.setItem('tc_saml_done:s1', '1');
  await tick(300);
  expect(testSamlResultApi).toHaveBeenCalledTimes(1);
  await tick(600);
  expect(testSamlResultApi).toHaveBeenCalledTimes(1);
  await tick(600);
  expect(testSamlResultApi).toHaveBeenCalledTimes(2);
  await tick(1200);
  expect(testSamlResultApi).toHaveBeenCalledTimes(3);
  expect(hook.result.current.testPassed).toBe(true);
});

test('closed without signal + 202 -> cancelled after one call', async () => {
  const { hook } = await start();
  testSamlResultApi.mockResolvedValue({ ok: true, status: 202, data: { pending: true } });
  popup.closed = true;
  await tick(300);
  await tick(5000);
  expect(testSamlResultApi).toHaveBeenCalledTimes(1);
  expect(hook.result.current.testResult).toEqual({ status: 'failed', message: 'Test Connection was cancelled. Please try again.' });
});

test('closed without signal + 401 -> 3 tries, then cancelled', async () => {
  const { hook } = await start();
  testSamlResultApi.mockResolvedValue({ ok: false, status: 401, data: {} });
  popup.closed = true;
  for (let i = 0; i < 12; i += 1) await tick(300);
  expect(testSamlResultApi).toHaveBeenCalledTimes(3);
  expect(hook.result.current.testResult.message).toBe('Test Connection was cancelled. Please try again.');
});

test('closed without signal but backend already has the result -> success', async () => {
  const { hook } = await start();
  testSamlResultApi.mockResolvedValue({ ok: true, status: 200, data: { success: true, data: {} } });
  popup.closed = true;
  await tick(300);
  expect(hook.result.current.testPassed).toBe(true);
});

test('callback error in tc_result -> failed, no backend call', async () => {
  const { hook } = await start();
  localStorage.setItem('tc_result', JSON.stringify({ message: 'SAML response missing. Please try signing in again.' }));
  await tick(300);
  expect(testSamlResultApi).not.toHaveBeenCalled();
  expect(hook.result.current.testResult.message).toBe('SAML response missing. Please try signing in again.');
});

test('callback error that is not JSON -> shown as-is, no backend call', async () => {
  const { hook } = await start();
  localStorage.setItem('tc_result', 'Plain callback error');
  await tick(300);
  expect(testSamlResultApi).not.toHaveBeenCalled();
  expect(hook.result.current.testResult).toEqual({ status: 'failed', message: 'Plain callback error' });
});

test('callback error without a message -> default Entra message', async () => {
  const { hook } = await start();
  localStorage.setItem('tc_result', JSON.stringify({}));
  await tick(300);
  expect(testSamlResultApi).not.toHaveBeenCalled();
  expect(hook.result.current.testResult.message).toBe('Microsoft Entra authentication failed.');
});

test('result call throws -> logged, retried 1 s later, then success', async () => {
  const { hook } = await start();
  const networkError = new Error('Network down');
  testSamlResultApi
    .mockRejectedValueOnce(networkError)
    .mockResolvedValue({ ok: true, status: 200, data: { success: true, data: {} } });
  localStorage.setItem('tc_saml_done:s1', '1');

  await tick(300);
  expect(testSamlResultApi).toHaveBeenCalledTimes(1);
  expect(console.error).toHaveBeenCalledWith('[SSO] SAML result API failed', networkError);
  expect(hook.result.current.testPassed).not.toBe(true);

  await tick(1200);
  expect(testSamlResultApi).toHaveBeenCalledTimes(2);
  expect(hook.result.current.testResult).toEqual({ status: 'passed', message: 'Test Connection successful.' });
});

test('times out after 5 minutes with no calls', async () => {
  const { hook } = await start();
  await tick(5 * 60 * 1000 + 300);
  expect(testSamlResultApi).not.toHaveBeenCalled();
  expect(hook.result.current.testResult.message).toBe('Test connection validation timed out. Please try again.');
});
