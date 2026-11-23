import { act, create } from 'react-test-renderer';
/**
 * OIDC callback page — for a SAML Test Connection (?saml_test=1) the popup only
 * tells the parent tab it is done (tc_saml_done:<sessionRef>) and closes itself.
 */

let mockSearch = '';
const mockReplace = jest.fn();
const mockSignIn = jest.fn();
jest.mock('react-router-dom', () => ({
  useHistory: () => ({ replace: mockReplace, push: jest.fn() }),
  useLocation: () => ({ search: mockSearch }),
}), { virtual: true });
jest.mock('antd', () => ({ Spin: () => null }), { virtual: true });
jest.mock('@ant-design/icons', () => ({ LoadingOutlined: () => null }), { virtual: true });
jest.mock('firebase/auth', () => ({
  getAuth: () => ({}),
  signInWithCustomToken: (...args) => mockSignIn(...args),
}), { virtual: true });
import OIDCCallback from './index';

const doneKeys = () => Object.keys(localStorage).filter((k) => k.startsWith('tc_saml_done:'));

const renderAt = async (search) => {
  mockSearch = search;
  await act(async () => { create(<OIDCCallback />); });
};

describe('OIDC callback page — SAML Test Connection signal', () => {
  let closeSpy;

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    jest.clearAllMocks();
    closeSpy = jest.spyOn(window, 'close').mockImplementation(() => {});
  });

  afterEach(() => {
    closeSpy.mockRestore();
  });

  test('tells the parent tab the sign-in finished and closes the popup', async () => {
    localStorage.setItem('tc_session_ref', 'ref-1');

    await renderAt('?saml_test=1&state=s1');

    expect(localStorage.getItem('tc_saml_done:ref-1')).toBe('1');
    expect(sessionStorage.getItem('oidc_exchange_started_s1')).toBeNull();
    expect(closeSpy).toHaveBeenCalledTimes(1);
    expect(mockSignIn).not.toHaveBeenCalled();
    expect(mockReplace).not.toHaveBeenCalled();
  });

  test('closes without a signal when no test session is stored', async () => {
    await renderAt('?saml_test=1');

    expect(doneKeys()).toEqual([]);
    expect(closeSpy).toHaveBeenCalledTimes(1);
    expect(mockReplace).not.toHaveBeenCalled();
  });

  test('leaves the test session ref for the parent tab to clean up', async () => {
    localStorage.setItem('tc_session_ref', 'ref-2');

    await renderAt('?saml_test=1');

    expect(localStorage.getItem('tc_session_ref')).toBe('ref-2');
    expect(localStorage.getItem('tc_result')).toBeNull();
  });

  test('does nothing when the same callback already ran in this tab', async () => {
    localStorage.setItem('tc_session_ref', 'ref-3');
    sessionStorage.setItem('oidc_exchange_started_default', '1');

    await renderAt('?saml_test=1');

    expect(doneKeys()).toEqual([]);
    expect(closeSpy).not.toHaveBeenCalled();
  });

  test('does not signal on a normal SSO sign-in callback', async () => {
    const previousUrl = process.env.REACT_APP_MICROSERVICE_API_URL;
    process.env.REACT_APP_MICROSERVICE_API_URL = 'https://api.example.test';
    mockSignIn.mockResolvedValue({});

    try {
      await renderAt('?token=custom-token');
    } finally {
      process.env.REACT_APP_MICROSERVICE_API_URL = previousUrl;
    }

    expect(doneKeys()).toEqual([]);
    expect(mockSignIn).toHaveBeenCalledWith({}, 'custom-token');
    expect(mockReplace).toHaveBeenCalledWith({ pathname: '/app/home', state: {} });
    expect(closeSpy).not.toHaveBeenCalled();
  });
});
