/**
 * useEntraClaims — loads the Entra claims catalog for the JIT checks (DLM-100021).
 *
 * Stack: React 16 + @testing-library/react-hooks v8. The API is mocked; fake
 * timers drive the 400 ms typing delay.
 */

import { renderHook, act } from '@testing-library/react-hooks';
import { useEntraClaims } from './useEntraClaims';
import { getEntraClaimsApi } from '../services/ssoApi';

jest.mock('../services/ssoApi', () => ({ getEntraClaimsApi: jest.fn() }));

const TENANT = '11111111-2222-3333-4444-555555555555';
const CLIENT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const SAML_URL = `https://login.microsoftonline.com/${TENANT}/saml2`;

const CATALOG = {
  claimNames: ['roles', 'groups', 'department'],
  roles: ['Zebra.Admin'],
  groups: [{ id: 'g1', name: 'ZDNA Admins' }],
  userAttributes: { departments: ['Sales'], jobTitles: ['Manager'] },
};

const oidcProps = (over = {}) => ({
  enabled: true, companyId: 'company-1', protocol: 'oidc', tenantId: TENANT, clientId: CLIENT, ...over,
});

// Run the 400 ms delay, then let the awaited API call settle.
const runLoad = async () => {
  await act(async () => {
    jest.advanceTimersByTime(400);
    for (let i = 0; i < 5; i += 1) await Promise.resolve();
  });
};

beforeEach(() => {
  jest.useFakeTimers();
  getEntraClaimsApi.mockReset();
  getEntraClaimsApi.mockResolvedValue({ ok: true, status: 200, data: { success: true, data: CATALOG } });
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  jest.useRealTimers();
  console.warn.mockRestore();
});

describe('useEntraClaims — when it loads', () => {
  test('stays idle and calls nothing when not enabled', async () => {
    const { result } = renderHook(() => useEntraClaims(oidcProps({ enabled: false })));
    await runLoad();
    expect(result.current.status).toBe('idle');
    expect(result.current.catalog).toBeUndefined();
    expect(getEntraClaimsApi).not.toHaveBeenCalled();
  });

  test('shows an error and calls nothing when the OIDC tenant ID is not a GUID', async () => {
    const { result } = renderHook(() => useEntraClaims(oidcProps({ tenantId: 'contoso' })));
    await runLoad();
    expect(result.current.status).toBe('error');
    expect(result.current.error).toMatch(/no valid tenant or app ID/);
    expect(getEntraClaimsApi).not.toHaveBeenCalled();
  });

  test('shows an error when the OIDC client ID is missing', async () => {
    const { result } = renderHook(() => useEntraClaims(oidcProps({ clientId: '' })));
    await runLoad();
    expect(result.current.status).toBe('error');
    expect(getEntraClaimsApi).not.toHaveBeenCalled();
  });

  test('shows an error when the SAML SSO URL has no tenant', async () => {
    const { result } = renderHook(() =>
      useEntraClaims({ enabled: true, companyId: 'company-1', protocol: 'saml', ssoUrl: 'https://idp.example.com/sso' }));
    await runLoad();
    expect(result.current.status).toBe('error');
    expect(getEntraClaimsApi).not.toHaveBeenCalled();
  });

  test('shows an error for an unknown protocol', async () => {
    const { result } = renderHook(() => useEntraClaims(oidcProps({ protocol: 'ldap' })));
    await runLoad();
    expect(result.current.status).toBe('error');
  });
});

describe('useEntraClaims — loading the catalog', () => {
  test('waits 400 ms, then loads the OIDC catalog', async () => {
    const { result } = renderHook(() => useEntraClaims(oidcProps()));
    expect(result.current.status).toBe('loading');
    expect(getEntraClaimsApi).not.toHaveBeenCalled();

    await runLoad();

    expect(getEntraClaimsApi).toHaveBeenCalledTimes(1);
    expect(getEntraClaimsApi).toHaveBeenCalledWith({
      company_id: 'company-1', protocol: 'oidc', tenant_id: TENANT, client_id: CLIENT, sso_url: undefined,
    });
    expect(result.current).toMatchObject({ status: 'ready', catalog: CATALOG, error: null });
  });

  test('loads the SAML catalog from the tenant in the SSO URL', async () => {
    const { result } = renderHook(() =>
      useEntraClaims({ enabled: true, companyId: 'company-1', protocol: 'saml', ssoUrl: SAML_URL }));
    await runLoad();
    expect(getEntraClaimsApi).toHaveBeenCalledWith(expect.objectContaining({ protocol: 'saml', sso_url: SAML_URL }));
    expect(result.current.status).toBe('ready');
  });

  test('makes one request while the admin is still typing', async () => {
    const { rerender } = renderHook((props) => useEntraClaims(props), { initialProps: oidcProps() });
    act(() => { jest.advanceTimersByTime(200); });
    rerender(oidcProps({ companyId: 'company-2' }));
    await runLoad();
    expect(getEntraClaimsApi).toHaveBeenCalledTimes(1);
    expect(getEntraClaimsApi).toHaveBeenCalledWith(expect.objectContaining({ company_id: 'company-2' }));
  });

  test('goes back to idle when it is turned off', async () => {
    const { result, rerender } = renderHook((props) => useEntraClaims(props), { initialProps: oidcProps() });
    await runLoad();
    expect(result.current.status).toBe('ready');
    rerender(oidcProps({ enabled: false }));
    expect(result.current.status).toBe('idle');
    expect(result.current.catalog).toBeUndefined();
  });
});

describe('useEntraClaims — errors and retry', () => {
  test('shows the API error message (e.g. connector not consented)', async () => {
    getEntraClaimsApi.mockResolvedValue({
      ok: false, status: 403,
      data: { success: false, error: { code: 'ENTRA_CONNECTOR_NOT_CONSENTED', message: 'Grant admin consent first.' } },
    });
    const { result } = renderHook(() => useEntraClaims(oidcProps()));
    await runLoad();
    expect(result.current).toMatchObject({ status: 'error', error: 'Grant admin consent first.', catalog: undefined });
  });

  test('falls back to the top-level message', async () => {
    getEntraClaimsApi.mockResolvedValue({ ok: false, status: 404, data: { message: 'App not found.' } });
    const { result } = renderHook(() => useEntraClaims(oidcProps()));
    await runLoad();
    expect(result.current.error).toBe('App not found.');
  });

  test('shows the generic message when the response has none', async () => {
    getEntraClaimsApi.mockResolvedValue({ ok: true, status: 200, data: { success: false } });
    const { result } = renderHook(() => useEntraClaims(oidcProps()));
    await runLoad();
    expect(result.current.error).toBe('Could not load claims from Microsoft Entra. Please try again.');
  });

  test('shows the generic message on a network error', async () => {
    getEntraClaimsApi.mockRejectedValue(new Error('Network error'));
    const { result } = renderHook(() => useEntraClaims(oidcProps()));
    await runLoad();
    expect(result.current.status).toBe('error');
    expect(result.current.error).toBe('Could not load claims from Microsoft Entra. Please try again.');
  });

  test('retry() loads the catalog again', async () => {
    getEntraClaimsApi.mockRejectedValueOnce(new Error('Network error'));
    const { result } = renderHook(() => useEntraClaims(oidcProps()));
    await runLoad();
    expect(result.current.status).toBe('error');

    act(() => result.current.retry());
    expect(result.current.status).toBe('loading');
    await runLoad();

    expect(getEntraClaimsApi).toHaveBeenCalledTimes(2);
    expect(result.current.status).toBe('ready');
  });

  test('ignores a late answer after unmount', async () => {
    let answer;
    getEntraClaimsApi.mockReturnValue(new Promise((resolve) => { answer = resolve; }));
    const { result, unmount } = renderHook(() => useEntraClaims(oidcProps()));
    await runLoad();
    unmount();
    await act(async () => { answer({ ok: true, data: { success: true, data: CATALOG } }); });
    expect(result.current.status).toBe('loading');
  });
});
