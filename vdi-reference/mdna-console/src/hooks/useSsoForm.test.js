/**
 * useSsoForm — readiness gating, file validation, and reset behaviour.
 *
 * The hook only ever touches four antd Form methods, so it is driven with a
 * stub form instead of rendering a real <Form>. That keeps these tests fast and
 * independent of antd v4's rc-field-form internals.
 */

import { renderHook, act } from '@testing-library/react-hooks';

jest.mock('antd', () => ({
  Modal: { confirm: jest.fn() },
  message: { error: jest.fn() },
}));

jest.mock('../constants/SsoConstants', () => ({
  FILE_FIELDS: ['certificate', 'saml_cert', 'saml_signing_cert'],
  IDP_RESET_FIELDS: ['protocol', 'tenant_id', 'client_id'],
  PROTOCOL_RESET_FIELDS: ['tenant_id', 'client_id', 'auth_method'],
}));

import { Modal, message } from 'antd';
import { useSsoForm } from './useSsoForm';

const makeForm = (values = {}, errors = []) => ({
  getFieldsValue: jest.fn(() => values),
  setFieldsValue: jest.fn(),
  resetFields: jest.fn(),
  getFieldsError: jest.fn(() => errors),
});

const OIDC_PKCE = {
  idp: 'entra', protocol: 'oidc', auth_method: 'none',
  tenant_id: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
  client_id: '11111111-2222-3333-4444-555555555555',
  entra_domain: 'contoso.com',
};

const fileEvent = (file) => ({ target: { files: [file], value: String.raw`C:\fake\path` } });
const fakeFile = (name, size) => ({ name, size, text: async () => '', arrayBuffer: async () => new ArrayBuffer(0) });

beforeEach(() => {
  jest.clearAllMocks();
  localStorage.clear();
});

describe('useSsoForm — initial state', () => {
  test('starts unconfigured and not test-ready', () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    expect(result.current.idp).toBeNull();
    expect(result.current.protocol).toBeNull();
    expect(result.current.isTestReady).toBe(false);
    expect(result.current.fileValues).toEqual({});
    expect(result.current.isEditMode).toBe(false);
  });
});

describe('useSsoForm — readiness (handleValuesChange defers via setTimeout)', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  const flush = () => act(() => { jest.runAllTimers(); });

  test('a complete OIDC/PKCE config becomes test-ready', () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    act(() => result.current.handleValuesChange({}, OIDC_PKCE));
    flush();
    expect(result.current.isTestReady).toBe(true);
  });

  test('an incomplete OIDC config does not', () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    act(() => result.current.handleValuesChange({}, { ...OIDC_PKCE, client_id: undefined }));
    flush();
    expect(result.current.isTestReady).toBe(false);
  });

  test('an invalid domain blocks readiness (FQDN check, not just presence)', () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    act(() => result.current.handleValuesChange({}, { ...OIDC_PKCE, entra_domain: 'not_a_domain' }));
    flush();
    expect(result.current.isTestReady).toBe(false);
  });

  test('outstanding antd field errors block readiness even when values are complete', () => {
    const form = makeForm({}, [{ name: ['tenant_id'], errors: ['bad uuid'] }]);
    const { result } = renderHook(() => useSsoForm(form));
    act(() => result.current.handleValuesChange({}, OIDC_PKCE));
    flush();
    expect(result.current.isTestReady).toBe(false);
  });

  test('OIDC with client_secret requires the secret to be present', () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    const base = { ...OIDC_PKCE, auth_method: 'secret' };

    act(() => result.current.handleValuesChange({}, base));
    flush();
    expect(result.current.isTestReady).toBe(false);

    act(() => result.current.handleValuesChange({}, { ...base, client_secret: 'a-real-secret' }));
    flush();
    expect(result.current.isTestReady).toBe(true);
  });

  test('SAML requires an ?appid= SSO URL', () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    const T = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
    const saml = { idp: 'entra', protocol: 'saml', entra_domain: 'contoso.com' };

    act(() => result.current.setFileValues({ saml_cert: fakeFile('c.pem', 100) }));
    act(() => result.current.handleValuesChange({}, {
      ...saml, sso_url: `https://login.microsoftonline.com/${T}/saml2`,
    }));
    flush();
    expect(result.current.isTestReady).toBe(false);
  });
});

describe('useSsoForm — handleFileChange', () => {
  test('rejects an empty file', async () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    await act(async () => { await result.current.handleFileChange('certificate', fileEvent(fakeFile('c.pfx', 0))); });
    expect(message.error).toHaveBeenCalledWith(expect.stringContaining('File is empty'));
    expect(result.current.fileValues.certificate).toBeUndefined();
  });

  test('rejects a file over the 10KB cap', async () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    await act(async () => { await result.current.handleFileChange('certificate', fileEvent(fakeFile('c.pfx', 10 * 1024 + 1))); });
    expect(message.error).toHaveBeenCalledWith(expect.stringContaining('File too large'));
    expect(result.current.fileValues.certificate).toBeUndefined();
  });

  test('drops the field and surfaces the validator message when content is invalid', async () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    // .pem is not a valid PKCS#12 extension → validatePkcs12File throws
    await act(async () => { await result.current.handleFileChange('certificate', fileEvent(fakeFile('c.pem', 200))); });
    expect(message.error).toHaveBeenCalledWith(expect.stringContaining('.pfx or .p12'));
    expect(result.current.fileValues.certificate).toBeUndefined();
  });

  test('ignores an event with no file selected', async () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    await act(async () => { await result.current.handleFileChange('certificate', { target: { files: [] } }); });
    expect(message.error).not.toHaveBeenCalled();
  });
});

describe('useSsoForm — reset handlers', () => {
  test('handleIdpChange clears protocol, auth method, and the SSO localStorage keys', () => {
    localStorage.setItem('oidc_company_id', 'company-1');
    localStorage.setItem('tc_session_ref', 'ref-1');

    const form = makeForm();
    const { result } = renderHook(() => useSsoForm(form));
    act(() => result.current.handleIdpChange('entra'));

    expect(result.current.idp).toBe('entra');
    expect(result.current.protocol).toBeNull();
    expect(result.current.authMethod).toBeNull();
    expect(result.current.isTestReady).toBe(false);
    expect(localStorage.getItem('oidc_company_id')).toBeNull();
    expect(localStorage.getItem('tc_session_ref')).toBeNull();
    expect(form.resetFields).toHaveBeenCalledWith(['protocol', 'tenant_id', 'client_id']);
  });

  test('handleProtocolChange applies immediately when not editing', () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    act(() => result.current.handleProtocolChange('oidc'));
    expect(Modal.confirm).not.toHaveBeenCalled();
    expect(result.current.protocol).toBe('oidc');
  });

  test('handleProtocolChange confirms first when editing an existing protocol', () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    act(() => { result.current.setProtocol('oidc'); result.current.setIsEditMode(true); });
    act(() => result.current.handleProtocolChange('saml'));

    expect(Modal.confirm).toHaveBeenCalledWith(expect.objectContaining({ title: 'Change Protocol?' }));
    expect(result.current.protocol).toBe('oidc'); // unchanged until confirmed

    act(() => Modal.confirm.mock.calls[0][0].onOk());
    expect(result.current.protocol).toBe('saml');
  });

  test('handleAuthMethodChange resets the fields belonging to the other methods', () => {
    const form = makeForm();
    const { result } = renderHook(() => useSsoForm(form));

    act(() => result.current.handleAuthMethodChange('secret'));
    expect(form.resetFields).toHaveBeenCalledWith(['certificate', 'certificate_password']);

    act(() => result.current.handleAuthMethodChange('certificate'));
    expect(form.resetFields).toHaveBeenCalledWith(['client_secret']);

    act(() => result.current.handleAuthMethodChange('none'));
    expect(form.resetFields).toHaveBeenCalledWith(['client_secret', 'certificate', 'certificate_password']);
  });

  test('handleAuthMethodChange invokes the caller reset callback', () => {
    const onReset = jest.fn();
    const { result } = renderHook(() => useSsoForm(makeForm()));
    act(() => result.current.handleAuthMethodChange('secret', onReset));
    expect(onReset).toHaveBeenCalledTimes(1);
  });

  // KNOWN ISSUE — documents current behaviour.
  // handleAuthMethodChange calls resetTestState() (async setFileValues({})) and
  // then evaluates checkTestReady against the *closure's* stale fileValues. An
  // earlier revision fixed this by computing `keptFiles` synchronously. Net
  // effect: files are cleared while readiness is judged against the old set.
  test('handleAuthMethodChange clears fileValues', () => {
    const { result } = renderHook(() => useSsoForm(makeForm()));
    act(() => result.current.setFileValues({ certificate: fakeFile('c.pfx', 100) }));
    act(() => result.current.handleAuthMethodChange('certificate'));
    expect(result.current.fileValues).toEqual({});
  });
});
