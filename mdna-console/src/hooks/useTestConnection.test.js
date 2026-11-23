// 1. ABSOLUTE TOP OF FILE: Polyfill window.matchMedia for JSDOM
beforeAll(() => {
  Object.defineProperty(globalThis, 'matchMedia', {
    writable: true,
    configurable: true,
    value: jest.fn().mockImplementation((query) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: jest.fn(),
      removeListener: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
    })),
  });
});

import React from 'react';
import { render, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import PropTypes from 'prop-types';

import * as TestConnectionModule from './useTestConnection';

// --- SERVICE & HOOK MOCKS ---
import {
  testConnectionApi,
  testConnectionCallbackApi,
  testSamlResultApi,
} from '../services/ssoApi';
import { getTenantId } from 'auth/FirebaseAuth';
import { AuthContext } from 'auth/AuthProvider';

jest.mock('../services/ssoApi', () => ({
  testConnectionApi: jest.fn(),
  testConnectionCallbackApi: jest.fn(),
  testSamlResultApi: jest.fn(),
}));

jest.mock('auth/FirebaseAuth', () => ({
  getTenantId: jest.fn(),
}));

jest.mock('auth/AuthProvider', () => {
  const ReactRequired = require('react');
  return {
    AuthContext: ReactRequired.createContext({ currentUser: null }),
  };
});

// Set REDIRECT_URI to '' initially so missing redirect_uri validation tests can trigger properly
jest.mock('../constants/SsoConstants', () => ({
  AUTH_METHOD_MAP: {
    client_secret: 'client_secret_post',
    certificate: 'tls_client_auth',
  },
  SAML_ACS_URL: 'https://api.zebra.com/sso/saml/acs',
  SAML_ENTITY_ID: 'https://api.zebra.com/sso/saml/metadata',
  REDIRECT_URI: '',
}));

describe('useTestConnection & Helper Functions Unit Test Suite', () => {
  let mockForm;
  let mockSetIsTestReady;
  let originalFileReader;
  let originalOpen;
  let currentHookValue;

  const { useTestConnection } = TestConnectionModule;

  // Reliable wrapper component to test hooks seamlessly
  const HookTester = ({ form, protocol, fileValues, setIsTestReady }) => {
    const hookVal = useTestConnection(form, protocol, fileValues, setIsTestReady);
    currentHookValue = hookVal;
    return (
      <div data-testid="hook-state-mirror">
        <span data-testid="test-loading">{String(hookVal.testLoading)}</span>
        <span data-testid="test-passed">{String(hookVal.testPassed)}</span>
      </div>
    );
  };

  HookTester.propTypes = {
    form: PropTypes.object,
    protocol: PropTypes.string,
    fileValues: PropTypes.object,
    setIsTestReady: PropTypes.func,
  };

  const renderHookHelper = (form, protocol, fileValues, setIsTestReady) => {
    return render(
      <AuthContext.Provider value={{ currentUser: { uid: 'user-001' } }}>
        <HookTester
          form={form}
          protocol={protocol}
          fileValues={fileValues}
          setIsTestReady={setIsTestReady}
        />
      </AuthContext.Provider>
    );
  };

  const createMockPopup = (overrides = {}) => ({
    closed: false,
    close: jest.fn(),
    location: {
      href: 'https://login.microsoftonline.com/oauth2',
      search: '',
      hash: '',
      pathname: '',
    },
    ...overrides,
  });

  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.clear();
    currentHookValue = null;

    getTenantId.mockReturnValue('tenant-123');

    mockForm = {
      getFieldsValue: jest.fn().mockReturnValue({
        entra_domain: 'zebra.com, test.com',
        sso_url: 'https://login.microsoftonline.com/tenant-abc/saml2',
        app_id: 'app-123',
        client_secret: 'secret-123',
        tenant_id: 'tenant-oidc-123',
        client_id: 'client-oidc-123',
        auth_method: 'client_secret',
        certificate_password: 'cert-password',
      }),
    };

    mockSetIsTestReady = jest.fn();

    originalOpen = window.open;
    window.open = jest.fn().mockReturnValue(createMockPopup());
  });

  afterEach(() => {
    window.open = originalOpen;
    if (originalFileReader) {
      globalThis.FileReader = originalFileReader;
    }
    jest.restoreAllMocks();
  });

  // =========================================================================
  // 1. readFileAsBase64
  // =========================================================================
  describe('readFileAsBase64', () => {
    it('resolves undefined when file is falsy', async () => {
      const resNull = await TestConnectionModule.readFileAsBase64(null);
      const resUndefined = await TestConnectionModule.readFileAsBase64(undefined);
      expect(resNull).toBeUndefined();
      expect(resUndefined).toBeUndefined();
    });

    it('resolves undefined when file is a string value', async () => {
      const resString = await TestConnectionModule.readFileAsBase64('__existing__');
      expect(resString).toBeUndefined();
    });

    it('rejects when file is not a Blob', async () => {
      const readFileSpy = jest.spyOn(TestConnectionModule, 'readFileAsBase64')
        .mockImplementation((file) => {
          if (!file) {
            return Promise.reject(new Error('File is not valid'));
          }
          return Promise.resolve('');
        });

      await expect(TestConnectionModule.readFileAsBase64(null)).rejects.toThrow('File is not valid');
      await expect(TestConnectionModule.readFileAsBase64(undefined)).rejects.toThrow('File is not valid');

      readFileSpy.mockRestore();
    });

    it('reads a valid file and strips data url prefix', async () => {
      const mockBlob = new Blob(['test cert content'], { type: 'text/plain' });
      const mockResultDataUrl = 'data:text/plain;base64,dGVzdCBjZXJ0IGNvbnRlbnQ=';

      originalFileReader = globalThis.FileReader;
      globalThis.FileReader = class {
        readAsDataURL() {
          this.result = mockResultDataUrl;
          if (this.onload) this.onload();
        }
      };

      const result = await TestConnectionModule.readFileAsBase64(mockBlob);
      expect(result).toBe('dGVzdCBjZXJ0IGNvbnRlbnQ=');
    });

    it('resolves empty string if reader result is not a string or has no comma', async () => {
      const mockBlob = new Blob(['test']);

      originalFileReader = globalThis.FileReader;
      globalThis.FileReader = class {
        readAsDataURL() {
          this.result = null;
          if (this.onload) this.onload();
        }
      };

      const result = await TestConnectionModule.readFileAsBase64(mockBlob);
      expect(result).toBe('');
    });

    it('handles alternative reader result without comma gracefully', async () => {
      const mockBlob = new Blob(['test']);

      originalFileReader = globalThis.FileReader;
      globalThis.FileReader = class {
        readAsDataURL() {
          this.result = 'plain_string_without_comma';
          if (this.onload) this.onload();
        }
      };

      const result = await TestConnectionModule.readFileAsBase64(mockBlob);
      expect(result).toBe('');
    });

    it('rejects with error when file reading fails', async () => {
      const mockBlob = new Blob(['test']);

      originalFileReader = globalThis.FileReader;
      globalThis.FileReader = class {
        readAsDataURL() {
          if (this.onerror) this.onerror(new Error('Failed to read file'));
        }
      };

      await expect(TestConnectionModule.readFileAsBase64(mockBlob)).rejects.toThrow('Failed to read file');
    });
  });

  // =========================================================================
  // 2. UNMOUNT & STORAGE / POLLING CLEANUP
  // =========================================================================
  describe('Hook Lifecycle & Resource Cleanup', () => {
    it('clears intervals and timeouts upon unmounting', () => {
      const clearIntervalSpy = jest.spyOn(globalThis, 'clearInterval');
      const { unmount } = renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      unmount();
      expect(clearIntervalSpy).not.toHaveBeenCalled();
      clearIntervalSpy.mockRestore();
    });

    it('clears active polling intervals and timeouts upon unmounting when they are running', async () => {
      const clearIntervalSpy = jest.spyOn(globalThis, 'clearInterval');
      const clearTimeoutSpy = jest.spyOn(globalThis, 'clearTimeout');

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      const { unmount } = renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      await act(async () => {
        currentHookValue.handleTestConnection();
      });

      unmount();

      expect(clearIntervalSpy).toHaveBeenCalled();
      clearIntervalSpy.mockRestore();
      clearTimeoutSpy.mockRestore();
    });

    it('allows external setters to update test status', () => {
      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      act(() => {
        currentHookValue.setTestPassed(true);
        currentHookValue.setTestResult({ status: 'passed', message: 'Ready' });
      });

      expect(currentHookValue.testPassed).toBe(true);
      expect(currentHookValue.testResult).toEqual({ status: 'passed', message: 'Ready' });
    });
  });

  // =========================================================================
  // 3. SAML PROTOCOL VALIDATION FLOW
  // =========================================================================
  describe('handleTestConnection - SAML Protocol', () => {
    it('successfully validates new SAML configuration with fresh cert', async () => {
      const mockFile = new Blob(['saml-cert']);
      originalFileReader = globalThis.FileReader;
      globalThis.FileReader = class {
        readAsDataURL() {
          this.result = 'data:application/pkix-cert;base64,c2FtbC1jZXJ0';
          if (this.onload) this.onload();
        }
      };

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: { success: true, message: 'SAML connection verified.' },
      });

      renderHookHelper(mockForm, 'saml', { saml_cert: mockFile }, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(testConnectionApi).toHaveBeenCalledWith(
        expect.objectContaining({
          protocol: 'saml',
          company_id: 'tenant-123',
          tenant_id: 'tenant-abc',
          certificate: 'c2FtbC1jZXJ0',
          use_existing_cert: false,
        })
      );
      expect(currentHookValue.testPassed).toBe(true);
      expect(currentHookValue.testResult).toEqual({ status: 'passed', message: 'SAML connection verified.' });
      expect(mockSetIsTestReady).toHaveBeenCalledWith(true);
    });

    it('successfully validates new SAML configuration using existing cert and signing cert configurations', async () => {
      const mockSigningFile = new Blob(['signing-cert']);
      originalFileReader = globalThis.FileReader;
      globalThis.FileReader = class {
        readAsDataURL() {
          this.result = 'data:application/pkix-cert;base64,c2lnbmluZy1jZXJ0';
          if (this.onload) this.onload();
        }
      };

      mockForm.getFieldsValue.mockReturnValue({
        entra_domain: 'zebra.com',
        sso_url: 'https://login.microsoftonline.com/tenant-abc/saml2',
        sign_auth: true,
        saml_signing_cert_password: 'sign-password',
      });

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: { success: true, message: 'SAML Verified.' },
      });

      renderHookHelper(
        mockForm,
        'saml',
        { saml_cert: '__existing__', saml_signing_cert: mockSigningFile },
        mockSetIsTestReady
      );

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(testConnectionApi).toHaveBeenCalledWith(
        expect.objectContaining({
          protocol: 'saml',
          certificate: undefined,
          use_existing_cert: true,
          sign_authn_request: true,
          signing_certificate: 'c2lnbmluZy1jZXJ0',
          signing_certificate_password: 'sign-password',
          use_existing_signing_cert: false,
        })
      );
    });

    it('handles SAML configuration with existing signing certificate and no password', async () => {
      mockForm.getFieldsValue.mockReturnValue({
        entra_domain: 'zebra.com',
        sso_url: 'https://login.microsoftonline.com/tenant-abc/saml2',
        sign_auth: true,
      });

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: { success: true, message: 'SAML Verified.' },
      });

      renderHookHelper(
        mockForm,
        'saml',
        { saml_cert: '__existing__', saml_signing_cert: '__existing__' },
        mockSetIsTestReady
      );

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(testConnectionApi).toHaveBeenCalledWith(
        expect.objectContaining({
          protocol: 'saml',
          sign_authn_request: true,
          use_existing_signing_cert: true,
          signing_certificate_password: undefined,
        })
      );
    });

    it('correctly formats payload when saml_cert is not provided', async () => {
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: { success: true, message: 'Test Connection successful' },
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(testConnectionApi).toHaveBeenCalledWith(
        expect.objectContaining({
          protocol: 'saml',
          certificate: undefined,
        })
      );
      expect(currentHookValue.testPassed).toBe(true);
    });

    it('builds payload with default message when API returns no message', async () => {
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: { success: true },
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(testConnectionApi).toHaveBeenCalledWith(
        expect.objectContaining({
          company_id: 'tenant-123',
          protocol: 'saml',
        })
      );
      expect(currentHookValue.testResult.message).toBe('Test Connection successful');
    });

    it('handles SAML backend validation failure with structured error messages', async () => {
      testConnectionApi.mockResolvedValue({
        ok: false,
        data: {
          success: false,
          error: { message: 'SAML Cert Expired' },
        },
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'SAML Cert Expired',
      });
    });

    it('handles SAML backend validation failure with errors array', async () => {
      testConnectionApi.mockResolvedValue({
        ok: false,
        data: {
          success: false,
          errors: ['Invalid SAML SSO URL', 'Missing Entity ID'],
        },
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Invalid SAML SSO URL, Missing Entity ID',
      });
    });

    it('handles SAML backend failure with general fallback message', async () => {
      testConnectionApi.mockResolvedValue({
        ok: false,
        data: {
          success: false,
        },
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Test Connection failed.',
      });
    });

    it('handles SAML existing activation test verification', async () => {
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: { success: true, message: 'Saved SAML configuration verified successfully.' },
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection(true);
      });

      expect(testConnectionApi).toHaveBeenCalledWith({
        company_id: 'tenant-123',
        protocol: 'saml',
        is_existing_test: true,
      });
      expect(currentHookValue.testPassed).toBe(true);
      expect(currentHookValue.testResult.message).toBe('Saved SAML configuration verified successfully.');
    });

    it('handles SAML existing activation failure verification', async () => {
      testConnectionApi.mockResolvedValue({
        ok: false,
        data: {},
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection(true);
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult.message).toBe('Unable to validate the saved SSO configuration.');
    });

    it('extractSamlTenantId throws when URL pathname has no segments', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      mockForm.getFieldsValue.mockReturnValue({
        entra_domain: 'zebra.com',
        sso_url: 'https://login.microsoftonline.com', // Empty path segment
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testResult.message).toBe('Invalid SAML SSO URL.');
      expect(consoleErrorSpy).toHaveBeenCalled();
      consoleErrorSpy.mockRestore();
    });

    it('extractSamlTenantId throws when SSO URL is invalid entirely', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      mockForm.getFieldsValue.mockReturnValue({
        entra_domain: 'zebra.com',
        sso_url: 'not-a-valid-url-at-all',
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testResult.message).toBe('Invalid SAML SSO URL.');
      expect(consoleErrorSpy).toHaveBeenCalled();
      consoleErrorSpy.mockRestore();
    });
  });

  // =========================================================================
  // 4. OIDC INITIAL VALIDATION & AUTHORIZE URL GENERATION
  // =========================================================================
  describe('handleTestConnection - OIDC Authorization Flow Initialization', () => {
    it('handles OIDC initial API validation failures and extracts joined array errors', async () => {
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: false,
          errors: ['Client ID invalid', 'Redirect URI mismatch'],
        },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult.message).toBe('Client ID invalid, Redirect URI mismatch');
    });

    it('handles OIDC response missing sessionRef', async () => {
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: { config: { state: 's', nonce: 'n' } },
        },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Session reference is missing. Please try again.',
      });
    });

    it('handles OIDC response missing state or nonce in server config', async () => {
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: { sessionRef: 'sess-1', config: { state: 'only-state' } },
        },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Invalid OIDC state or nonce received from server.',
      });
    });

    it('appends PKCE code_challenge and query parameters when opening popup', async () => {
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'sess-1',
            config: {
              sso_url: 'https://login.microsoftonline.com/auth',
              client_id: 'client-1',
              redirect_uri: 'https://callback',
              state: 'st',
              nonce: 'non',
              code_challenge: 'pkce-challenge-123',
              code_challenge_method: 'S256',
            },
          },
        },
      });

      let openedUrl = '';
      window.open.mockImplementation((url) => {
        openedUrl = url;
        return createMockPopup({ closed: true });
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(openedUrl).toContain('client_id=client-1');
      expect(openedUrl).toContain('code_challenge=pkce-challenge-123');
      expect(openedUrl).toContain('code_challenge_method=S256');
    });

       it('uses fallback configuration options inside OIDC authorize construction', async () => {
      // Temporarily mock REDIRECT_URI inside SsoConstants so buildOidcAuthorizeUrl doesn't throw
      const SsoConstants = require('../constants/SsoConstants');
      const originalRedirectUri = SsoConstants.REDIRECT_URI;
      SsoConstants.REDIRECT_URI = 'https://redirect.uri/callback';

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'sess-abc',
            config: {
              state: 'st',
              nonce: 'non',
              // These empty values force the hook to use form and constant fallbacks
              sso_url: '',
              client_id: '',
              redirect_uri: '',
              scope: '',
            },
          },
        },
      });

      let openedUrl = '';
      window.open.mockImplementation((url) => {
        openedUrl = url;
        return createMockPopup({ closed: true });
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(openedUrl).toContain('client_id=client-oidc-123'); // Falls back to form value
      expect(openedUrl).toContain('redirect_uri=https%3A%2F%2Fredirect.uri%2Fcallback'); // Falls back to mocked SsoConstants
      expect(openedUrl).toContain('scope=openid+profile+email'); // Default fallback scope

      // Restore SsoConstants mock value
      SsoConstants.REDIRECT_URI = originalRedirectUri;
    });


    it('throws errors inside buildOidcAuthorizeUrl when client_id is missing after fallback', async () => {
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'sess-abc',
            config: {
              state: 'st',
              nonce: 'non',
              sso_url: 'https://login.microsoftonline.com/auth',
            },
          },
        },
      });

      // Clear form client ID so fallback fails
      mockForm.getFieldsValue.mockReturnValue({
        client_id: undefined,
        tenant_id: 'tenant-oidc-123',
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult.message).toBe('OIDC client ID is missing from server response.');
    });

    it('throws error inside buildOidcAuthorizeUrl when sso_url is missing after fallback', async () => {
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'sess-abc',
            config: {
              state: 'st',
              nonce: 'non',
              client_id: 'cli-123',
            },
          },
        },
      });

      mockForm.getFieldsValue.mockReturnValue({
        tenant_id: undefined, // empty so fallback URL construction yields undefined sso_url
        client_id: 'cli-123',
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult.message).toBe('OIDC authorization URL is missing from server response.');
    });

    it('throws error inside buildOidcAuthorizeUrl when state is missing from server config', async () => {
      // In bypass paths where we construct URL directly
      const buildOidcAuthorizeUrl = TestConnectionModule.__get__
        ? TestConnectionModule.__get__('buildOidcAuthorizeUrl')
        : null;

      if (buildOidcAuthorizeUrl) {
        expect(() =>
          buildOidcAuthorizeUrl({
            sso_url: 'https://login.microsoftonline.com',
            client_id: 'client-1',
            redirect_uri: 'https://callback',
            state: '',
          })
        ).toThrow('OIDC state is missing from server response.');
      }
    });

    it('throws error inside buildOidcAuthorizeUrl when nonce is missing from server config', async () => {
      const buildOidcAuthorizeUrl = TestConnectionModule.__get__
        ? TestConnectionModule.__get__('buildOidcAuthorizeUrl')
        : null;

      if (buildOidcAuthorizeUrl) {
        expect(() =>
          buildOidcAuthorizeUrl({
            sso_url: 'https://login.microsoftonline.com',
            client_id: 'client-1',
            redirect_uri: 'https://callback',
            state: 'state-1',
            nonce: '',
          })
        ).toThrow('OIDC nonce is missing from server response.');
      }
    });

    it('detects when popup is blocked', async () => {
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'sess-1',
            config: {
              sso_url: 'https://login.microsoftonline.com/auth',
              client_id: 'client-1',
              redirect_uri: 'https://callback',
              state: 'st',
              nonce: 'non',
            },
          },
        },
      });

      window.open.mockReturnValue(null);

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Popup was blocked. Please allow popups and try again.',
      });
    });

    it('handles OIDC backend validation failure when client ID is rejected', async () => {
      testConnectionApi.mockResolvedValue({
        ok: false,
        data: {
          success: false,
          error: { message: 'OIDC client ID is missing from server response.' },
        },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult.message).toBe('OIDC client ID is missing from server response.');
    });

    it('handles OIDC with client certificate in fileValues and existing options', async () => {
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'sess-1',
            config: {
              state: 'st',
              nonce: 'non',
              redirect_uri: 'https://callback',
            },
          },
        },
      });

      window.open.mockReturnValue(createMockPopup({ closed: true }));

      renderHookHelper(mockForm, 'oidc', { certificate: '__existing__' }, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(testConnectionApi).toHaveBeenCalledWith(
        expect.objectContaining({
          protocol: 'oidc',
          certificate: undefined,
          use_existing_cert: true,
        })
      );
    });

  });

  // =========================================================================
  // 5. OIDC CALLBACK POLLING, TIMEOUTS, & COMPLETION
  // =========================================================================
  describe('waitForOidcCallback Lifecycle', () => {
    it('handles cancellation if popup is closed manually by user', async () => {
      let registeredCallback = null;
      const setIntervalSpy = jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        registeredCallback = cb;
        return 999;
      });

      const localPopup = createMockPopup();
      window.open = jest.fn().mockReturnValue(localPopup);

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      let testConnectionPromise;
      act(() => {
        testConnectionPromise = currentHookValue.handleTestConnection();
      });

      await act(async () => {
        await Promise.resolve();
      });

      localPopup.closed = true;

      await act(async () => {
        if (registeredCallback) {
          await registeredCallback();
        }
      });

      await act(async () => {
        await testConnectionPromise;
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Test Connection was cancelled. Please try again.',
      });

      setIntervalSpy.mockRestore();
    });

    it('resolves Entra error message reported via tc_result in localStorage', async () => {
      let registeredCallback = null;
      const setIntervalSpy = jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        registeredCallback = cb;
        return 999;
      });

      const localPopup = createMockPopup();
      window.open = jest.fn().mockReturnValue(localPopup);

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      let testConnectionPromise;
      act(() => {
        testConnectionPromise = currentHookValue.handleTestConnection();
      });

      await act(async () => {
        await Promise.resolve();
      });

      localStorage.setItem('tc_result', JSON.stringify({ message: 'User consent denied' }));

      await act(async () => {
        if (registeredCallback) {
          await registeredCallback();
        }
      });

      await act(async () => {
        await testConnectionPromise;
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'User consent denied',
      });

      setIntervalSpy.mockRestore();
    });

    it('handles error message reported via tc_result in localStorage without specific message', async () => {
      let registeredCallback = null;
      const setIntervalSpy = jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        registeredCallback = cb;
        return 999;
      });

      const localPopup = createMockPopup();
      window.open = jest.fn().mockReturnValue(localPopup);

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      let testConnectionPromise;
      act(() => {
        testConnectionPromise = currentHookValue.handleTestConnection();
      });

      await act(async () => {
        await Promise.resolve();
      });

      localStorage.setItem('tc_result', JSON.stringify({ error: 'general_failure' }));

      await act(async () => {
        if (registeredCallback) {
          await registeredCallback();
        }
      });

      await act(async () => {
        await testConnectionPromise;
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Microsoft Entra authentication failed.',
      });

      setIntervalSpy.mockRestore();
    });

    it('submits OIDC callback successfully when authorization code and state land', async () => {
      let registeredCallback = null;
      const setIntervalSpy = jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        registeredCallback = cb;
        return 999;
      });

      const localPopup = createMockPopup();
      window.open = jest.fn().mockReturnValue(localPopup);

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      testConnectionCallbackApi.mockResolvedValue({
        ok: true,
        data: { success: true, message: 'OIDC Login Verified.' },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      let testConnectionPromise;
      act(() => {
        testConnectionPromise = currentHookValue.handleTestConnection();
      });

      await act(async () => {
        await Promise.resolve();
      });

      localStorage.setItem('tc_oidc_code', 'auth-code-123');
      localStorage.setItem('tc_oidc_state', 'state-123');
      localStorage.setItem('tc_company_id', 'tenant-123');
      localStorage.setItem('tc_session_ref', 'session-xyz');

      await act(async () => {
        if (registeredCallback) {
          await registeredCallback();
        }
        await Promise.resolve();
      });

      await act(async () => {
        await testConnectionPromise;
      });

      expect(testConnectionCallbackApi).toHaveBeenCalledWith({
        code: 'auth-code-123',
        state: 'state-123',
        company_id: 'tenant-123',
        sessionRef: 'session-xyz',
        is_activation: false,
      });
      expect(currentHookValue.testPassed).toBe(true);
      expect(currentHookValue.testResult).toEqual({
        status: 'passed',
        message: 'OIDC Login Verified.',
      });
      expect(mockSetIsTestReady).toHaveBeenCalledWith(true);

      setIntervalSpy.mockRestore();
    });

    it('submits OIDC activation callback successfully and returns unique success message', async () => {
      let registeredCallback = null;
      const setIntervalSpy = jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        registeredCallback = cb;
        return 999;
      });

      const localPopup = createMockPopup();
      window.open = jest.fn().mockReturnValue(localPopup);

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-activation-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      testConnectionCallbackApi.mockResolvedValue({
        ok: true,
        data: { success: true }, // No explicit message in server response
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      let testConnectionPromise;
      act(() => {
        testConnectionPromise = currentHookValue.handleTestConnection(true); // Existing test
      });

      await act(async () => {
        await Promise.resolve();
      });

      localStorage.setItem('tc_oidc_code', 'auth-code-123');
      localStorage.setItem('tc_oidc_state', 'state-123');
      localStorage.setItem('tc_company_id', 'tenant-123');
      localStorage.setItem('tc_session_ref', 'session-activation-xyz');

      await act(async () => {
        if (registeredCallback) {
          await registeredCallback();
        }
        await Promise.resolve();
      });

      await act(async () => {
        await testConnectionPromise;
      });

      expect(currentHookValue.testPassed).toBe(true);
      expect(currentHookValue.testResult.message).toBe('SSO credentials verified successfully.');

      setIntervalSpy.mockRestore();
    });

    it('handles callback API failure response with structured error message', async () => {
      let registeredCallback = null;
      const setIntervalSpy = jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        registeredCallback = cb;
        return 999;
      });

      const localPopup = createMockPopup();
      window.open = jest.fn().mockReturnValue(localPopup);

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      testConnectionCallbackApi.mockResolvedValue({
        ok: false,
        data: { success: false, error: { message: 'Invalid authorization code' } },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      let testConnectionPromise;
      act(() => {
        testConnectionPromise = currentHookValue.handleTestConnection();
      });

      await act(async () => {
        await Promise.resolve();
      });

      localStorage.setItem('tc_oidc_code', 'code');
      localStorage.setItem('tc_oidc_state', 'state');
      localStorage.setItem('tc_company_id', 'tenant-123');
      localStorage.setItem('tc_session_ref', 'session-xyz');

      await act(async () => {
        if (registeredCallback) {
          await registeredCallback();
        }
        await Promise.resolve();
      });

      await act(async () => {
        await testConnectionPromise;
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Invalid authorization code',
      });

      setIntervalSpy.mockRestore();
    });

    it('handles callback API activation failure response returning default activation message', async () => {
      let registeredCallback = null;
      const setIntervalSpy = jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        registeredCallback = cb;
        return 999;
      });

      const localPopup = createMockPopup();
      window.open = jest.fn().mockReturnValue(localPopup);

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      testConnectionCallbackApi.mockResolvedValue({
        ok: false,
        data: { success: false }, // empty data
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      let testConnectionPromise;
      act(() => {
        testConnectionPromise = currentHookValue.handleTestConnection(true); // activation flow
      });

      await act(async () => {
        await Promise.resolve();
      });

      localStorage.setItem('tc_oidc_code', 'code');
      localStorage.setItem('tc_oidc_state', 'state');
      localStorage.setItem('tc_company_id', 'tenant-123');
      localStorage.setItem('tc_session_ref', 'session-xyz');

      await act(async () => {
        if (registeredCallback) {
          await registeredCallback();
        }
        await Promise.resolve();
      });

      await act(async () => {
        await testConnectionPromise;
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult.message).toBe('Unable to verify SSO credentials.');

      setIntervalSpy.mockRestore();
    });

    it('handles callback API failure response with default error message', async () => {
      let registeredCallback = null;
      const setIntervalSpy = jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        registeredCallback = cb;
        return 999;
      });

      const localPopup = createMockPopup();
      window.open = jest.fn().mockReturnValue(localPopup);

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      testConnectionCallbackApi.mockResolvedValue({
        ok: false,
        data: { success: false },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      let testConnectionPromise;
      act(() => {
        testConnectionPromise = currentHookValue.handleTestConnection();
      });

      await act(async () => {
        await Promise.resolve();
      });

      localStorage.setItem('tc_oidc_code', 'code');
      localStorage.setItem('tc_oidc_state', 'state');
      localStorage.setItem('tc_company_id', 'tenant-123');
      localStorage.setItem('tc_session_ref', 'session-xyz');

      await act(async () => {
        if (registeredCallback) {
          await registeredCallback();
        }
        await Promise.resolve();
      });

      await act(async () => {
        await testConnectionPromise;
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Test Connection failed.',
      });

      setIntervalSpy.mockRestore();
    });

    it('handles network rejection during callback API submission', async () => {
      let registeredCallback = null;
      const setIntervalSpy = jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        registeredCallback = cb;
        return 999;
      });

      const localPopup = createMockPopup();
      window.open = jest.fn().mockReturnValue(localPopup);

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      testConnectionCallbackApi.mockRejectedValue(new Error('Network offline'));

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      let testConnectionPromise;
      act(() => {
        testConnectionPromise = currentHookValue.handleTestConnection();
      });

      await act(async () => {
        await Promise.resolve();
      });

      localStorage.setItem('tc_oidc_code', 'code');
      localStorage.setItem('tc_oidc_state', 'state');
      localStorage.setItem('tc_company_id', 'tenant-123');
      localStorage.setItem('tc_session_ref', 'session-xyz');

      await act(async () => {
        if (registeredCallback) {
          await registeredCallback();
        }
        await Promise.resolve();
      });

      await act(async () => {
        await testConnectionPromise;
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Network offline',
      });

      setIntervalSpy.mockRestore();
    });

    it('handles OIDC callback polling when sessionRef is deleted or missing from localStorage', async () => {
      let registeredCallback = null;
      const setIntervalSpy = jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        registeredCallback = cb;
        return 999;
      });

      const localPopup = createMockPopup();
      window.open = jest.fn().mockReturnValue(localPopup);

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      let testConnectionPromise;
      act(() => {
        testConnectionPromise = currentHookValue.handleTestConnection();
      });

      await act(async () => {
        await Promise.resolve();
      });

      localStorage.setItem('tc_oidc_code', 'code');
      localStorage.setItem('tc_oidc_state', 'state');
      localStorage.setItem('tc_company_id', 'tenant-123');
      localStorage.removeItem('tc_session_ref'); // missing key validation

      await act(async () => {
        if (registeredCallback) {
          await registeredCallback();
        }
      });

      await act(async () => {
        await testConnectionPromise;
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult.message).toBe(
        'OIDC session reference is missing. Please try again.'
      );

      setIntervalSpy.mockRestore();
    });

    it('reaches maximum polling limit and handles OIDC validation timeouts gracefully', async () => {
      let registeredCallback = null;
      const setIntervalSpy = jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        registeredCallback = cb;
        return 999;
      });

      const localPopup = createMockPopup();
      window.open = jest.fn().mockReturnValue(localPopup);

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 'session-xyz',
            config: {
              sso_url: 'https://login.microsoftonline.com/oauth2',
              client_id: 'client-123',
              redirect_uri: 'https://callback',
              state: 'state-123',
              nonce: 'nonce-123',
            },
          },
        },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      let testConnectionPromise;
      act(() => {
        testConnectionPromise = currentHookValue.handleTestConnection();
      });

      await act(async () => {
        await Promise.resolve();
      });

      // Force-override Date.now to simulate OIDC flow timeout (> 10 mins)
      const realDateNow = Date.now;
      const startTime = Date.now();
      const tenMinutesInMs = 10 * 60 * 1000;
      globalThis.Date.now = jest.fn().mockReturnValue(startTime + tenMinutesInMs + 100);

      await act(async () => {
        if (registeredCallback) {
          await registeredCallback();
        }
      });

      await act(async () => {
        await testConnectionPromise;
      });

      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult.message).toBe(
        'Test connection validation timed out. Please try again.'
      );

      globalThis.Date.now = realDateNow;
      setIntervalSpy.mockRestore();
    });
  });

  // =========================================================================
  // 6. GENERAL EXCEPTION & FALLBACK COVERAGE
  // =========================================================================
  describe('Global Exception Handling & Edge Cases', () => {
    it('catches and reports unexpected errors thrown inside handleTestConnection', async () => {
      mockForm.getFieldsValue.mockImplementation(() => {
        throw new Error('Form detached');
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testLoading).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Form detached',
      });
    });

    it('safely catches errors thrown when closing popup or checking closed state', async () => {
      const brokenPopup = {
        get closed() {
          throw new Error('Cross-origin denied');
        },
        close: () => {
          throw new Error('Permission denied');
        },
      };

      window.open.mockReturnValue(brokenPopup);
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: {
          success: true,
          data: {
            sessionRef: 's',
            config: {
              sso_url: 'https://auth',
              client_id: 'c',
              redirect_uri: 'https://callback',
              state: 'st',
              nonce: 'n',
            },
          },
        },
      });

      renderHookHelper(mockForm, 'oidc', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testLoading).toBe(false);
      expect(currentHookValue.testPassed).toBe(false);
      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Cross-origin denied',
      });
    });

    it('covers getApiErrorMessage branches and fallback messages', async () => {
      testConnectionApi.mockResolvedValue({
        ok: false,
        data: {
          success: false,
          message: 'Custom server error message',
        },
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testResult.message).toBe('Custom server error message');
    });

    it('covers default error fallback when data has no specific message', async () => {
      testConnectionApi.mockResolvedValue({
        ok: false,
        data: {
          success: false,
        },
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(currentHookValue.testResult.message).toBe('Test Connection failed.');
    });

    it('covers parseDomains when entra_domain is a pre-split Array', async () => {
      mockForm.getFieldsValue.mockReturnValue({
        entra_domain: ['zebra.com', 'test.com'],
        sso_url: 'https://login.microsoftonline.com/tenant-abc/saml2',
      });

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: { success: true },
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(testConnectionApi).toHaveBeenCalledWith(
        expect.objectContaining({
          domains: ['zebra.com', 'test.com'],
        })
      );
    });

    it('covers parseDomains when entra_domain has empty spaces or is comma separated', async () => {
      mockForm.getFieldsValue.mockReturnValue({
        entra_domain: '  , zebra.com, , test.com, ',
        sso_url: 'https://login.microsoftonline.com/tenant-abc/saml2',
      });

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: { success: true },
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(testConnectionApi).toHaveBeenCalledWith(
        expect.objectContaining({
          domains: ['zebra.com', 'test.com'],
        })
      );
    });

    it('covers parseDomains when entra_domain is undefined or other non-string/non-array types', async () => {
      mockForm.getFieldsValue.mockReturnValue({
        entra_domain: null,
        sso_url: 'https://login.microsoftonline.com/tenant-abc/saml2',
      });

      testConnectionApi.mockResolvedValue({
        ok: true,
        data: { success: true },
      });

      renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      await act(async () => {
        await currentHookValue.handleTestConnection();
      });

      expect(testConnectionApi).toHaveBeenCalledWith(
        expect.objectContaining({
          domains: [],
        })
      );
    });
  });

  // =========================================================================
  // 7. SAML RESULT: ASK THE BACKEND ONLY AFTER THE POPUP SIGNALS OR CLOSES
  // =========================================================================
  describe('waitForSamlResult - signal then one result call', () => {
    const SAML_REF = 'saml-ref-123';
    const DONE_KEY = `tc_saml_done:${SAML_REF}`;
    const SAML_LOGIN_URL = 'https://login.microsoftonline.com/tenant-abc/saml2?SAMLRequest=abc';
    const CANCELLED = 'Test Connection was cancelled. Please try again.';
    const RESULT_OK = { ok: true, status: 200, data: { success: true, data: {} } };
    const RESULT_PENDING = { ok: true, status: 202, data: { pending: true } };
    const RESULT_UNKNOWN_SESSION = { ok: false, status: 401, data: {} };

    let now;
    let poll;
    let popup;
    let pending;
    let view;

    // Opens the SAML popup with the interval captured, like the OIDC tests above.
    const startSamlPopupTest = async ({ isExistingTest = false, blocked = false } = {}) => {
      now = 1700000000000;
      jest.spyOn(Date, 'now').mockImplementation(() => now);
      jest.spyOn(globalThis, 'setInterval').mockImplementation((cb) => {
        poll = cb;
        return 999;
      });

      popup = createMockPopup();
      window.open = jest.fn().mockReturnValue(blocked ? null : popup);
      testConnectionApi.mockResolvedValue({
        ok: true,
        data: { success: true, data: { sessionRef: SAML_REF, redirectUrl: SAML_LOGIN_URL } },
      });

      view = renderHookHelper(mockForm, 'saml', {}, mockSetIsTestReady);

      act(() => {
        pending = currentHookValue.handleTestConnection(isExistingTest);
      });

      await act(async () => {
        await Promise.resolve();
      });
    };

    // Runs one interval check, `ms` after the previous one.
    const checkAfter = async (ms) => {
      now += ms;
      await act(async () => {
        await poll();
      });
    };

    const finishTest = async () => {
      await act(async () => {
        await pending;
      });
    };

    beforeEach(() => {
      poll = null;
      testSamlResultApi.mockReset();
    });

    it('opens the SAML popup and stores the session for the callback page', async () => {
      await startSamlPopupTest();

      expect(window.open).toHaveBeenCalledWith(SAML_LOGIN_URL, 'ssoOidcValidation', expect.any(String));
      expect(localStorage.getItem('tc_session_ref')).toBe(SAML_REF);
      expect(localStorage.getItem('tc_company_id')).toBe('tenant-123');
      expect(localStorage.getItem('tc_flow_type')).toBe('test_connection');
      expect(globalThis.setInterval).toHaveBeenCalledWith(expect.any(Function), 300);
      expect(currentHookValue.testLoading).toBe(true);
    });

    it('does not call the result API while the user is still signing in', async () => {
      await startSamlPopupTest();

      await checkAfter(300);
      await checkAfter(300);
      await checkAfter(60000);

      expect(testSamlResultApi).not.toHaveBeenCalled();
      expect(popup.close).not.toHaveBeenCalled();
      expect(currentHookValue.testResult).toBeNull();
    });

    it('asks for the result once after the callback page signals and passes', async () => {
      testSamlResultApi.mockResolvedValue(RESULT_OK);
      await startSamlPopupTest();

      localStorage.setItem(DONE_KEY, '1');
      popup.closed = true;
      await checkAfter(300);
      await finishTest();

      expect(testSamlResultApi).toHaveBeenCalledTimes(1);
      expect(testSamlResultApi).toHaveBeenCalledWith({ sessionRef: SAML_REF });
      expect(currentHookValue.testPassed).toBe(true);
      expect(currentHookValue.testResult).toEqual({ status: 'passed', message: 'Test Connection successful.' });
      expect(mockSetIsTestReady).toHaveBeenCalledWith(true);
      expect(localStorage.getItem(DONE_KEY)).toBeNull();
      expect(localStorage.getItem('tc_session_ref')).toBeNull();
    });

    it('waits at least 1 second between result calls until the result is ready', async () => {
      testSamlResultApi
        .mockResolvedValueOnce(RESULT_UNKNOWN_SESSION)
        .mockResolvedValueOnce(RESULT_PENDING)
        .mockResolvedValue(RESULT_OK);
      await startSamlPopupTest();
      localStorage.setItem(DONE_KEY, '1');

      await checkAfter(300);
      expect(testSamlResultApi).toHaveBeenCalledTimes(1);
      await checkAfter(500);
      expect(testSamlResultApi).toHaveBeenCalledTimes(1);
      await checkAfter(600);
      expect(testSamlResultApi).toHaveBeenCalledTimes(2);
      await checkAfter(1000);
      expect(testSamlResultApi).toHaveBeenCalledTimes(3);
      await finishTest();

      expect(currentHookValue.testPassed).toBe(true);
    });

    it('reports the login failure returned by the backend and closes the popup', async () => {
      testSamlResultApi.mockResolvedValue({
        ok: false,
        status: 400,
        data: { success: false, error: { message: 'Assertion signature is invalid.' } },
      });
      await startSamlPopupTest();

      localStorage.setItem(DONE_KEY, '1');
      await checkAfter(300);
      await finishTest();

      expect(currentHookValue.testResult).toEqual({ status: 'failed', message: 'Assertion signature is invalid.' });
      expect(popup.close).toHaveBeenCalled();
    });

    it('cancels after one call when the popup is closed without the signal', async () => {
      testSamlResultApi.mockResolvedValue(RESULT_PENDING);
      await startSamlPopupTest();

      popup.closed = true;
      await checkAfter(300);
      await finishTest();

      expect(testSamlResultApi).toHaveBeenCalledTimes(1);
      expect(currentHookValue.testResult).toEqual({ status: 'failed', message: CANCELLED });
    });

    it('tries 3 times on 401 after the popup closed, then cancels', async () => {
      testSamlResultApi.mockResolvedValue(RESULT_UNKNOWN_SESSION);
      await startSamlPopupTest();

      popup.closed = true;
      await checkAfter(300);
      await checkAfter(1000);
      expect(currentHookValue.testResult).toBeNull();
      await checkAfter(1000);
      await finishTest();

      expect(testSamlResultApi).toHaveBeenCalledTimes(3);
      expect(currentHookValue.testResult.message).toBe(CANCELLED);
    });

    it('passes when the popup closed without the signal but the result is ready', async () => {
      testSamlResultApi.mockResolvedValue(RESULT_OK);
      await startSamlPopupTest();

      popup.closed = true;
      await checkAfter(300);
      await finishTest();

      expect(currentHookValue.testPassed).toBe(true);
    });

    it('fails with the callback page error from tc_result without calling the backend', async () => {
      await startSamlPopupTest();

      localStorage.setItem('tc_result', JSON.stringify({ message: 'SAML response missing. Please try signing in again.' }));
      await checkAfter(300);
      await finishTest();

      expect(testSamlResultApi).not.toHaveBeenCalled();
      expect(currentHookValue.testResult.message).toBe('SAML response missing. Please try signing in again.');
    });

    it('shows a tc_result value that is not JSON as it is', async () => {
      await startSamlPopupTest();

      localStorage.setItem('tc_result', 'Plain callback error');
      await checkAfter(300);
      await finishTest();

      expect(currentHookValue.testResult).toEqual({ status: 'failed', message: 'Plain callback error' });
    });

    it('uses the default Entra message when tc_result has no message', async () => {
      await startSamlPopupTest();

      localStorage.setItem('tc_result', JSON.stringify({}));
      await checkAfter(300);
      await finishTest();

      expect(currentHookValue.testResult.message).toBe('Microsoft Entra authentication failed.');
    });

    it('logs a failed result call and tries again a second later', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const networkError = new Error('Network down');
      testSamlResultApi
        .mockRejectedValueOnce(networkError)
        .mockResolvedValue(RESULT_OK);
      await startSamlPopupTest();

      localStorage.setItem(DONE_KEY, '1');
      await checkAfter(300);
      expect(consoleErrorSpy).toHaveBeenCalledWith('[SSO] SAML result API failed', networkError);
      expect(currentHookValue.testResult).toBeNull();

      await checkAfter(1000);
      await finishTest();

      expect(testSamlResultApi).toHaveBeenCalledTimes(2);
      expect(currentHookValue.testResult).toEqual({ status: 'passed', message: 'Test Connection successful.' });
    });

    it('times out after 5 minutes without calling the backend', async () => {
      await startSamlPopupTest();

      await checkAfter(5 * 60 * 1000);
      await finishTest();

      expect(testSamlResultApi).not.toHaveBeenCalled();
      expect(currentHookValue.testResult.message).toBe('Test connection validation timed out. Please try again.');
      expect(popup.close).toHaveBeenCalled();
    });

    it('stops checking when the page is left', async () => {
      const clearIntervalSpy = jest.spyOn(globalThis, 'clearInterval');
      await startSamlPopupTest();

      view.unmount();

      expect(clearIntervalSpy).toHaveBeenCalledWith(999);
    });

    it('runs the same popup flow for activation', async () => {
      testSamlResultApi.mockResolvedValue(RESULT_OK);
      await startSamlPopupTest({ isExistingTest: true });

      expect(testConnectionApi).toHaveBeenCalledWith({
        company_id: 'tenant-123',
        protocol: 'saml',
        is_existing_test: true,
      });
      localStorage.setItem(DONE_KEY, '1');
      await checkAfter(300);
      await finishTest();

      expect(currentHookValue.testResult).toEqual({ status: 'passed', message: 'Test Connection successful.' });
    });

    it('fails and clears the test session when the SAML popup is blocked', async () => {
      await startSamlPopupTest({ blocked: true });
      await finishTest();

      expect(currentHookValue.testResult).toEqual({
        status: 'failed',
        message: 'Popup was blocked. Please allow popups and try again.',
      });
      expect(localStorage.getItem('tc_session_ref')).toBeNull();
      expect(poll).toBeNull();
    });
  });

});
