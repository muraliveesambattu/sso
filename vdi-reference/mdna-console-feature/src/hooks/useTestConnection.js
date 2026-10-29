import { useState, useContext, useEffect, useRef } from 'react';
import {
  AUTH_METHOD_MAP,
  SAML_ACS_URL,
  SAML_ENTITY_ID,
  REDIRECT_URI,
} from '../constants/SsoConstants';
import { testConnectionApi, testConnectionCallbackApi, testSamlResultApi } from '../services/ssoApi';
import { getTenantId } from 'auth/FirebaseAuth';
import { AuthContext } from 'auth/AuthProvider';

export const readFileAsBase64 = (file) =>
  new Promise((resolve, reject) => {

    if (!file || typeof file === 'string') {
      resolve(undefined);
      return;
    }

    const reader = new FileReader();

    reader.onload = () => {
      const result =
        typeof reader.result === 'string'
          ? reader.result
          : '';

      resolve(result.split(',')[1] ?? '');
    };

    reader.onerror = () =>
      reject(new Error('Failed to read file'));

    reader.readAsDataURL(file);
  });

const parseDomains = (val) => {
  if (typeof val === 'string') return val.split(',').map((d) => d.trim()).filter(Boolean);
  if (Array.isArray(val)) return val;
  return [];
};

export const useTestConnection = (form, protocol, fileValues, setIsTestReady) => {
  const [testLoading, setTestLoading] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [testPassed, setTestPassed] = useState(false);
  const context = useContext(AuthContext);
  const tenantId = getTenantId(context?.currentUser);
  const popupCheckRef = useRef(null);
  const popupTimeoutRef = useRef(null);

  useEffect(() => {
    return () => {
      if (popupCheckRef.current) {
        clearInterval(popupCheckRef.current);
        popupCheckRef.current = null;
      }
      if (popupTimeoutRef.current) {
        clearTimeout(popupTimeoutRef.current);
        popupTimeoutRef.current = null;
      }
    };
  }, []);

  const OIDC_POPUP_TIMEOUT_MS = 10 * 60 * 1000;
  const OIDC_POLL_INTERVAL_MS = 500;
  const SAML_TEST_TIMEOUT_MS = 5 * 60 * 1000;
  const SAML_POLL_INTERVAL_MS = 2000;

  const TEST_CONNECTION_STORAGE_KEYS = [
    'tc_company_id',
    'tc_session_ref',
    'tc_result',
    'tc_oidc_code',
    'tc_oidc_state',
    'tc_flow_type',
    'oidc_company_id',
  ];

  /**
   * Remove all temporary OIDC test/activation values.
   */
  const clearTestConnectionStorage = () => {
    TEST_CONNECTION_STORAGE_KEYS.forEach((key) => {
      localStorage.removeItem(key);
    });
  };

  /**
   * Stop the active popup polling interval.
   */
  const clearPopupPolling = () => {
    if (popupCheckRef.current) {
      clearInterval(popupCheckRef.current);
      popupCheckRef.current = null;
    }
  };

  /**
   * Safely close the Entra login popup.
   */
  const closePopupSafely = (popup) => {
    try {
      if (popup && !popup.closed) {
        popup.close();
      }
    } catch (error) {
      console.debug('[SSO] Unable to close popup', error);
    }
  };

  /**
   * Extract an error message returned by the backend.
   */
  const getApiErrorMessage = (
    data,
    fallbackMessage = 'Test connection validation failed.',
  ) => {
    if (data?.error?.message) {
      return data.error.message;
    }

    if (data?.message) {
      return data.message;
    }

    if (Array.isArray(data?.errors) && data.errors.length > 0) {
      return data.errors.join(', ');
    }

    return fallbackMessage;
  };

  /**
   * Extract tenant ID from Microsoft SAML SSO URL.
   */
  const extractSamlTenantId = (ssoUrl) => {
    try {
      const url = new URL(ssoUrl);
      const tenantIdFromUrl = url.pathname
        .split('/')
        .find(Boolean);

      if (!tenantIdFromUrl) {
        throw new Error('Tenant ID is missing from SAML SSO URL.');
      }

      return tenantIdFromUrl;
    } catch (error) {
      console.error('[SSO] Invalid SAML SSO URL', error);
      throw new Error('Invalid SAML SSO URL.');
    }
  };

  /**
   * Build payload for:
   *
   * 1. New Test Connection
   * 2. Existing configuration validation before activation
   */
  const buildTestConnectionPayload = async ({
    isExistingTest,
    currentProtocol,
    companyId,
    values,
  }) => {
    /*
     * Existing configuration activation flow.
     *
     * Backend fetches the saved configuration from DB using company_id.
     * Do not send masked or potentially stale values from the form.
     */
    if (isExistingTest) {
      return {
        company_id: companyId,
        protocol: currentProtocol,
        is_existing_test: true,
      };
    }

    /*
     * New SAML configuration test.
     */
    if (currentProtocol === 'saml') {
      const samlCertificate =
        fileValues.saml_cert &&
          fileValues.saml_cert !== '__existing__'
          ? await readFileAsBase64(fileValues.saml_cert)
          : undefined;

      const samlSigningCert =
        fileValues.saml_signing_cert &&
          fileValues.saml_signing_cert !== '__existing__'
          ? await readFileAsBase64(fileValues.saml_signing_cert)
          : undefined;

      return {
        protocol: 'saml',
        company_id: companyId,
        domains: parseDomains(values.entra_domain),
        entity_id: SAML_ENTITY_ID,
        acs_url: SAML_ACS_URL,
        sso_url: values.sso_url?.trim(),
        certificate: samlCertificate,
        use_existing_cert: fileValues.saml_cert === '__existing__',
        tenant_id: extractSamlTenantId(values.sso_url),
        app_id: values.app_id?.trim(),
        client_secret: values.client_secret?.trim(),
        sign_authn_request: !!values.sign_auth,
        signing_certificate: samlSigningCert,
        signing_certificate_password: values.saml_signing_cert_password || undefined,
        use_existing_signing_cert: !!values.sign_auth && fileValues.saml_signing_cert === '__existing__',
        is_existing_test: false,
      };
    }


    /*
     * New OIDC configuration test.
     */
    const oidcCertificate =
      fileValues.certificate &&
        fileValues.certificate !== '__existing__'
        ? await readFileAsBase64(fileValues.certificate)
        : undefined;

    const oidcTenantId = values.tenant_id?.trim();

    return {
      protocol: 'oidc',
      company_id: companyId,
      domains: parseDomains(values.entra_domain),
      tenant_id: oidcTenantId,
      client_id: values.client_id?.trim(),
      auth_method: AUTH_METHOD_MAP[values.auth_method],
      client_secret: values.client_secret || undefined,
      certificate: oidcCertificate,
      use_existing_cert:
        fileValues.certificate === '__existing__',
      certificate_password:
        values.certificate_password || undefined,
      sso_url:
        `https://login.microsoftonline.com/` +
        `${oidcTenantId}/oauth2/v2.0/authorize`,
      redirect_uri: REDIRECT_URI,
      scope: 'openid profile email',
      is_existing_test: false,
    };
  };

  /**
   * Build Microsoft Entra authorization URL.
   */
  const buildOidcAuthorizeUrl = (config) => {
    const {
      sso_url: ssoUrl,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope,
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
    } = config;

    if (!ssoUrl) {
      throw new Error(
        'OIDC authorization URL is missing from server response.',
      );
    }

    if (!clientId) {
      throw new Error(
        'OIDC client ID is missing from server response.',
      );
    }

    if (!redirectUri) {
      throw new Error(
        'OIDC redirect URI is missing from server response.',
      );
    }

    if (!state) {
      throw new Error(
        'OIDC state is missing from server response.',
      );
    }

    if (!nonce) {
      throw new Error(
        'OIDC nonce is missing from server response.',
      );
    }

    const authorizeParams = new URLSearchParams({
      client_id: clientId,
      response_type: 'code',
      redirect_uri: redirectUri,
      scope: scope || 'openid profile email',
      state,
      nonce,
      prompt: 'login',
    });

    /*
     * Add PKCE parameters only when generated by backend.
     */
    if (codeChallenge) {
      authorizeParams.set(
        'code_challenge',
        codeChallenge,
      );

      authorizeParams.set(
        'code_challenge_method',
        codeChallengeMethod || 'S256',
      );
    }

    const separator = ssoUrl.includes('?') ? '&' : '?';

    return `${ssoUrl}${separator}${authorizeParams.toString()}`;
  };

  /**
   * Open Microsoft Entra login popup.
   */
  const openOidcPopup = (authorizeUrl) =>
    window.open(
      authorizeUrl,
      'ssoOidcValidation',
      'width=500,height=600,left=200,top=100',
    );

  /**
   * Wait for Microsoft Entra redirect page to place the
   * authorization code and state in localStorage.
   *
   * This Promise resolves only after:
   *
   * 1. Callback succeeds
   * 2. Callback fails
   * 3. Entra returns an error
   * 4. Popup is closed
   * 5. Flow times out
   */
  const waitForOidcCallback = ({
    popup,
    isExistingTest,
  }) =>
    new Promise((resolve) => {
      const startedAt = Date.now();

      let completed = false;
      let callbackInProgress = false;

      const finish = ({
        success,
        message,
        claims,
      }) => {
        if (completed) {
          return;
        }

        completed = true;

        clearPopupPolling();
        closePopupSafely(popup);
        clearTestConnectionStorage();

        resolve({
          success,
          message,
          claims,
        });
      };

      const submitOidcCallback = async ({
        code,
        state,
      }) => {
        const companyId =
          localStorage.getItem('tc_company_id');

        const sessionRef =
          localStorage.getItem('tc_session_ref');

        if (!sessionRef) {
          finish({
            success: false,
            message:
              'OIDC session reference is missing. Please try again.',
          });

          return;
        }

        try {
          console.log('[SSO] Submitting OIDC callback', {
            companyId,
            sessionRef,
            isExistingTest,
          });

          const {
            ok,
            data,
          } = await testConnectionCallbackApi({
            code,
            state,
            company_id: companyId,
            sessionRef,
            is_activation: isExistingTest,
          });

          if (!ok || !data?.success) {
            finish({
              success: false,
              message: getApiErrorMessage(
                data,
                isExistingTest
                  ? 'Unable to verify SSO credentials.'
                  : 'Test Connection failed.',
              ),
            });

            return;
          }

          finish({
            success: true,
            message:
              data.message ||
              (isExistingTest
                ? 'SSO credentials verified successfully.'
                : 'Test Connection successful.'),
            claims: data.data?.claims,
          });
        } catch (error) {
          console.error(
            '[SSO] OIDC callback API failed',
            error,
          );

          finish({
            success: false,
            message:
              error.message ||
              'Network error during OIDC validation.',
          });
        }
      };

      const pollPopup = async () => {
        if (completed || callbackInProgress) {
          return;
        }

        /*
         * Stop the flow when maximum time is reached.
         */
        const isTimedOut =
          Date.now() - startedAt >=
          OIDC_POPUP_TIMEOUT_MS;

        if (isTimedOut) {
          finish({
            success: false,
            message:
              'Test connection validation timed out. Please try again.',
          });

          return;
        }

        /*
         * Check whether redirect page reported an Entra error.
         */
        const storedResult =
          localStorage.getItem('tc_result');

        if (storedResult) {
          let parsedResult;

          try {
            parsedResult = JSON.parse(storedResult);
          } catch {
            parsedResult = {
              message: storedResult,
            };
          }

          finish({
            success: false,
            message:
              parsedResult?.message ||
              'Microsoft Entra authentication failed.',
          });

          return;
        }

        /*
         * Check whether the callback page stored code and state.
         */
        const authorizationCode =
          localStorage.getItem('tc_oidc_code');

        const returnedState =
          localStorage.getItem('tc_oidc_state');

        if (authorizationCode && returnedState) {
          callbackInProgress = true;

          /*
           * Remove code and state before calling callback API.
           * This prevents the polling interval from processing the
           * same authorization code more than once.
           */
          localStorage.removeItem('tc_oidc_code');
          localStorage.removeItem('tc_oidc_state');

          await submitOidcCallback({
            code: authorizationCode,
            state: returnedState,
          });

          callbackInProgress = false;
          return;
        }

        /*
         * Detect manual popup closure.
         */
        try {
          if (popup.closed) {
            finish({
              success: false,
              message:
                'Test Connection was cancelled. Please try again.',
            });
          }
        } catch (error) {
          console.debug(
            '[SSO] Unable to check popup status',
            error,
          );
        }
      };

      popupCheckRef.current = setInterval(
        pollPopup,
        OIDC_POLL_INTERVAL_MS,
      );
    });

  /**
   * Wait for the SAML test login to finish.
   *
   * Entra's login page sends Cross-Origin-Opener-Policy, so popup.closed
   * reads true while the user is still signing in. Instead of watching the
   * popup, ask the backend: it answers 202 (pending) until the ACS callback
   * has run.
   */
  const waitForSamlResult = ({
    popup,
    sessionRef,
  }) =>
    new Promise((resolve) => {
      const startedAt = Date.now();

      let completed = false;
      let requestInProgress = false;

      const finish = ({
        success,
        message,
        claims,
      }) => {
        if (completed) {
          return;
        }

        completed = true;

        clearPopupPolling();
        closePopupSafely(popup);
        clearTestConnectionStorage();

        resolve({
          success,
          message,
          claims,
        });
      };

      const pollSamlResult = async () => {
        if (completed || requestInProgress) {
          return;
        }

        if (Date.now() - startedAt >= SAML_TEST_TIMEOUT_MS) {
          finish({
            success: false,
            message:
              'Test connection validation timed out. Please try again.',
          });

          return;
        }

        /*
         * The callback page reported an error (e.g. MISSING_SAML_RESPONSE).
         */
        const storedResult =
          localStorage.getItem('tc_result');

        if (storedResult) {
          let parsedResult;

          try {
            parsedResult = JSON.parse(storedResult);
          } catch {
            parsedResult = {
              message: storedResult,
            };
          }

          finish({
            success: false,
            message:
              parsedResult?.message ||
              'Microsoft Entra authentication failed.',
          });

          return;
        }

        requestInProgress = true;

        try {
          const {
            ok,
            status,
            data,
          } = await testSamlResultApi({ sessionRef });

          if (status === 202 || data?.pending) {
            return;
          }

          if (!ok || !data?.success) {
            finish({
              success: false,
              message: getApiErrorMessage(
                data,
                'Test Connection failed.',
              ),
            });

            return;
          }

          finish({
            success: true,
            message: 'Test Connection successful.',
            claims: data.data?.claims,
          });
        } catch (error) {
          console.error(
            '[SSO] SAML result API failed',
            error,
          );

          finish({
            success: false,
            message:
              error.message ||
              'Network error during SAML validation.',
          });
        } finally {
          requestInProgress = false;
        }
      };

      popupCheckRef.current = setInterval(
        pollSamlResult,
        SAML_POLL_INTERVAL_MS,
      );
    });

  /**
   * Test Connection and activation validation handler.
   *
   * Usage:
   *
   * handleTestConnection(false)
   *   New configuration validation using form values.
   *
   * handleTestConnection(true)
   *   Existing configuration validation before activation.
   *   Backend fetches the saved configuration from DB.
   */
  const handleTestConnection = async (
    isExistingTest = false,
  ) => {
    console.log('[SSO] Starting validation', {
      companyId: tenantId,
      protocol,
      isExistingTest,
    });

    setTestLoading(true);
    setTestResult(null);
    setTestPassed(false);

    /*
     * Stop any previously running popup interval.
     */
    clearPopupPolling();

    /*
     * Remove temporary data from previous attempts.
     */
    clearTestConnectionStorage();

    /**
     * Update UI and return a consistent result.
     */
    const updateResult = ({
      success,
      message,
      claims,
    }) => {
      setTestResult({
        status: success ? 'passed' : 'failed',
        message,
        ...(claims && { claims }),
      });

      setTestPassed(success);

      if (success) {
        setIsTestReady(true);
      }

      return {
        success,
        message,
      };
    };

    try {
      const values = form.getFieldsValue();

      /*
       * Build the payload depending on whether this is:
       *
       * 1. New Test Connection
       * 2. Existing configuration activation validation
       */
      const payload =
        await buildTestConnectionPayload({
          isExistingTest,
          currentProtocol: protocol,
          companyId: tenantId,
          values,
        });

      console.log('[SSO] Calling validation API', {
        companyId: payload.company_id,
        protocol: payload.protocol,
        isExistingTest,
      });

      const {
        ok,
        data,
      } = await testConnectionApi(payload);

      /*
       * Initial backend validation failed.
       */
      if (!ok || !data?.success) {
        return updateResult({
          success: false,
          message: getApiErrorMessage(
            data,
            isExistingTest
              ? 'Unable to validate the saved SSO configuration.'
              : 'Test Connection failed.',
          ),
        });
      }

      /*
       * SAML: the initial API call validates metadata, certificate and the
       * Entra app. When the backend also returns a login session, open the
       * Entra popup and wait for the real sign-in result.
       */
      if (protocol === 'saml' && data?.success) {
        const samlSessionRef = data.data?.sessionRef;
        const samlRedirectUrl = data.data?.redirectUrl;

        if (isExistingTest || !samlSessionRef || !samlRedirectUrl) {
          return updateResult({
            success: true,
            message:
              data.message ||
              (isExistingTest
                ? 'Saved SAML configuration verified successfully.'
                : 'Test Connection successful'),
          });
        }

        localStorage.setItem(
          'tc_company_id',
          String(payload.company_id),
        );

        localStorage.setItem(
          'tc_session_ref',
          samlSessionRef,
        );

        localStorage.setItem(
          'tc_flow_type',
          'test_connection',
        );

        const samlPopup =
          openOidcPopup(samlRedirectUrl);

        if (!samlPopup || samlPopup.closed) {
          clearTestConnectionStorage();

          return updateResult({
            success: false,
            message:
              'Popup was blocked. Please allow popups and try again.',
          });
        }

        const samlResult =
          await waitForSamlResult({
            popup: samlPopup,
            sessionRef: samlSessionRef,
          });

        return updateResult(samlResult);
      }

      /*
       * OIDC requires the browser-based authorization flow.
       */
      const sessionRef =
        data.data?.sessionRef;

      const serverConfig =
        data.data?.config;

      if (!sessionRef) {
        return updateResult({
          success: false,
          message:
            'Session reference is missing. Please try again.',
        });
      }

      if (!serverConfig) {
        return updateResult({
          success: false,
          message:
            'OIDC configuration is missing from server response.',
        });
      }

      if (!serverConfig.state || !serverConfig.nonce) {
        return updateResult({
          success: false,
          message:
            'Invalid OIDC state or nonce received from server.',
        });
      }

      /*
       * Always prefer server values.
       *
       * This is important during activation because the configuration
       * is loaded by the backend from the database.
       */
      const oidcConfig = {
        ...serverConfig,

        client_id:
          serverConfig.client_id ||
          values.client_id?.trim(),

        redirect_uri:
          serverConfig.redirect_uri ||
          REDIRECT_URI,

        scope:
          serverConfig.scope ||
          'openid profile email',

        sso_url:
          serverConfig.sso_url ||
          (
            values.tenant_id
              ? `https://login.microsoftonline.com/` +
              `${values.tenant_id.trim()}/oauth2/v2.0/authorize`
              : undefined
          ),
      };

      const authorizeUrl =
        buildOidcAuthorizeUrl(oidcConfig);

      /*
       * Save the runtime session information required by the
       * redirect page and callback API.
       */
      localStorage.setItem(
        'tc_company_id',
        String(payload.company_id),
      );

      localStorage.setItem(
        'tc_session_ref',
        sessionRef,
      );

      localStorage.setItem(
        'tc_flow_type',
        isExistingTest
          ? 'activation'
          : 'test_connection',
      );

      console.log('[SSO] Opening Entra login popup', {
        sessionRef,
        flowType: isExistingTest
          ? 'activation'
          : 'test_connection',
      });

      const popup =
        openOidcPopup(authorizeUrl);

      if (!popup || popup.closed) {
        clearTestConnectionStorage();

        return updateResult({
          success: false,
          message:
            'Popup was blocked. Please allow popups and try again.',
        });
      }

      /*
       * Wait until the complete OIDC callback flow finishes.
       *
       * Without await, handleTestConnection would complete before
       * the callback and set loading to false too early.
       */
      const callbackResult =
        await waitForOidcCallback({
          popup,
          isExistingTest,
        });

      return updateResult(callbackResult);
    } catch (error) {
      console.error(
        '[SSO] Validation flow failed',
        error,
      );

      clearPopupPolling();
      clearTestConnectionStorage();

      return updateResult({
        success: false,
        message:
          error.message ||
          'Network error. Please check your connection and try again.',
      });
    } finally {
      setTestLoading(false);
    }
  };

  return {
    testLoading,
    testResult,
    testPassed,
    setTestPassed,
    setTestResult,
    handleTestConnection,
  };
};
