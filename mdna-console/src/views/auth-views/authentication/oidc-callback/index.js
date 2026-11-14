import { useEffect, useRef, useState } from 'react';
import { useHistory, useLocation } from 'react-router-dom';
import { Spin } from 'antd';
import { LoadingOutlined } from '@ant-design/icons';
import { getAuth, signInWithCustomToken } from 'firebase/auth';

const ERROR_MESSAGES = {
  INVALID_STATE: 'Authentication session expired. Please try signing in again.',
  SESSION_EXPIRED: 'Your sign-in session has expired. Please sign in again.',
  INVALID_TOKEN: 'Your session token has expired. Please sign in again.',
  INVALID_NONCE: 'Security validation failed. Please try again.',
  JWT_VERIFICATION_FAILED: 'Security validation failed. Please try again.',
  INTEGRATION_NOT_FOUND: 'SSO configuration not found for your organisation.',
  CONFIG_NOT_FOUND: 'SSO configuration not found for your organisation.',
  MISSING_CODE_VERIFIER: 'PKCE session error. Please try signing in again.',
  TOKEN_EXCHANGE_FAILED: 'Token exchange with Microsoft Entra failed. Please try again.',
  MISSING_EMAIL: 'Your account is missing a required email claim.',
  MISSING_OID: 'Your account is missing a required identifier.',
  TOKEN_REFRESH_FAILED: 'Failed to complete sign-in. Please try again.',
  FIREBASE_SIGNIN_FAILED: 'Failed to sign in to the application. Please try again.',
  MISSING_SAML_RESPONSE: 'SAML response missing. Please try signing in again.',
  MISSING_RELAY_STATE: 'SAML session error. Please try signing in again.',
  SAML_LOGIN_FAILED: 'SAML login failed. Please try again.',
  INVALID_ENCODING: 'Authentication failed. Please try again.',
  MISSING_IN_RESPONSE_TO: 'Authentication failed. Please try again.',
  SESSION_NOT_FOUND: 'Your sign-in session has expired. Please try again.',
  INVALID_XML: 'Authentication failed. Please try again.',
  MISSING_ASSERTION: 'Authentication failed. Please try again.',
  AUTHENTICATION_FAILED: 'Authentication failed. Please try again.',
  INVALID_ISSUER: 'Authentication failed. Please try again.',
  MISSING_INRESPONSET: 'Authentication failed. Please try again.',
  INVALID_INRESPONSETO: 'Authentication failed. Please try again.',
  MISSING_CONDITIONS: 'Authentication failed. Please try again.',
  ASSERTION_NOT_YET_VALID: 'Authentication failed. Please try again.',
  ASSERTION_EXPIRED: 'Your sign-in session has expired. Please try again.',
  INVALID_AUDIENCE: 'Authentication failed. Please try again.',
  MISSING_IDENTITY_CLAIMS: 'Authentication failed. Please try again.',
  NO_ROLE_ASSIGNED: 'No role is assigned to your account for this organisation. Please contact your administrator.',
  USER_NOT_PROVISIONED: 'You are not allowed to login using SSO',
  LOGIN_METHOD_NOT_ALLOWED: 'You are not allowed to login using zDNA SSO',
  USER_EXPIRED: 'Your account has expired. Please contact your administrator',
};

function resolveErrorMessage(code, fallback) {
  return ERROR_MESSAGES[code] ?? fallback ?? 'Sign-in failed. Please try again.';
}

function redirectToLogin(history, errorMessage, guardKey) {
  if (guardKey) sessionStorage.removeItem(guardKey);
  history.replace({ pathname: '/auth/login', state: { errorMessage } });
}

function handlePopupFlow({ code, state, token, error }) {
  if (error) {
    localStorage.removeItem('tc_company_id');
    localStorage.removeItem('tc_session_ref');
    localStorage.setItem('tc_result', JSON.stringify({
      type: 'TEST_CONNECTION_FAILED',
      message: resolveErrorMessage(error, 'Sign-in failed.'),
    }));
    globalThis.close();
    return;
  }
  if (token) {
    localStorage.removeItem('tc_company_id');
    localStorage.removeItem('tc_session_ref');
    localStorage.setItem('tc_result', JSON.stringify({
      type: 'TEST_CONNECTION_SUCCESS',
      message: 'Test Connection successful',
    }));
    globalThis.close();
    return;
  }
  if (code && state) {
    localStorage.setItem('tc_oidc_code', code);
    localStorage.setItem('tc_oidc_state', state);
    window.close();
    return;
  }
  window.close();
}

async function handleOidcExchange({
  code, state, auth, history,
  controller, TOKEN_EXCHANGE_TIMEOUT_MS, cancelled, guardKey,
}) {
  const MICROSERVICE_API_URL = process.env.REACT_APP_MICROSERVICE_API_URL;
  const company_id = localStorage.getItem('oidc_company_id');
  if (!company_id) {
    redirectToLogin(history, resolveErrorMessage('INVALID_STATE'), guardKey);
    return;
  }

  const exchangeTimer = setTimeout(() => controller.abort(), TOKEN_EXCHANGE_TIMEOUT_MS);
  try {
    const res = await fetch(
      `${MICROSERVICE_API_URL}auth/oidc/token-exchange`,
      {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, state, company_id }),
        signal: controller.signal,
      }
    );
    if (cancelled.current) return;
    const data = await res.json();
    clearTimeout(exchangeTimer);

    if (!res.ok) {
      const errCode = data.code ?? data.error?.code;
      const errMsg = data.error?.message || data.message;
      redirectToLogin(history, resolveErrorMessage(errCode, errMsg), guardKey);
      return;
    }

    await signInWithCustomToken(auth, data.customToken);
    localStorage.removeItem('oidc_company_id');
    globalThis.history.replaceState({}, document.title, globalThis.location.pathname);
    sessionStorage.removeItem(guardKey);
    history.replace({ pathname: '/app/home', state: {} });
  } catch (err) {
    clearTimeout(exchangeTimer);
    if (cancelled.current) return;
    if (err.name === 'AbortError') {
      redirectToLogin(history, 'Request timed out. Please try again.', guardKey);
      return;
    }
    const isFirebaseError = err?.code?.startsWith('auth/');
    redirectToLogin(
      history,
      isFirebaseError
        ? resolveErrorMessage('FIREBASE_SIGNIN_FAILED')
        : 'Network error. Please check your connection and try again.',
      guardKey
    );
  }
}

export default function OIDCCallback() {
  const history = useHistory();
  const location = useLocation();
  const [status] = useState({ type: 'loading' });
  const cancelled = useRef(false);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const guardKey = `oidc_exchange_started_${params.get('state') ?? 'default'}`;

    if (sessionStorage.getItem(guardKey)) return;
    sessionStorage.setItem(guardKey, '1');

    const auth = getAuth();
    const controller = new AbortController();
    const TOKEN_EXCHANGE_TIMEOUT_MS = 30000;

    const run = async () => {
      const code = params.get('code');
      const state = params.get('state');
      const token = params.get('token');
      const error = params.get('error');
      const urlMessage = params.get('message');
      const samlTest = params.get('saml_test') === '1';

      // SAML Test Connection popup: the backend already holds the result and
      // the parent tab fetches it, so this page only closes itself.
      if (samlTest) {
        sessionStorage.removeItem(guardKey);
        globalThis.close();
        return;
      }

      const isPopup = !!localStorage.getItem('tc_session_ref')
        && !localStorage.getItem('oidc_company_id');

      if (isPopup) {
        sessionStorage.removeItem(guardKey);
        handlePopupFlow({ code, state, token, error });
        return;
      }

      if (error) {
        redirectToLogin(
          history,
          urlMessage || resolveErrorMessage(error, 'Sign-in failed. Please try again.'),
          guardKey
        );
        return;
      }

      const MICROSERVICE_API_URL = process.env.REACT_APP_MICROSERVICE_API_URL;
      if (!MICROSERVICE_API_URL) {
        redirectToLogin(history, 'Service configuration error. Please contact support.', guardKey);
        return;
      }

      if (token) {
        try {
          await signInWithCustomToken(auth, token);
          sessionStorage.removeItem(guardKey);
          history.replace({ pathname: '/app/home', state: {} });
        } catch {
          if (cancelled.current) return;
          redirectToLogin(history, resolveErrorMessage('FIREBASE_SIGNIN_FAILED'), guardKey);
        }
        return;
      }

      if (code && state) {
        await handleOidcExchange({
          code, state, auth, history,
          controller, TOKEN_EXCHANGE_TIMEOUT_MS, cancelled, guardKey,
        });
        return;
      }

      redirectToLogin(history, 'Invalid callback. Please try signing in again.', guardKey);
    };

    run();
    return () => {
      cancelled.current = true;
      controller.abort();
    };
  }, []);

  if (status.type === 'loading') {
    return (
      <div className="container-fluid min-vh-100 d-flex align-items-center justify-content-center bg-light">
        <div className="text-center">
          <Spin indicator={<LoadingOutlined style={{ fontSize: 40 }} spin />} />
        </div>
      </div>
    );
  }

  return null;
}
