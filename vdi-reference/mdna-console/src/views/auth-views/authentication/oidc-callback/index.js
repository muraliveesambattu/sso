import { useEffect, useRef, useState } from 'react';
import { useHistory, useLocation } from 'react-router-dom';
import { message,Spin } from 'antd';
import { LoadingOutlined } from '@ant-design/icons';
import { getAuth, signInWithCustomToken } from 'firebase/auth';

const ERROR_MESSAGES = {
  INVALID_STATE:          'Authentication session expired. Please try signing in again.',
  SESSION_EXPIRED:        'Your sign-in session has expired. Please sign in again.',
  INVALID_TOKEN:          'Your session token has expired. Please sign in again.',
  INVALID_NONCE:          'Security validation failed. Please try again.',
  JWT_VERIFICATION_FAILED:'Security validation failed. Please try again.',
  INTEGRATION_NOT_FOUND:  'SSO configuration not found for your organisation.',
  CONFIG_NOT_FOUND:       'SSO configuration not found for your organisation.',
  MISSING_CODE_VERIFIER:  'PKCE session error. Please try signing in again.',
  TOKEN_EXCHANGE_FAILED:  'Token exchange with Microsoft Entra failed. Please try again.',
  MISSING_EMAIL:          'Your account is missing a required email claim.',
  MISSING_OID:            'Your account is missing a required identifier.',
  TOKEN_REFRESH_FAILED:   'Failed to complete sign-in. Please try again.',
  FIREBASE_SIGNIN_FAILED: 'Failed to sign in to the application. Please try again.',
  MISSING_SAML_RESPONSE:  'SAML response missing. Please try signing in again.',
  MISSING_RELAY_STATE:    'SAML session error. Please try signing in again.',
  SAML_LOGIN_FAILED:      'SAML login failed. Please try again.',
};

function resolveErrorMessage(code, fallback) {
  return ERROR_MESSAGES[code] ?? fallback ?? 'Sign-in failed. Please try again.';
}

// ── popup (test connection) handler ──────────────────────────────────────────
function handlePopupFlow({ code, state, token, error, samlTest }) {
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
  if (samlTest) {   // SAML Test Connection: only signal "done"; the parent fetches the result
    localStorage.setItem('tc_saml_done', '1');
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

// ── OIDC token exchange (normal login) ───────────────────────────────────────
async function handleOidcExchange({ code, state, auth, history, setStatus, controller, TOKEN_EXCHANGE_TIMEOUT_MS, cancelled }) {
  const MICROSERVICE_API_URL = process.env.REACT_APP_MICROSERVICE_API_URL;
  const company_id = localStorage.getItem('oidc_company_id');
  if (!company_id) {
    history.replace('/auth/login');
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
      const errMsg  = data.error?.message || data.message;
      setStatus({ type: 'error', message: resolveErrorMessage(errCode, errMsg) });
      errMsg && message.error(errMsg);
      return;
    }
    await signInWithCustomToken(auth, data.customToken);
    if (cancelled.current) return;
    localStorage.removeItem('oidc_company_id');
    globalThis.history.replaceState({}, document.title, globalThis.location.pathname);
    history.replace('/app/home');
  } catch (err) {
    clearTimeout(exchangeTimer);
    if (err.name === 'AbortError' || cancelled.current) return;
    const isFirebaseError = err?.code?.startsWith('auth/');
    setStatus({
      type: 'error',
      message: isFirebaseError
        ? resolveErrorMessage('FIREBASE_SIGNIN_FAILED')
        : 'Network error. Please check your connection and try again.',
    });
  }
}

export default function OIDCCallback() {
  const history = useHistory();
  const location = useLocation();
  const [status, setStatus] = useState({ type: 'loading', message: '' });
  const exchanged = useRef(false);
  const completed = useRef(false);
  const cancelled = useRef(false);
  const auth = getAuth();

  useEffect(() => {
    if (exchanged.current) return;
    exchanged.current = true;
    const controller = new AbortController();
    const TOKEN_EXCHANGE_TIMEOUT_MS = 30000;

    const run = async () => {
      const params = new URLSearchParams(location.search);
      const code  = params.get('code');
      const state = params.get('state');
      const token = params.get('token');
      const error = params.get('error');
      const samlTest = params.get('saml_test') === '1';
      if (samlTest) {   // SAML Test Connection popup: the parent tab polls the backend for the result
        localStorage.setItem('tc_saml_done', '1');
        globalThis.close();
        return;
      }

      const isPopup = !!localStorage.getItem('tc_session_ref')
        && !localStorage.getItem('oidc_company_id');

      if (isPopup) {
        handlePopupFlow({ code, state, token, error, samlTest });
        return;
      }

      const MICROSERVICE_API_URL = process.env.REACT_APP_MICROSERVICE_API_URL;
      if (!MICROSERVICE_API_URL?.startsWith('https://')) {
        setStatus({ type: 'error', message: 'Service configuration error. Please contact support.' });
        return;
      }

      if (token) {
        try {
          await signInWithCustomToken(auth, token);
          if (cancelled.current) return;
          completed.current = true;
          history.replace('/app/home');
        } catch {
          if (cancelled.current) return;
          setStatus({ type: 'error', message: resolveErrorMessage('FIREBASE_SIGNIN_FAILED') });
        }
        return;
      }

      if (error) {
        setStatus({ type: 'error', message: resolveErrorMessage(error, 'Sign-in failed. Please try again.') });
        return;
      }

      if (code && state) {
        await handleOidcExchange({ code, state, auth, history, setStatus, controller, TOKEN_EXCHANGE_TIMEOUT_MS, cancelled });
        return;
      }

      history.replace('/auth/login');
    };

    run();
    return () => {
      cancelled.current = true;
      controller.abort();
    };
  }, []);

  useEffect(() => {
    if (status.type === 'error') {
      history.replace('/auth/login');
    }
  }, [status, history]);

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
