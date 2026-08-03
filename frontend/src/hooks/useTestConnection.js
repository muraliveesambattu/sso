import { useState, useContext, useEffect, useRef } from 'react';
import {
  AUTH_METHOD_MAP,
  SAML_ACS_URL,
  SAML_ENTITY_ID,
  REDIRECT_URI,
} from '../constants/SsoConstants';
import { testConnectionApi, testConnectionCallbackApi } from '../services/ssoApi';
import { getTenantId } from 'auth/FirebaseAuth';
import { AuthContext } from 'auth/AuthProvider';

export const readFileAsBase64 = (file) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = typeof reader.result === 'string' ? reader.result : '';
      resolve(result.split(',')[1] ?? '');
    };
    reader.onerror = () => reject(new Error('Failed to read file'));
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

  const cleanupPopupFlow = (popup, popupCheck) => {
    if (popupCheck) clearInterval(popupCheck);
    localStorage.removeItem('tc_company_id');
    localStorage.removeItem('tc_session_ref');
    localStorage.removeItem('tc_result');
    localStorage.removeItem('tc_oidc_code');
    localStorage.removeItem('tc_oidc_state');
    try { popup?.close(); } catch (err) { console.debug('Unable to check popup state:', err); }
  };

  const handleTestConnection = async () => {
    setTestLoading(true);
    setTestResult(null);
    localStorage.removeItem('tc_company_id');
    localStorage.removeItem('tc_session_ref');
    localStorage.removeItem('tc_result');
    localStorage.removeItem('tc_oidc_code');
    localStorage.removeItem('tc_oidc_state');
    localStorage.removeItem('oidc_company_id');
    try {
      const values = form.getFieldsValue();
      const samlCertB64 = fileValues.saml_cert ? await readFileAsBase64(fileValues.saml_cert) : undefined;
      const oidcCertB64 = fileValues.certificate ? await readFileAsBase64(fileValues.certificate) : undefined;

      const payload = protocol === 'saml'
        ? {
          protocol: 'saml',
          company_id: tenantId,
          domains: parseDomains(values.entra_domain),
          entity_id: SAML_ENTITY_ID,
          acs_url: SAML_ACS_URL,
          sso_url: values.sso_url,
          certificate: samlCertB64,
          tenant_id: tenantId,
        }
        : {
          protocol: 'oidc',
          company_id: tenantId,
          domains: parseDomains(values.entra_domain),
          tenant_id: values.tenant_id,
          client_id: values.client_id,
          auth_method: AUTH_METHOD_MAP[values.auth_method],
          client_secret: values.client_secret || undefined,
          certificate: oidcCertB64,
          certificate_password: values.certificate_password || undefined,
          sso_url: `https://login.microsoftonline.com/${values.tenant_id}/oauth2/v2.0/authorize`,
          redirect_uri: REDIRECT_URI,
          scope: 'openid profile email',
        };

      const { ok, data } = await testConnectionApi(payload);
      if (!ok || !data.success) {
        setTestResult({
          status: 'failed',
          message: data.error?.message || data.message || data.errors?.join(', ') || 'Test Connection failed',
        });
        setTestPassed(false);
        return;
      }

      if (protocol === 'saml') {
        setTestResult({ status: 'passed', message: data.message || 'Test Connection successful' });
        setTestPassed(true);
        setIsTestReady(true);
        return;
      }

      if (protocol === 'oidc') {
        const cfg = data.data?.config || {};
        const sessionRef = data.data?.sessionRef;
        if (!sessionRef) {
          setTestResult({ status: 'failed', message: 'Session reference missing. Please try again.' });
          setTestPassed(false);
          return;
        }
        if (!cfg.state || !cfg.nonce) {
          setTestResult({ status: 'failed', message: 'Invalid configuration from server. Please try again.' });
          setTestPassed(false);
          return;
        }
        const ssoUrl = cfg.sso_url ||
          `https://login.microsoftonline.com/${values.tenant_id}/oauth2/v2.0/authorize`;
        const authorizeParams = new URLSearchParams({
          client_id: cfg.client_id || values.client_id,
          response_type: 'code',
          redirect_uri: REDIRECT_URI,
          scope: cfg.scope || 'openid profile email',
          state: cfg.state,
          nonce: cfg.nonce,
          prompt: 'login',
          ...(cfg.code_challenge ? {
            code_challenge: cfg.code_challenge,
            code_challenge_method: cfg.code_challenge_method,
          } : {}),
        });
        localStorage.setItem('tc_company_id', payload.company_id);
        localStorage.setItem('tc_session_ref', sessionRef);
        const azureUrl = `${ssoUrl}?${authorizeParams.toString()}`;
        const popup = window.open(azureUrl, '_blank', 'width=500,height=600,left=200,top=100');
        if (!popup || popup.closed) {
          localStorage.removeItem('tc_company_id');
          localStorage.removeItem('tc_session_ref');
          setTestResult({ status: 'failed', message: 'Popup was blocked. Please allow popups for this site and try again.' });
          setTestPassed(false);
          return;
        }

        const pollPopup = async () => {
          const tcResult = localStorage.getItem('tc_result');
          if (tcResult) {
            const result = JSON.parse(tcResult);
            setTestResult({ status: 'failed', message: result.message || 'Test Connection failed.' });
            setTestPassed(false);
            cleanupPopupFlow(popup, popupCheckRef.current);
            return;
          }
          const tcCode = localStorage.getItem('tc_oidc_code');
          const tcState = localStorage.getItem('tc_oidc_state');
          if (tcCode && tcState) {
            clearInterval(popupCheckRef.current);
            popupCheckRef.current = null;
            const company_id = localStorage.getItem('tc_company_id');
            const tcRef = localStorage.getItem('tc_session_ref');
            localStorage.removeItem('tc_oidc_code');
            localStorage.removeItem('tc_oidc_state');
            localStorage.removeItem('tc_company_id');
            localStorage.removeItem('tc_session_ref');
            try {
              const { ok: cbOk, data: cbData } = await testConnectionCallbackApi({ code: tcCode, state: tcState, company_id, sessionRef: tcRef });
              if (!cbOk || !cbData.success) {
                setTestResult({ status: 'failed', message: cbData.error?.message || cbData.message || 'Test Connection failed.' });
                setTestPassed(false);
                try { popup?.close(); } catch (e) { console.debug('Unable to close popup:', e); }
                return;
              }
              setTestResult({ status: 'passed', message: cbData.message || 'Test Connection successful' });
              setTestPassed(true);
              setIsTestReady(true);
              try { popup?.close(); } catch (e) { console.debug('Unable to close popup:', e); }
            } catch (err) {
              console.error('[useTestConnection] callback API error:', err);
              setTestResult({ status: 'failed', message: err.message || 'Network error. Please try again.' });
              setTestPassed(false);
            }
            return;
          }
          try {
            if (popup?.closed) {
              cleanupPopupFlow(popup, popupCheckRef.current);
              setTestPassed(prev => {
                if (!prev) setTestResult({ status: 'failed', message: 'Test Connection cancelled. Please try again.' });
                return prev;
              });
            }
          } catch (err) {
            console.debug('Popup close failed:', err);
          }
        };

        popupCheckRef.current = setInterval(pollPopup, 500);
      }
    } catch (err) {
      console.error('[useTestConnection] handleTestConnection error:', err);
      setTestResult({
        status: 'failed',
        message: err.message || 'Network error. Please check your connection and try again.',
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
