import { useState, useEffect, useCallback } from 'react';
import { getEntraClaimsApi } from '../services/ssoApi';
import {
  ENTRA_GUID_RE,
  ENTRA_SAML_TENANT_RE,
  ENTRA_CLAIMS_LOAD_DELAY_MS,
  ENTRA_CLAIMS_FAILED_MESSAGE,
  ENTRA_CLAIMS_INCOMPLETE_MESSAGE,
} from '../constants/SsoConstants';

const IDLE = { catalog: undefined, status: 'idle', error: null };

// The SSO app must be identifiable before Entra can be asked about it:
// OIDC by tenant + client id, SAML by the tenant inside its SSO URL.
const isComplete = ({ protocol, tenantId, clientId, ssoUrl }) => {
  if (protocol === 'oidc') return ENTRA_GUID_RE.test(tenantId || '') && ENTRA_GUID_RE.test(clientId || '');
  if (protocol === 'saml') return ENTRA_SAML_TENANT_RE.test(ssoUrl || '');
  return false;
};

/**
 * Loads, in the background, the claims catalog of the customer's Entra SSO app
 * ({ claimNames, roles, groups }) through the ZDNA connector app. Shows nothing
 * itself: useJitMappings checks the rows against the catalog once it arrives.
 *
 * Returns { catalog, status, error, retry }:
 *   status  'idle' (not enabled) | 'loading' | 'ready' | 'error'
 *   error   message to show when status is 'error' — the API's safe message
 *           (e.g. connector not consented) or a generic one for network errors
 *   retry() loads the catalog again
 */
export const useEntraClaims = ({ enabled, companyId, protocol, tenantId, clientId, ssoUrl }) => {
  const [state, setState] = useState(IDLE);
  const [attempt, setAttempt] = useState(0);
  const complete = isComplete({ protocol, tenantId, clientId, ssoUrl });

  useEffect(() => {
    if (!enabled) {
      setState(IDLE);
      return undefined;
    }
    if (!complete) {
      setState({ catalog: undefined, status: 'error', error: ENTRA_CLAIMS_INCOMPLETE_MESSAGE });
      return undefined;
    }
    setState({ catalog: undefined, status: 'loading', error: null });
    let cancelled = false;
    // Short delay so typing a tenant or client id does not fire a request per key.
    const timer = setTimeout(async () => {
      try {
        const { ok, data } = await getEntraClaimsApi({
          company_id: companyId,
          protocol,
          tenant_id: tenantId,
          client_id: clientId,
          sso_url: ssoUrl,
        });
        if (cancelled) return;
        if (ok && data?.success) {
          setState({ catalog: data.data, status: 'ready', error: null });
        } else {
          setState({ catalog: undefined, status: 'error', error: data?.error?.message || data?.message || ENTRA_CLAIMS_FAILED_MESSAGE });
        }
      } catch (err) {
        if (cancelled) return;
        console.warn('[SSO] Entra claims not loaded:', err.message);
        setState({ catalog: undefined, status: 'error', error: ENTRA_CLAIMS_FAILED_MESSAGE });
      }
    }, ENTRA_CLAIMS_LOAD_DELAY_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [enabled, complete, companyId, protocol, tenantId, clientId, ssoUrl, attempt]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  return { ...state, retry };
};
