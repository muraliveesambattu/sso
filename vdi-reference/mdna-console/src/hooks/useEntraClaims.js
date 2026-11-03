import { useState, useEffect } from 'react';
import { getEntraClaimsApi } from '../services/ssoApi';

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LOAD_DELAY_MS = 400;

// The SSO app must be identifiable before Entra can be asked about it:
// OIDC by tenant + client id, SAML by the tenant inside its SSO URL.
const isComplete = ({ protocol, tenantId, clientId, ssoUrl }) => {
  if (protocol === 'oidc') return GUID_RE.test(tenantId || '') && GUID_RE.test(clientId || '');
  if (protocol === 'saml') return /login\.microsoftonline\.com\/[0-9a-f-]{36}\//i.test(ssoUrl || '');
  return false;
};

/**
 * Loads, in the background, the claims catalog of the customer's Entra SSO app
 * ({ claimNames, roles, groups }) through the ZDNA connector app. Shows nothing
 * itself: useJitMappings checks the rows against it once it arrives.
 *
 * Returns the catalog, or undefined while it is loading or when it cannot be
 * loaded (connector not configured or not consented, network error) — then the
 * console does not block and the backend check on Save decides.
 */
export const useEntraClaims = ({ enabled, companyId, protocol, tenantId, clientId, ssoUrl }) => {
  const [catalog, setCatalog] = useState(undefined);
  const ready = enabled && isComplete({ protocol, tenantId, clientId, ssoUrl });

  useEffect(() => {
    setCatalog(undefined);
    if (!ready) return undefined;
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
        if (!cancelled && ok && data?.success) setCatalog(data.data);
      } catch (err) {
        console.warn('[SSO] Entra claims not loaded:', err.message);
      }
    }, LOAD_DELAY_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [ready, companyId, protocol, tenantId, clientId, ssoUrl]);

  return catalog;
};
