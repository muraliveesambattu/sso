import React, { useContext, useEffect, useState } from 'react';
import { Card, Form, Divider, Button, Tooltip, message, Modal, Spin } from 'antd';
import { InfoCircleOutlined } from '@ant-design/icons';
import { useSsoForm } from '../../../../hooks/useSsoForm';
import { readFileAsBase64, useTestConnection } from '../../../../hooks/useTestConnection';
import { useJitMappings } from '../../../../hooks/useJitMappings';
import { activateSso, deactivateSso, deleteSsoConfig, getSsoConfig, saveConfigApi, saveSsoConfig } from '../../../../services/ssoApi';
import { AUTH_METHOD_MAP } from '../../../../constants/SsoConstants';
import IdpProtocolSelector from './components/IdpProtocolSelector';
import OidcConfigForm from './components/OidcConfigForm';
import SamlConfigForm from './components/SamlConfigForm';
import JitMappingSection from './components/JitMappingSection';
import ActiveConfigView from './components/ActiveConfigView';
import { getTenantId } from 'auth/FirebaseAuth';
import PermissionRestricted from 'views/app-views/utils/permission-restricted';
import { GetPermissionForPage } from 'views/app-views/utils/pagePermission';
import { AuthContext, useAuthContext } from 'auth/AuthProvider';
import PropTypes from 'prop-types'

const sectionLabel = { fontSize: 15, fontWeight: 600, color: '#1a1a2e' };

const SectionTitle = ({ text, tooltip }) => (
  <div style={{ marginBottom: 12 }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <span style={sectionLabel}>
        {text}
        <span style={{ color: '#ff4d4f', marginLeft: 2 }}>*</span>
      </span>
      {tooltip && (
        <Tooltip title={tooltip}>
          <InfoCircleOutlined style={{ color: '#0073E6', fontSize: 16, cursor: 'pointer' }} />
        </Tooltip>
      )}
    </div>
  </div>
);

SectionTitle.propTypes = {
  text: PropTypes.string.isRequired,
  tooltip: PropTypes.string,
}

const REVERSE_AUTH_METHOD = Object.fromEntries(
  Object.entries(AUTH_METHOD_MAP).map(([formVal, apiVal]) => [apiVal, formVal])
);

const mapApiToSavedConfig = (d) => ({
  company_id: d.integration.company_id,
  ownerTenantId: d.integration.owner_tenant_id,
  ownerCompanyName: d.integration.owner_company_name,
  protocol: d.integration.protocol,
  entra_domain: Array.isArray(d.integration.domains)
    ? d.integration.domains.join(', ')
    : (d.integration.domains || ''),
  tenant_id: d.integration.entra_tenant_id,
  client_id: d.oidc_config?.client_id,
  auth_method: d.oidc_config?.client_auth_method,
  idp: d.integration.idp,
  sso_status: d.integration.sso_status,
  jitEnabled: d.integration.jit_status,
  jitMappings: (d.jit_mappings || []).map(m => ({
    zdna_role: m.role_name || m.role_id, mapping_source: m.mapping_source, mapping_value: m.mapping_value,
  })),
  savedAt: new Date(),
  hasCert: !!d.oidc_config?.client_cert_thumbprint,
  certNames: {},
});

const parseDomains = (entra_domain) => {
  if (typeof entra_domain === 'string')
    return entra_domain.split(',').map((d) => d.trim()).filter(Boolean);
  return Array.isArray(entra_domain) ? entra_domain : [];
};

// Centred spinner used while the saved config is being fetched on first paint.
// Note: antd v5 only honours <Spin tip> in nest/fullscreen mode — a standalone
// `tip` prop logs a console warning — hence the separate caption node.
const LoadingCard = ({ text }) => (
  <Card style={{ borderRadius: 10, marginTop: 16 }} bodyStyle={{ padding: '24px' }}>
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', minHeight: 240, gap: 12,
    }}>
      <Spin size="large" />
      <span style={{ fontSize: 14, fontWeight: 400, color: '#595959' }}>{text}</span>
    </div>
  </Card>
);

LoadingCard.propTypes = {
  text: PropTypes.string.isRequired,
};

const SsoIntegrationPage = () => {
  const [form] = Form.useForm();
  const [savedConfig, setSavedConfig] = useState(null);
  const [originalConfig, setOriginalConfig] = useState(null);
  const [jitEnabled, setJitEnabled] = useState(false);
  const [saveLoading, setSaveLoading] = useState(false);
  // Covers the first-paint fetch only. Without it the empty form renders and
  // then snaps to ActiveConfigView when the request lands, which reads as the
  // page being slow to "display" the saved config.
  const [initialLoading, setInitialLoading] = useState(true);
  const context = useContext(AuthContext);
  const tenantId = getTenantId(context?.currentUser);
  console.log("Current Tenant ID >>", tenantId);
  const featureAccess = GetPermissionForPage('myServices');
  const isReadOnly = featureAccess.myServices.zebraDNAconfigToken <= 2;

  const {
    idp, setIdp,
    protocol, setProtocol,
    authMethod, setAuthMethod,
    signAuthn, setSignAuthn,
    isTestReady, setIsTestReady,
    fileValues, setFileValues,
    setIsEditMode,
    handleValuesChange,
    handleFileChange,
    handleIdpChange,
    handleProtocolChange,
    handleAuthMethodChange,
  } = useSsoForm(form);

  const {
    testLoading, testResult, testPassed,
    setTestPassed, setTestResult,
    handleTestConnection,
  } = useTestConnection(form, protocol, fileValues, setIsTestReady);

  const { currentUser } = useAuthContext();
  const claims = currentUser?.claims;
  const isSSOUser = claims?.loginType === "entra";
  // Kept as a primitive so the fetch effect below depends on the id, not on the
  // currentUser object identity. Optional chaining because savedConfig is null
  // on first render — reading .ownerTenantId off it threw before auth resolved.
  const ownerTenantIdFromUser = getTenantId(currentUser);
  const ownerTenantId = ownerTenantIdFromUser || savedConfig?.ownerTenantId;

  const {
    jitMappings, updateMapping, addMapping,
    removeMapping, resetMappings, isJitValid,
    mappingErrors: allMappingErrors,
  } = useJitMappings();

  const handleCancel = () => {
    const currentIdp = form.getFieldValue('idp');
    const currentProtocol = form.getFieldValue('protocol');
    form.resetFields();
    if (originalConfig) {
      form.setFieldsValue({ idp: currentIdp, protocol: currentProtocol });
    } else {
      setIdp(undefined);
      setProtocol(undefined);
    }
    setFileValues({});
    setJitEnabled(false);
    resetMappings();
    setIsTestReady(false);
    setTestResult(null);
    setTestPassed(false);
    setSavedConfig(originalConfig);
    setIsEditMode(false);
  };

  useEffect(() => {
    console.log('isSSOUser', isSSOUser);
    console.log('companyId', claims?.companyId);
    if (!isSSOUser || !claims?.companyId) return;
    let cancelled = false;
    (async () => {
      try {
        const { success, data } = await getSsoConfig({ companyId: claims.companyId });
        if (cancelled || !success || !data) return;
        const config = {
          ...mapApiToSavedConfig(data),
          email: claims.email,
          displayName: claims.displayName,
          role: claims.role,
          loginType: claims.loginType,
        };
        setSavedConfig(config);
        setOriginalConfig(config);
      } catch (e) {
        if (!cancelled) console.error('Failed to load SSO config for current user', e);
      }
    })();
    return () => { cancelled = true; };
  }, [isSSOUser, claims?.companyId]);

  useEffect(() => {
    // Nothing to fetch — clear the spinner so the empty form can render,
    // otherwise the page would spin forever for a user with no tenant.
    if (!ownerTenantIdFromUser) {
      setInitialLoading(false);
      return;
    }
    let cancelled = false;
    setInitialLoading(true);
    (async () => {
      try {
        console.log('calling getSSOConfig with CompanyId', claims?.companyId);
        const body = await getSsoConfig({ companyId: ownerTenantIdFromUser });
        const cfg = body?.data || body;
        if (cancelled) return;
        if (cfg?.integration) {
          const config = mapApiToSavedConfig(cfg);
          if (cfg?.saml_config) {
            config.sso_url = cfg.saml_config.sso_url;
          }
          setSavedConfig(config);
          setOriginalConfig(config);
        }
      } catch (err) {
        const msg = err?.message || '';
        const isNotFound = msg.includes('404') || msg.toLowerCase().includes('not found');
        if (!isNotFound) console.error('Failed to load existing SSO config:', err);
        if (!cancelled) setSavedConfig(null);
      } finally {
        if (!cancelled) setInitialLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [ownerTenantIdFromUser]);

  const handleSaveActivate = async () => {
    if (jitEnabled) {
      const invalid = jitMappings.some(m =>
        !m.zdna_role || !m.mapping_source ||
        (m.mapping_source !== 'default' && !m.mapping_value));
      if (invalid) {
        message.error('Please complete all JIT role mapping rows before saving.');
        return;
      }
    }
    const values = form.getFieldsValue();
    const [oidcCertB64, samlCertB64] = await Promise.all([
      fileValues.certificate ? readFileAsBase64(fileValues.certificate) : Promise.resolve(undefined),
      fileValues.saml_cert ? readFileAsBase64(fileValues.saml_cert) : Promise.resolve(undefined),
    ]);

    const domains = parseDomains(values.entra_domain);

    const payload = {
      company_id: ownerTenantId,
      protocol,
      idp,
      domains,
      tenant_id: values.tenant_id,
      client_id: values.client_id,
      auth_method: AUTH_METHOD_MAP[values.auth_method],
      client_secret: values.client_secret || undefined,
      certificate: protocol === 'saml' ? samlCertB64 : oidcCertB64,
      certificate_password: values.certificate_password || undefined,
      redirect_uri: values.redirect_uri,
      sso_url: values.sso_url,
      jit_status: jitEnabled,
      jit_mappings: jitEnabled ? jitMappings.map((row, index) => ({ ...row, order: index + 1 })) : [],
    };

    setSaveLoading(true);
    try {
      const { ok, data } = await saveConfigApi(payload);
      if (!ok || !data.success) {
        message.error(data.message || data?.error?.message || 'Failed to save SSO configuration.');
        return;
      }
      message.success(data.message || 'SSO configuration saved and activated!');
      const config = {
        ...values,
        idp,
        protocol,
        company_id: tenantId,
        jitEnabled,
        jitMappings: jitMappings.map((row, index) => ({ ...row, order: index + 1 })),
        savedAt: new Date(),
        hasCert: !!fileValues.saml_cert || !!fileValues.certificate,
        certNames: {
          saml_cert: fileValues.saml_cert?.name || null,
          certificate: fileValues.certificate?.name || null,
          saml_signing_cert: fileValues.saml_signing_cert?.name || null,
        },
        sso_status: 'active',
      };
      setSavedConfig(config);
      setOriginalConfig(config);
      setIsEditMode(false);
    } catch (err) {
      message.error(err.message || 'Network error — is the backend running?');
    } finally {
      setSaveLoading(false);
    }
  };

  const handleAuthMethodChangeWithReset = (val) =>
    handleAuthMethodChange(val, () => { setTestPassed(false); setTestResult(null); });

  const mappingErrors = jitEnabled ? allMappingErrors : {};
  const isSaveEnabled = testPassed && isJitValid(jitEnabled);

  const handleEdit = () => {
    const cfg = savedConfig;
    const formAuthMethod = REVERSE_AUTH_METHOD[cfg.auth_method] || cfg.auth_method;
    const formSignAuth = cfg.sign_auth || false;
    resetMappings(cfg.jitMappings || []);
    setJitEnabled(cfg.jitEnabled || false);
    setIdp(cfg.idp);
    setProtocol(cfg.protocol);
    setAuthMethod(formAuthMethod);
    setSignAuthn(formSignAuth);
    const restoredValues = {
      idp: cfg.idp,
      protocol: cfg.protocol,
      entra_domain: cfg.entra_domain,
      auth_method: formAuthMethod,
      tenant_id: cfg.tenant_id || undefined,
      client_id: cfg.client_id || undefined,
      sso_url: cfg.sso_url || undefined,
      sign_auth: formSignAuth,
    };
    setFileValues({});
    setIsTestReady(false);
    setTestPassed(false);
    setTestResult(null);
    form.resetFields();
    form.setFieldsValue(restoredValues);
    setSavedConfig(null);
    setIsEditMode(true);
  };

  const handleActivate = async (companyId) => {
    try {
      await activateSso(companyId);
      setSavedConfig(prev => ({ ...prev, sso_status: 'active' }));
      setOriginalConfig(prev => ({ ...prev, sso_status: 'active' }));
      message.success('SSO activated');
    } catch (err) {
      message.error(err.message || 'Failed to activate SSO');
    }
  };

  const handleDeactivate = () => {
    Modal.confirm({
      title: 'Deactivate SSO?',
      content: 'Users will no longer be able to log in using SSO. Do you want to continue?',
      okText: 'Deactivate',
      okType: 'danger',
      cancelText: 'Cancel',
      onOk: async () => {
        try {
          await deactivateSso(savedConfig.company_id);
          setSavedConfig(prev => ({ ...prev, sso_status: 'inactive' }));
          setOriginalConfig(prev => ({ ...prev, sso_status: 'inactive' }));
          message.success('SSO deactivated');
        } catch (err) {
          message.error(err.message || 'Failed to deactivate SSO');
        }
      },
    });
  };

  const handleRemove = async (companyId) => {
    try {
      await deleteSsoConfig(companyId);
      handleCancel();
      message.success('SSO configuration removed');
      setSavedConfig(null);
    } catch (err) {
      message.error(err.message || 'Failed to remove SSO configuration');
    }
  };

  const handleUpdate = async (payload) => {
    setSaveLoading(true);
    try {
      const res = await saveSsoConfig(payload);
      message.success(res.message || 'Configuration updated');
      const cfg = await getSsoConfig({ companyId: res.company_id });
      const config = mapApiToSavedConfig(cfg);
      setSavedConfig(config);
      setOriginalConfig(config);
      setIsEditMode(false);
    } catch (err) {
      message.error(err.message || 'Failed to update configuration');
    } finally {
      setSaveLoading(false);
    }
  };

  const handleProtocolChangeWithReset = (value) => {
    resetMappings();
    setJitEnabled(false);
    handleProtocolChange(value);
  };

  // Held before the savedConfig branch so the user never sees the empty form
  // flash while the saved config is still in flight.
  if (initialLoading) {
    return <LoadingCard text="Loading SSO configuration…" />;
  }

  if (savedConfig) {
    return (
      <ActiveConfigView
        savedConfig={savedConfig}
        saving={saveLoading}
        onEdit={handleEdit}
        onActivate={() => handleActivate(savedConfig.company_id)}
        onDeactivate={() => handleDeactivate()}
        onRemove={() => handleRemove(savedConfig.company_id)}
        onSaveJitMappings={(mappings) => {
          const savedDomains = parseDomains(savedConfig.entra_domain);
          return handleUpdate({
            protocol: savedConfig.protocol,
            idp: savedConfig.idp,
            domains: savedDomains,
            tenant_id: savedConfig.tenant_id,
            client_id: savedConfig.client_id,
            auth_method: AUTH_METHOD_MAP[REVERSE_AUTH_METHOD[savedConfig.auth_method]] || savedConfig.auth_method,
            company_id: savedConfig.company_id,
            jit_enabled: true,
            jit_mappings: mappings.map((row, index) => ({ ...row, order: index + 1 })),
          });
        }}
      />
    );
  }

  return (
    <Card style={{ borderRadius: 10, marginTop: 16, background: 'white !important' }} bodyStyle={{ padding: '24px' }}>
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 20, fontWeight: 700, color: '#1a1a2e', marginBottom: 4 }}>
          Single Sign On Integration
        </div>
        <div style={{ fontSize: 14, fontWeight: 400, color: '#595959' }}>
          Connect your Microsoft Entra (Azure AD) tenant to enable Single Sign-On for your users.
        </div>
      </div>
      <Form form={form} layout="vertical" onValuesChange={handleValuesChange} disabled={isReadOnly}>
        <SectionTitle text="Select Identity Provider & Protocol" />
        <IdpProtocolSelector
          idp={idp}
          onIdpChange={handleIdpChange}
          onProtocolChange={handleProtocolChangeWithReset}
        />
        {protocol === 'oidc' && (
          <>
            <SectionTitle text="Enter your Entra credentials to configure the OIDC connection" />
            <OidcConfigForm
              authMethod={authMethod}
              onAuthMethodChange={handleAuthMethodChangeWithReset}
              onFileChange={handleFileChange}
              isTestReady={isTestReady}
              testLoading={testLoading}
              testResult={testResult}
              onTest={handleTestConnection}
            />
          </>
        )}
        {protocol === 'saml' && (
          <>
            <SectionTitle text="Enter your Entra credentials to configure the SAML connection" />
            <SamlConfigForm
              signAuthn={signAuthn}
              onSignAuthnChange={setSignAuthn}
              onFileChange={handleFileChange}
              isTestReady={isTestReady}
              testLoading={testLoading}
              testResult={testResult}
              onTest={handleTestConnection}
            />
          </>
        )}
        <JitMappingSection
          jitEnabled={jitEnabled}
          onJitToggle={setJitEnabled}
          jitMappings={jitMappings}
          onUpdateMapping={updateMapping}
          onAddMapping={addMapping}
          onRemoveMapping={removeMapping}
          mappingErrors={mappingErrors}
          disabled={!testPassed}
        />
        <Divider style={{ margin: '20px 0 16px' }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: 12, fontWeight: 400, color: '#bfbfbf' }}>
            {testPassed
              ? 'Mandatory Steps must be completed before activation*'
              : 'Test Connection must pass before activation*'}
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            <Button onClick={handleCancel} style={{ borderRadius: 6 }}>
              Cancel
            </Button>
            {isReadOnly ? (
              <PermissionRestricted
                type="customButton"
                title="Save & Activate SSO"
                tooltipPlacement="top"
              />
            ) : (
              <Button
                type="primary"
                disabled={!isSaveEnabled}
                loading={saveLoading}
                onClick={handleSaveActivate}
                style={{
                  backgroundColor: isSaveEnabled ? '#0073E6' : undefined,
                  borderColor: isSaveEnabled ? '#0073E6' : undefined,
                  borderRadius: 6,
                  fontWeight: 500,
                  fontSize: 14,
                  minWidth: 160,
                  height: 36,
                }}
              >
                Save & Activate SSO
              </Button>
            )}
          </div>
        </div>
      </Form>
      <style>{`
        .ant-form-item-label { background: white; }
      `}</style>
    </Card>
  );
};

export default SsoIntegrationPage;
