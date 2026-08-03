import { useState, useCallback } from 'react';
import { Modal, message } from 'antd';
import { FILE_FIELDS, IDP_RESET_FIELDS, PROTOCOL_RESET_FIELDS } from '../constants/SsoConstants';
import { validatePemOrDerCertFile, validatePkcs12File, FQDN } from '../utils/sso-integration-field-validator';

const MAX_FILE_SIZE_BYTES = 10 * 1024;

const getRequiredFields = (protocol, authMethod) => {
  if (protocol === 'oidc') {
    const base = ['idp', 'protocol', 'tenant_id', 'client_id', 'auth_method', 'entra_domain'];
    if (authMethod === 'secret') return [...base, 'client_secret'];
    if (authMethod === 'certificate') return [...base, 'certificate', 'certificate_password'];
    return base;
  }
  if (protocol === 'saml') return ['idp', 'protocol', 'sso_url', 'saml_cert', 'entra_domain'];
  return ['idp', 'protocol'];
};

export const useSsoForm = (form) => {
  const [idp, setIdp] = useState(null);
  const [protocol, setProtocol] = useState(null);
  const [authMethod, setAuthMethod] = useState(null);
  const [signAuthn, setSignAuthn] = useState(false);
  const [isTestReady, setIsTestReady] = useState(false);
  const [fileValues, setFileValues] = useState({});
  const [isEditMode, setIsEditMode] = useState(false);

  const checkTestReady = (values, files) => {
    const selectedProtocol = values.protocol;
    const selectedAuthMethod = values.auth_method;
    if (!selectedProtocol) return false;
    if (selectedProtocol === 'oidc' && !selectedAuthMethod) return false;
    if (selectedProtocol === 'oidc' && selectedAuthMethod === 'none') {
      return !!(values.tenant_id && values.client_id && values.entra_domain);
    }
    if (selectedProtocol === 'saml' && values.sso_url) {
      const samlUrlPattern = /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/saml2\?appid=[0-9a-f-]{36}$/i;
      if (!samlUrlPattern.test(values.sso_url.trim())) return false;
    }
    let requiredFields = getRequiredFields(selectedProtocol, selectedAuthMethod);
    if (selectedProtocol === 'saml' && values.sign_auth) {
      requiredFields = [...requiredFields, 'saml_signing_cert', 'saml_signing_cert_password'];
    }
    return requiredFields.every((field) => {
      if (FILE_FIELDS.includes(field)) return !!files[field];
      const fieldValue = values[field];
      if (field === 'entra_domain') {
        const domains = String(fieldValue ?? '').split(',').map((d) => d.trim().toLowerCase());
        return domains.every((d) => FQDN.test(d));
      }
      return fieldValue !== undefined && fieldValue !== null && String(fieldValue).trim() !== '';
    });
  };

  const resetTestState = (filesToKeep = {}) => {
    setFileValues(filesToKeep);
    setIsTestReady(false);
  };

  const handleValuesChange = (_, allValues) => {
    const fileUpdates = {};
    FILE_FIELDS.forEach((f) => {
      if (allValues[f] instanceof File) fileUpdates[f] = allValues[f];
    });
    const mergedFileValues = { ...fileValues, ...fileUpdates };
    setFileValues(mergedFileValues);

    setTimeout(() => {
      const hasErrors = form.getFieldsError().some((field) => field.errors.length > 0);
      setIsTestReady(checkTestReady(allValues, mergedFileValues) && !hasErrors);
    }, 0)
  };

  const handleFileChange = useCallback(async (fieldName, e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size === 0) {
      e.target.value = '';
      message.error('File is empty. Please upload a valid certificate file.');
      return;
    }
    if (file.size > MAX_FILE_SIZE_BYTES) {
      e.target.value = '';
      message.error(`File too large. Maximum size is ${MAX_FILE_SIZE_BYTES / 1024} KB.`);
      return;
    }
    try {
      if (fieldName === 'saml_cert') await validatePemOrDerCertFile(file);
      if (fieldName === 'certificate' || fieldName === 'saml_signing_cert') await validatePkcs12File(file);
    } catch (error_) {
      message.error(error_.message);
      const cleaned = { ...fileValues };
      delete cleaned[fieldName];
      setFileValues(cleaned);
      setIsTestReady(checkTestReady(form.getFieldsValue(), cleaned));
      return;
    }
    const updated = { ...fileValues, [fieldName]: file };
    setFileValues(updated);
    const hasErrors = form.getFieldsError().some((field) => field.errors.length > 0);
    setIsTestReady(checkTestReady(form.getFieldsValue(), updated) && !hasErrors);
    return updated;
  }, [fileValues, form]);

  const handleIdpChange = (value) => {
    setIdp(value);
    form.setFieldsValue({ idp: value });
    setProtocol(null);
    setAuthMethod(null);
    resetTestState();
    form.resetFields(IDP_RESET_FIELDS);
    [
      'oidc_company_id', 'tc_company_id', 'tc_session_ref',
      'tc_result', 'tc_oidc_code', 'tc_oidc_state', 'tc_session_timestamp',
    ].forEach((key) => localStorage.removeItem(key));
  };

  const applyProtocolChange = (value) => {
    setProtocol(value);
    setAuthMethod(null);
    setSignAuthn(false);
    resetTestState();
    form.resetFields(PROTOCOL_RESET_FIELDS);
    form.setFieldsValue({ protocol: value });
  };

  const handleProtocolChange = (value) => {
    if (isEditMode && protocol && protocol !== value) {
      Modal.confirm({
        title: 'Change Protocol?',
        content: 'Changing the protocol will clear all existing SSO configuration. Do you want to continue?',
        onOk: () => { setIsTestReady(false); applyProtocolChange(value); },
      });
      return;
    }
    setIsTestReady(false);
    applyProtocolChange(value);
  };

  const handleAuthMethodChange = (selectedMethod, onResetTest) => {
    setAuthMethod(selectedMethod);
    form.setFieldsValue({ auth_method: selectedMethod });
    resetTestState();
    let fieldsToReset;
    if (selectedMethod === 'secret') fieldsToReset = ['certificate', 'certificate_password'];
    else if (selectedMethod === 'certificate') fieldsToReset = ['client_secret'];
    else fieldsToReset = ['client_secret', 'certificate', 'certificate_password'];
    form.resetFields(fieldsToReset);
    const currentValues = form.getFieldsValue();
    const updatedValues = { ...currentValues, auth_method: selectedMethod };
    const hasErrors = form.getFieldsError().some((field) => field.errors.length > 0);
    setIsTestReady(checkTestReady(updatedValues, fileValues) && !hasErrors);
    if (onResetTest) onResetTest();
  };

  return {
    idp, setIdp,
    protocol, setProtocol,
    authMethod, setAuthMethod,
    signAuthn, setSignAuthn,
    isTestReady, setIsTestReady,
    fileValues, setFileValues,
    isEditMode, setIsEditMode,
    handleValuesChange,
    handleFileChange,
    handleIdpChange,
    handleProtocolChange,
    handleAuthMethodChange,
  };
};
