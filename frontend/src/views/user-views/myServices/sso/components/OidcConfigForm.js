import React, { useState } from 'react';
import { Form, Input, Select, Row, Col, Tooltip } from 'antd';
import { CopyOutlined } from '@ant-design/icons';
import { validateUUID, validateDomains, validatePkcs12File ,validateClientSecret } from '../../../../../utils/sso-integration-field-validator';
import { REDIRECT_URI } from '../../../../../constants/SsoConstants';
import TestConnectionPanel from './TestConnectionPanel';
import PropTypes from 'prop-types';


const { Option } = Select;
const fieldLabel = { fontSize: 13, fontWeight: 400, color: '#595959' };

const OidcConfigForm = ({
  authMethod,
  onAuthMethodChange,
  onFileChange,
  isTestReady,
  testLoading,
  testResult,
  onTest,
}) => {
  const [copied, setCopied] = useState(false);
  const redirectInputRef = React.useRef(null);
  const handleCopy = () => {
    const val = redirectInputRef.current?.input?.value || REDIRECT_URI;
    navigator.clipboard.writeText(val);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <>
      <Form.Item
        label={<span style={fieldLabel}>Redirect URL</span>}
        name="redirect_uri"
        initialValue={REDIRECT_URI}
        style={{ marginBottom: 16 }}
      >
        <Input
          ref={redirectInputRef}
          style={{ borderRadius: 6 }}
          suffix={
            <Tooltip title={copied ? 'Copied!' : 'Copy'}>
              <CopyOutlined
                onClick={handleCopy}
                style={{ color: copied ? '#27e395' : '#e62300e9', cursor: 'pointer' }}
              />
            </Tooltip>
          }
        />
      </Form.Item>
      <Row gutter={16} style={{ background: "white" }}>
        <Col span={12}>
          <Form.Item
            label={<span style={fieldLabel}>Tenant ID *</span>}
            name="tenant_id"
            rules={[{ validator: validateUUID('Tenant ID') }]}
            style={{ marginBottom: 16 }}
          >
            <Input placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
          </Form.Item>
        </Col>
        <Col span={12}>
          <Form.Item
            label={<span style={fieldLabel}>Client ID (Application ID) *</span>}
            name="client_id"
            rules={[{ validator: validateUUID('Client ID') }]}
            style={{ marginBottom: 16 }}
          >
            <Input placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
          </Form.Item>
        </Col>
      </Row >
      <Form.Item
        label={<span style={fieldLabel}>Authentication Method *</span>}
        name="auth_method"
        rules={[{ required: true, message: 'Select auth method' }]}
        style={{ marginBottom: 16 }}
      >
        <Select placeholder="Select authentication method" onChange={onAuthMethodChange}>
          <Option value="none">None (PKCE)</Option>
          <Option value="secret">Client Secret</Option>
          <Option value="certificate">Client Certificate</Option>
        </Select>
      </Form.Item>
      {
        authMethod === 'secret' && (
          <Form.Item
            label={<span id="client-secret-label" style={fieldLabel}>Client Secret *</span>}
            name="client_secret"
            rules={[{ validator: validateClientSecret }]}
            style={{ marginBottom: 16 }}
          >
            <Input.Password placeholder="Enter client secret value" />
          </Form.Item>
        )
      }
      {
        authMethod === 'certificate' && (
          <Row gutter={16} style={{ background: "white !important" }}>
            <Col span={12}>
              <Form.Item
                label={
                  <span id="certificate-label" style={fieldLabel}>
                    Upload Certificate (.pfx/.p12){' '}
                    <span id="certificate-required-asterisk" style={{ color: '#ff4d4f', background: "white !important" }}> *</span>
                  </span>
                }
                name="certificate"
                valuePropName="file"
                getValueFromEvent={(e) => e?.target?.files?.[0]}
                rules={[
                  {
                    validator: async (_, file) => {
                      if (!file) {
                        throw new Error('Certificate is required');
                      }
                      await validatePkcs12File(file);
                    }
                  }
                ]}
                style={{ marginBottom: 16 }}
              >
                <input
                  id="certificate-file-input"
                  type="file"
                  accept=".pfx,.p12"
                  style={{ width: '100%', padding: '4px 0' }}
                  onChange={(e) => onFileChange('certificate', e)}
                />
              </Form.Item>

            </Col>
            <Col span={12}>
              <Form.Item
                label={<span id="certificate-password-label" style={fieldLabel}>Certificate Password *</span>}
                name="certificate_password"
                rules={[{ required: true, message: 'Password required' }]}
                style={{ marginBottom: 16 }}
              >
                <Input.Password />
              </Form.Item>
            </Col>
          </Row>
        )
      }
      <Form.Item
        label={<span style={fieldLabel}>Entra Verified Domains *</span>}
        name="entra_domain"
        rules={[{ validator: validateDomains }]}
        style={{ marginBottom: 16 }}
      >
        <Input placeholder="contoso.com, domain.com" />
      </Form.Item>
      <TestConnectionPanel
        isTestReady={isTestReady}
        testLoading={testLoading}
        testResult={testResult}
        onTest={onTest}
      />
    </>
  );
};


OidcConfigForm.propTypes = {
  authMethod: PropTypes.string,
  onAuthMethodChange: PropTypes.func.isRequired,
  onFileChange: PropTypes.func.isRequired,
  isTestReady: PropTypes.bool.isRequired,
  testLoading: PropTypes.bool.isRequired,
  onTest: PropTypes.func.isRequired,
  testResult: PropTypes.shape({
    status: PropTypes.string,
    message: PropTypes.string,
  }),
};

export default OidcConfigForm;
