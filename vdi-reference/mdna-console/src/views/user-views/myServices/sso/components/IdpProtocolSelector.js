import React from 'react';
import { Form, Select } from 'antd';
import PropTypes from 'prop-types';
import { useFeatures } from 'auth/AuthProvider';
const { Option } = Select;
const fieldLabel = { fontSize: 13, fontWeight: 400, color: '#595959' };
const IdpProtocolSelector = ({ idp, onIdpChange, onProtocolChange }) => {
  const features = useFeatures();
  const isSamlEnabled = features?.saml_enabled;

  return (
    <>
      <Form.Item
        label={<span style={fieldLabel}>Identity Provider</span>}
        name="idp"
        rules={[{ required: true, message: 'Select Identity Provider' }]}
        style={{ marginBottom: 16 }}
      >
        <Select placeholder="Select your Identity Provider" onChange={onIdpChange}>
          <Option value="entra">Microsoft Entra (Azure AD)</Option>
        </Select>
      </Form.Item>
      {idp && (
        <Form.Item
          label={<span style={fieldLabel}>Authentication Protocol</span>}
          name="protocol"
          rules={[{ required: true, message: 'Select protocol' }]}
          style={{ marginBottom: 20 }}
        >
          <Select placeholder="Select a protocol" onChange={onProtocolChange}>
            <Option value="oidc">OIDC (OpenID Connect)</Option>
            {isSamlEnabled && (<Option value="saml">SAML 2.0</Option>)}
          </Select>
        </Form.Item>
      )}
    </>
  )
};


IdpProtocolSelector.propTypes = {
  idp: PropTypes.string,
  onIdpChange: PropTypes.func.isRequired,
  onProtocolChange: PropTypes.func.isRequired,
};

export default IdpProtocolSelector;
