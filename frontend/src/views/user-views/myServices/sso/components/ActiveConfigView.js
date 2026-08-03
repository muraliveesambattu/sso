import React, { useState, useEffect, useContext } from 'react';
import { Card, Row, Col, Button, Tooltip, Select, Input, Modal } from 'antd';
import { InfoCircleOutlined } from '@ant-design/icons';
import { useJitMappings } from '../../../../../hooks/useJitMappings';
import { AuthContext } from 'auth/AuthProvider';
import { getTenantId } from 'auth/FirebaseAuth';
import { getRoleConfig } from '../../../../../firebase/fireStore/roleManagementDBMethods';
import PropTypes from 'prop-types';
import PermissionRestricted from 'views/app-views/utils/permission-restricted';
import { GetPermissionForPage } from 'views/app-views/utils/pagePermission';

const { Option } = Select;

const metaLabel = {
  fontSize: 12,
  color: '#8c8c8c',
  marginBottom: 2
};
const metaValue = {
  fontSize: 13,
  fontWeight: 500,
  color: '#1a1a2e'
};

const StatusBadge = ({ status }) => (
  <span
    id='status-badge'
    style={{
      background: status === 'inactive' ? '#fff1f0' : '#f6ffed',
      color: status === 'inactive' ? '#cf1322' : '#389e0d',
      border:
        '1px solid ' +
        (status === 'inactive' ? '#ffa39e' : '#b7eb8f'),
      borderRadius: 12,
      padding: '2px 10px',
      fontSize: 12,
      fontWeight: 500
    }}
  >
    ● {status === 'inactive' ? 'Inactive' : 'Active'}
  </span>
);
StatusBadge.propTypes = {
  status: PropTypes.string,
};

const ActiveConfigView = ({
  savedConfig,
  onEdit,
  onDeactivate,
  onRemove,
  onSaveJitMappings,
  saving = false
}) => {
  const context = useContext(AuthContext);
  const tenantId = getTenantId(context?.currentUser);
  const [roleData, setRoleData] = useState([]);
  const featureAccess = GetPermissionForPage('myServices');
  const canManageSSO = featureAccess.myServices.zebraDNAconfigToken > 2;

  useEffect(() => {
    let cancelled = false;
    getRoleConfig(tenantId)
      .then((resData) => {
        if (cancelled) return;
        const arr = resData.roleNames.map((ele) => ({
          value: ele,
          label: ele,
        }));
        setRoleData(arr);
      })
      .catch((err) => {
        if (cancelled) return;
        console.error('Failed to load role config:', err);
        setRoleData([]);
      });
    return () => {
      cancelled = true;
    };
  }, [tenantId]);

  const [editingJit, setEditingJit] = useState(false);
  const {
    jitMappings,
    updateMapping,
    addMapping,
    removeMapping,
    resetMappings,
    isJitValid,
    mappingErrors,
  } = useJitMappings(
    (savedConfig.jitMappings || []).map(row => ({
      ...row,
      id: row.id || crypto.randomUUID(),
    }))
  );

  const handleRemoveClick = () => {
    Modal.confirm({
      title: 'Remove SSO Configuration?',
      content:
        'This will permanently delete all SSO and JIT configuration. This action is irreversible.',
      okText: 'Remove',
      okButtonProps: { danger: true },
      onOk: onRemove
    });
  };

  return (
    <Card
      style={{ borderRadius: 10, marginTop: 16 }}
      bodyStyle={{ padding: '24px' }}
    >
      <div
        style={{
          fontSize: 20,
          fontWeight: 700,
          color: '#1a1a2e',
          marginBottom: 16
        }}
      >
        Single Sign On Integration
      </div>
      {savedConfig.sso_status === 'active' && (
        <div style={{
          background: '#f6ffed',
          border: '1px solid #b7eb8f',
          borderRadius: 6,
          padding: '8px 16px',
          marginBottom: 20,
          fontSize: 13,
          color: '#389e0d',
        }}>
          <strong>SSO Active:</strong> Microsoft Entra SSO is configured. Users can sign in with their Microsoft accounts.
        </div>
      )}

      {/* SSO CONFIG */}
      <div
        style={{
          border: '1px solid #f0f0f0',
          borderRadius: 8,
          padding: '16px',
          marginBottom: 20
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            marginBottom: 16
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span
              id="sso-config-title"
              style={{ fontSize: 14, fontWeight: 600, color: '#1a1a2e' }}
            >
              SSO Configuration
            </span>
            <Tooltip title="Read-only view of your active SSO configuration">
              <InfoCircleOutlined style={{ color: '#0073E6', fontSize: 14 }} />
            </Tooltip>
          </div>
          <StatusBadge status={savedConfig.sso_status} />
        </div>
        <Row gutter={[24, 12]}>
          <Col span={12}>
            <div style={metaLabel}>Protocol</div>
            <div style={metaValue}>
              {savedConfig.protocol?.toUpperCase() || '—'}
            </div>
          </Col>
          {savedConfig.protocol === 'oidc' && (
            <>
              <Col span={12}>
                <div style={metaLabel}>Tenant ID</div>
                <div style={{ ...metaValue, fontSize: 12 }}>
                  {savedConfig.tenant_id || '—'}
                </div>
              </Col>
              <Col span={12}>
                <div style={metaLabel}>Client ID</div>
                <div style={{ ...metaValue, fontSize: 12 }}>
                  {savedConfig.client_id || '—'}
                </div>
              </Col>
            </>
          )}
          {savedConfig.protocol === 'saml' && (
            <Col span={12}>
              <div style={metaLabel}>IdP SSO URL</div>
              <div style={{ ...metaValue, fontSize: 12 }}>
                {savedConfig.sso_url || '—'}
              </div>
            </Col>
          )}
          <Col span={12}>
            <div style={metaLabel}>Verified Domains</div>
            <div style={metaValue}>{savedConfig.entra_domain || '—'}</div>
          </Col>
          <Col span={12}>
            <div style={metaLabel}>JIT Provisioning</div>
            <div style={metaValue}>
              {savedConfig.jitEnabled ? 'Enabled' : 'Disabled'}
            </div>
          </Col>
          <Col span={12}>
            <div style={metaLabel}>Last Validated</div>
            <div style={metaValue}>
              Today,{' '}
              {savedConfig.savedAt.toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit'
              })}
            </div>
          </Col>
        </Row>
      </div>

      {/* ACTION BUTTONS */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'flex-end',
          alignItems: 'center',
          gap: 12,
          marginBottom: 20
        }}
      >
        {canManageSSO ? (
          <Button
            id="Edit-SSO"
            onClick={onEdit}
            size="small"
            style={{ borderRadius: 6, borderColor: '#0073E6', color: '#0073E6' }}
          >
            Edit Configuration
          </Button>
        ) : (
          <PermissionRestricted type="customButton" title="Edit Configuration" />
        )}
        {canManageSSO ? (
          <Button
            id="Deactivate-SSO"
            size="small"
            onClick={onDeactivate}
            disabled={savedConfig?.sso_status === 'inactive'}
            style={{
              borderRadius: 6,
              borderColor: savedConfig?.sso_status === 'inactive' ? '#d9d9d9' : '#0073E6',
              color: savedConfig?.sso_status === 'inactive' ? '#bfbfbf' : '#0073E6',
              backgroundColor: savedConfig?.sso_status === 'inactive' ? '#f5f5f5' : '#fff',
            }}
          >
            Deactivate SSO
          </Button>
        ) : (
          <PermissionRestricted type="customButton" title="Deactivate SSO" />
        )}
        {canManageSSO ? (
          <Button
            id="remove-SSO"
            danger
            size="small"
            onClick={handleRemoveClick}
            style={{ borderRadius: 6 }}
          >
            Remove SSO & JIT
          </Button>
        ) : (
          <PermissionRestricted
            type="customButton"
            tooltipPlacement="top"
            title="Remove SSO & JIT"
          />
        )}
      </div>

      {/* ROLE MAPPINGS */}
      {savedConfig.jitEnabled && savedConfig.jitMappings?.length > 0 && (
        <div
          style={{
            border: '1px solid #f0f0f0',
            borderRadius: 8,
            padding: '16px',
            marginBottom: 20
          }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              marginBottom: 16
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span
                id="role-mappings-title"
                style={{ fontSize: 14, fontWeight: 600, color: '#1a1a2e' }}
              >
                Role Mappings
              </span>
              <Tooltip title="JIT role mapping rules">
                <InfoCircleOutlined style={{ color: '#0073E6', fontSize: 14 }} />
              </Tooltip>
            </div>
            {!editingJit && (
              canManageSSO ? (
                <Button
                  id="jit-manage-roles"
                  size="small"
                  style={{
                    backgroundColor: '#0073E6',
                    borderColor: '#0073E6',
                    color: '#fff',
                    borderRadius: 6,
                    fontWeight: 500
                  }}
                  onClick={() => {
                    resetMappings(savedConfig.jitMappings || []);
                    setEditingJit(true);
                  }}
                >
                  Manage roles
                </Button>
              ) : (
                <PermissionRestricted
                  type="customButton"
                  tooltipPlacement="top"
                  title="Manage roles"
                />
              )
            )}
          </div>

          <Row style={{ marginBottom: 8 }}>
            {['Role', 'Claim Name', 'Claim Value'].map((h, i) => (
              <Col key={h} span={i === 3 ? 4 : 6}>
                <span style={{ fontSize: 12, fontWeight: 500, color: '#8c8c8c' }}>
                  {h}
                </span>
              </Col>
            ))}
          </Row>

          {(editingJit ? jitMappings : savedConfig.jitMappings).map((m, i) => (
            <Row
              key={m.id}
              style={{
                padding: '8px 0',
                borderTop: '1px solid #f5f5f5',
                alignItems: 'flex-start'
              }}
            >
              <Col span={6}>
                {editingJit ? (
                  <div>
                    <Select
                      id={`role-select-${i + 1}`}
                      value={m.zdna_role}
                      onChange={(v) => updateMapping(i, 'zdna_role', v)}
                      style={{ width: '100%' }}
                      status={mappingErrors[i] ? 'error' : ''}
                    >
                      {roleData.map((r) => (
                        <Option key={r.value} value={r.value}>{r.label}</Option>
                      ))}
                    </Select>
                    {mappingErrors[i] && (
                      <div style={{ color: '#ff4d4f', fontSize: 11, marginTop: 2 }}>
                        {mappingErrors[i]}
                      </div>
                    )}
                  </div>
                ) : (
                  <span id={`role-value-${i + 1}`}>{m.zdna_role || '—'}</span>
                )}
              </Col>
              <Col span={6}>
                {editingJit ? (
                  <Input
                    id={`claim-name-input-${i + 1}`}
                    value={m.mapping_source}
                    status={mappingErrors[i] ? 'error' : ''}
                    onChange={(e) => updateMapping(i, 'mapping_source', e.target.value)}
                  />
                ) : (
                  <span id={`claim-name-value-${i + 1}`}>{m.mapping_source || '—'}</span>
                )}
              </Col>
              <Col span={6}>
                {editingJit ? (
                  <Input
                    id={`claim-value-input-${i + 1}`}
                    value={m.mapping_value}
                    status={mappingErrors[i] ? 'error' : ''}
                    onChange={(e) => updateMapping(i, 'mapping_value', e.target.value)}
                  />
                ) : (
                  <span id={`claim-value-display-${i + 1}`}>{m.mapping_value || '—'}</span>
                )}
              </Col>
              <Col span={4} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {editingJit && (
                  <Button
                    id={`remove-role-btn-${i + 1}`}
                    type="text"
                    onClick={() => removeMapping(i)}
                    style={{ color: '#ff4d4f', fontSize: 16 }}
                  >
                    ✕
                  </Button>
                )}
              </Col>
            </Row>
          ))}

          {editingJit && (
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginTop: 16
              }}
            >
              <Button
                id="add-role-btn"
                onClick={addMapping}
                style={{ borderColor: '#0073E6', color: '#0073E6', borderRadius: 6 }}
              >
                + Add Role
              </Button>
              <div style={{ display: 'flex', gap: 8 }}>
                <Button
                  id="edit-jit-cancel"
                  onClick={() => {
                    resetMappings(savedConfig.jitMappings);
                    setEditingJit(false);
                  }}
                >
                  Cancel
                </Button>
                <Button
                  id="edit-jit-save"
                  type="primary"
                  loading={saving}
                  disabled={!isJitValid(true) || saving}
                  onClick={async () => {
                    // Await the parent update so the button keeps its spinner
                    // until the save resolves — closing the editor first left
                    // the slowest path in the page with no feedback at all.
                    await onSaveJitMappings(
                      jitMappings.map((row, index) => ({
                        ...row,
                        order: index + 1
                      }))
                    );
                    setEditingJit(false);
                  }}
                >
                  Save
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
};

ActiveConfigView.propTypes = {
  onEdit: PropTypes.func.isRequired,
  onDeactivate: PropTypes.func.isRequired,
  onRemove: PropTypes.func.isRequired,
  onSaveJitMappings: PropTypes.func.isRequired,
  saving: PropTypes.bool,
  savedConfig: PropTypes.shape({
    sso_status: PropTypes.string,
    protocol: PropTypes.string,
    tenant_id: PropTypes.string,
    client_id: PropTypes.string,
    sso_url: PropTypes.string,
    entra_domain: PropTypes.oneOfType([
      PropTypes.string,
      PropTypes.array,
    ]),
    jitEnabled: PropTypes.bool,
    hasCert: PropTypes.bool,
    certNames: PropTypes.object,
    savedAt: PropTypes.instanceOf(Date),
    jitMappings: PropTypes.arrayOf(
      PropTypes.shape({
        id: PropTypes.oneOfType([
          PropTypes.string,
          PropTypes.number,
        ]),
        zdna_role: PropTypes.string,
        mapping_source: PropTypes.string,
        mapping_value: PropTypes.string,
      })
    ),
  }).isRequired,
};

export default ActiveConfigView;
