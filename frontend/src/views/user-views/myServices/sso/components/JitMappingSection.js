import React, { useContext,useState,useEffect } from 'react';
import { Row, Col, Input, Button, Switch, Tooltip, Select } from 'antd';
import { InfoCircleOutlined } from '@ant-design/icons';
import { getTenantId } from 'auth/FirebaseAuth'
import { getRoleConfig } from '../../../../../firebase/fireStore/roleManagementDBMethods'
import { AuthContext } from 'auth/AuthProvider'
import PropTypes from 'prop-types';


const { Option } = Select;
const sectionLabel = { fontSize: 15, fontWeight: 600, color: '#1a1a2e' };

const JitMappingSection = ({
  jitEnabled,
  onJitToggle,
  jitMappings,
  onUpdateMapping,
  onAddMapping,
  onRemoveMapping,
  mappingErrors,
  disabled,
}) => {
  const context = useContext(AuthContext);
  const tenantId = getTenantId(context?.currentUser);
  const [roleData, setRoleData] = useState([]);

  useEffect(() => {
    getRoleConfig(tenantId).then((resData) => {
      const arr = resData.roleNames.map((ele) => ({ value: ele, label: ele }));
      setRoleData(arr);
    });
  }, [tenantId]);

  return (
    <div style={{ marginBottom: 4 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
        <span style={sectionLabel}>
          JIT Provisioning &amp; Role Mapping{' '}
          <span style={{ color: '#ff4d4f', marginLeft: 2 }}>*</span>
        </span>
        <Tooltip title="Just-in-Time provisioning automatically creates user accounts on first SSO login">
          <InfoCircleOutlined style={{ color: '#0073E6', fontSize: 16, cursor: 'pointer' }} />
        </Tooltip>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <span style={{ fontSize: 14, fontWeight: 400, color: '#595959' }}>
          Enable Just-in-Time (JIT) Provisioning
        </span>
        <Switch checked={jitEnabled} onChange={onJitToggle} disabled={disabled}/>
      </div>

      {jitEnabled && (
        <>
          <Row gutter={8} style={{ marginBottom: 6, background: "white !important"  }} >
            <Col span={8}><span id="jit-role-header" style={{ fontSize: 12, color: '#595959', fontWeight: 500 ,background: "white" }}>Role</span></Col>
            <Col span={7}><span id="jit-claim-name-header" style={{ fontSize: 12, color: '#595959', fontWeight: 500,background: "white" }}>Claim Name</span></Col>
            <Col span={7}><span id="jit-claim-value-header" style={{ fontSize: 12, color: '#595959', fontWeight: 500 ,background: "white"}}>Claim Value</span></Col>
            <Col span={2} />
          </Row>

          {jitMappings.map((row, idx) => {
            const rowError = mappingErrors?.[idx];
            return (
              <div key={row.id} id={`jit-mapping-row-${idx}`}>
                <Row gutter={8} style={{ marginBottom: rowError ? 2 : 8, alignItems: 'center' ,background: "white"}}>
                  <Col span={8}>
                    <Select
                      placeholder="Select role"
                      id={`role-select-${idx+1}`}
                      value={row.zdna_role || undefined}
                      onChange={v => onUpdateMapping(idx, 'zdna_role', v)}
                      style={{ width: '100%' }}
                      status={rowError ? 'error' : ''}
                    >
                      {roleData.map(r => (
                        <Option
                          key={r.value}
                          value={r.value}
                        >
                          {r.label}
                        </Option>
                      ))}
                    </Select>
                  </Col>
                  <Col span={7}>
                    <Input
                      id={`claim-name-${idx+1}`}
                      placeholder="Claim name"
                      value={row.mapping_source}
                      onChange={e => onUpdateMapping(idx, 'mapping_source', e.target.value)}
                      style={{ borderColor: rowError ? '#ff4d4f' : undefined ,background: "white"}}
                    />
                  </Col>
                  <Col span={7}>
                    <Input
                      id={`claim-value-${idx+1}`}
                      placeholder="Value"
                      value={row.mapping_value}
                      onChange={e => onUpdateMapping(idx, 'mapping_value', e.target.value)}
                      style={{ borderColor: rowError ? '#ff4d4f' : undefined,background: "white" }}
                    />
                  </Col>
                  <Col span={2} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    {jitMappings.length > 1 && (
                      <Button
                        id='jit-mapping-remove-btn-active-view'
                        type="text"
                        onClick={() => onRemoveMapping(idx)}
                        style={{ color: '#ff4d4f', padding: 0, minWidth: 'unset', lineHeight: 1 }}
                      >✕</Button>
                    )}
                  </Col>
                </Row>
                {rowError && (
                  <div style={{ fontSize: 11, color: '#ff4d4f', marginBottom: 6, paddingLeft: 2 }}>
                    {rowError}
                  </div>
                )}
              </div>
            );
          })}

          <Button
            id='Add-role-btn-mapping-section'
            onClick={onAddMapping}
            style={{ borderColor: '#0073E6', color: '#0073E6', borderRadius: 6, marginTop: 4 }}
          >
            Add Role
          </Button>
        </>
      )}
    </div>
  );
};


JitMappingSection.propTypes = {
  jitEnabled: PropTypes.bool.isRequired,
  onJitToggle: PropTypes.func.isRequired,
  onUpdateMapping: PropTypes.func.isRequired,
  onAddMapping: PropTypes.func.isRequired,
  onRemoveMapping: PropTypes.func.isRequired,
  disabled: PropTypes.bool,
  jitMappings: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
      zdna_role: PropTypes.string,
      mapping_source: PropTypes.string,
      mapping_value: PropTypes.string,
    })
  ).isRequired,
  mappingErrors: PropTypes.oneOfType([
    PropTypes.array,
    PropTypes.object,
  ]),
};


export default JitMappingSection;
