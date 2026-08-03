import React from 'react';
import { Button } from 'antd';
import PropTypes from 'prop-types'

const TestConnectionPanel = ({ isTestReady, testLoading, testResult, onTest }) => (
  <div style={{ marginTop: 8, marginBottom: 24 }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
      <Button
        loading={testLoading}
        disabled={!isTestReady || testLoading}
        onClick={onTest}
        style={{
          borderColor: isTestReady ? '#0073E6' : '#d9d9d9',
          color: isTestReady ? '#0073E6' : '#bfbfbf',
          borderRadius: 6,
          background: '#fff',
          fontWeight: 500,
          minWidth: 140,
          height: 36,
        }}
      >
        Test Connection
      </Button>

      {/* Show helper text only when no result yet */}
      {!testResult && !testLoading && (
        <span id="test-connection-helper-text" style={{ fontSize: 12, color: '#bfbfbf' }}>
          {isTestReady
            ? 'Click to verify your configuration'
            : 'Fill all required fields to enable test'}
        </span>
      )}
    </div>

    {/* Result shown here — replaces helper text */}
    {testResult && (
      <div id="test-connection-result" style={{
        marginTop: 10,
        fontSize: 13,
        fontWeight: 500,
        color: testResult.status === 'passed' ? '#36B37E' : '#ff4d4f',
      }}>
        {testResult.status === 'passed' ? '✓ ' : '✗ '}
        {testResult.message}
      </div>
    )}
  </div>
);

TestConnectionPanel.propTypes = {
  isTestReady: PropTypes.bool.isRequired,
  testLoading: PropTypes.bool.isRequired,
  onTest: PropTypes.func,
  testResult: PropTypes.shape({
    status: PropTypes.string,
    message: PropTypes.string,
  }),
};


export default TestConnectionPanel;
