/**
 * TestConnectionPanel — presentational only.
 * Stack: React 16 + @testing-library/react v12 + jest-dom v5.
 */

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import TestConnectionPanel from './TestConnectionPanel';

const setup = (props = {}) =>
  render(
    <TestConnectionPanel
      isTestReady={false}
      testLoading={false}
      testResult={null}
      onTest={jest.fn()}
      {...props}
    />
  );

describe('TestConnectionPanel — button state', () => {
  test('is disabled and shows the "fill the fields" hint when not ready', () => {
    setup({ isTestReady: false });
    expect(screen.getByRole('button', { name: /test connection/i })).toBeDisabled();
    expect(screen.getByText('Fill all required fields to enable test')).toBeInTheDocument();
  });

  test('is enabled and shows the "click to verify" hint when ready', () => {
    setup({ isTestReady: true });
    expect(screen.getByRole('button', { name: /test connection/i })).toBeEnabled();
    expect(screen.getByText('Click to verify your configuration')).toBeInTheDocument();
  });

  test('stays disabled while loading, even when ready', () => {
    setup({ isTestReady: true, testLoading: true });
    expect(screen.getByRole('button', { name: /test connection/i })).toBeDisabled();
  });

  test('calls onTest when clicked', () => {
    const onTest = jest.fn();
    setup({ isTestReady: true, onTest });
    fireEvent.click(screen.getByRole('button', { name: /test connection/i }));
    expect(onTest).toHaveBeenCalledTimes(1);
  });

  test('does not call onTest when disabled', () => {
    const onTest = jest.fn();
    setup({ isTestReady: false, onTest });
    fireEvent.click(screen.getByRole('button', { name: /test connection/i }));
    expect(onTest).not.toHaveBeenCalled();
  });
});

describe('TestConnectionPanel — result display', () => {
  test('hides the helper text while loading', () => {
    setup({ isTestReady: true, testLoading: true });
    expect(screen.queryByText('Click to verify your configuration')).not.toBeInTheDocument();
  });

  test('replaces the helper text with a passing result', () => {
    setup({ isTestReady: true, testResult: { status: 'passed', message: 'Test Connection successful' } });
    expect(screen.queryByText(/Click to verify/)).not.toBeInTheDocument();
    const result = screen.getByText(/Test Connection successful/);
    expect(result).toBeInTheDocument();
    expect(result).toHaveTextContent('✓');
    expect(result).toHaveStyle({ color: '#36B37E' });
  });

  test('renders a failing result in the error colour with a cross', () => {
    setup({ isTestReady: true, testResult: { status: 'failed', message: 'Invalid client secret' } });
    const result = screen.getByText(/Invalid client secret/);
    expect(result).toHaveTextContent('✗');
    expect(result).toHaveStyle({ color: '#ff4d4f' });
  });

  test('treats any non-passed status as a failure', () => {
    setup({ testResult: { status: 'error', message: 'Something else' } });
    expect(screen.getByText(/Something else/)).toHaveTextContent('✗');
  });
});
