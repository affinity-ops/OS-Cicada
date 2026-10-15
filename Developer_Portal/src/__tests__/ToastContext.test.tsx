// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests for the Developer Portal ToastContext — supports info and error types.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { ToastProvider, useToast } from '@/components/ToastContext';

function ToastTrigger({ message, type }: { message: string; type?: 'info' | 'error' }) {
  const { showToast } = useToast();
  return <button onClick={() => showToast(message, type)}>Show Toast</button>;
}

describe('Portal ToastContext', () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it('renders children without toast initially', () => {
    render(
      <ToastProvider>
        <p>Portal Content</p>
      </ToastProvider>
    );
    expect(screen.getByText('Portal Content')).toBeInTheDocument();
  });

  it('displays an info toast', () => {
    render(
      <ToastProvider>
        <ToastTrigger message="Agent registered" />
      </ToastProvider>
    );

    act(() => {
      screen.getByText('Show Toast').click();
    });
    expect(screen.getByText('Agent registered')).toBeInTheDocument();
  });

  it('displays an error toast with distinct styling', () => {
    render(
      <ToastProvider>
        <ToastTrigger message="Registration failed" type="error" />
      </ToastProvider>
    );

    act(() => {
      screen.getByText('Show Toast').click();
    });

    const toast = screen.getByText('Registration failed');
    expect(toast).toBeInTheDocument();
    // Error toast parent should have red border styling
    const container = toast.closest('div[class*="fixed"]');
    expect(container?.className).toContain('red');
  });

  it('auto-dismisses after 3 seconds', () => {
    render(
      <ToastProvider>
        <ToastTrigger message="Temporary" />
      </ToastProvider>
    );

    act(() => { screen.getByText('Show Toast').click(); });
    expect(screen.getByText('Temporary')).toBeInTheDocument();

    act(() => { vi.advanceTimersByTime(3000); });
    expect(screen.queryByText('Temporary')).not.toBeInTheDocument();
  });

  it('throws when useToast is used outside ToastProvider', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => {
      render(<ToastTrigger message="should throw" />);
    }).toThrow('useToast must be used within ToastProvider');
    spy.mockRestore();
  });

  it('replaces current toast with new message', () => {
    function MultiToast() {
      const { showToast } = useToast();
      return (
        <div>
          <button onClick={() => showToast('Alpha Toast')}>Alpha</button>
          <button onClick={() => showToast('Beta Toast')}>Beta</button>
        </div>
      );
    }

    render(
      <ToastProvider>
        <MultiToast />
      </ToastProvider>
    );

    act(() => { screen.getByText('Alpha').click(); });
    expect(screen.getByText('Alpha Toast')).toBeInTheDocument();

    act(() => { screen.getByText('Beta').click(); });
    expect(screen.getByText('Beta Toast')).toBeInTheDocument();
    expect(screen.queryByText('Alpha Toast')).not.toBeInTheDocument();
  });
});
