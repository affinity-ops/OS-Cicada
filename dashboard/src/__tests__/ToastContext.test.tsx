// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests for the ToastContext — the global notification system.
// Tests cover: provider rendering, showToast trigger, auto-dismiss, and hook safety.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { ToastProvider, useToast } from '@/components/ToastContext';

// Helper component that triggers the toast via the hook.
function ToastTrigger({ message }: { message: string }) {
  const { showToast } = useToast();
  return <button onClick={() => showToast(message)}>Show Toast</button>;
}

describe('ToastContext', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('renders children without toast initially', () => {
    render(
      <ToastProvider>
        <p>Dashboard</p>
      </ToastProvider>
    );
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
  });

  it('displays a toast message when showToast is called', () => {
    render(
      <ToastProvider>
        <ToastTrigger message="Key rotated successfully." />
      </ToastProvider>
    );

    act(() => {
      screen.getByText('Show Toast').click();
    });

    expect(screen.getByText('Key rotated successfully.')).toBeInTheDocument();
  });

  it('auto-dismisses the toast after 3 seconds', () => {
    render(
      <ToastProvider>
        <ToastTrigger message="Auto-dismiss test" />
      </ToastProvider>
    );

    act(() => {
      screen.getByText('Show Toast').click();
    });
    expect(screen.getByText('Auto-dismiss test')).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(3000);
    });
    expect(screen.queryByText('Auto-dismiss test')).not.toBeInTheDocument();
  });

  it('throws when useToast is used outside ToastProvider', () => {
    // Suppress error output for this intentional error test
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => {
      render(<ToastTrigger message="should throw" />);
    }).toThrow('useToast must be used within ToastProvider');

    spy.mockRestore();
  });

  it('replaces existing toast with new message', () => {
    function MultiToast() {
      const { showToast } = useToast();
      return (
        <div>
          <button onClick={() => showToast('Message A')}>Trigger A</button>
          <button onClick={() => showToast('Message B')}>Trigger B</button>
        </div>
      );
    }

    render(
      <ToastProvider>
        <MultiToast />
      </ToastProvider>
    );

    act(() => {
      screen.getByText('Trigger A').click();
    });
    expect(screen.getByText('Message A')).toBeInTheDocument();

    act(() => {
      screen.getByText('Trigger B').click();
    });
    // The new toast should replace the old one
    expect(screen.getByText('Message B')).toBeInTheDocument();
    expect(screen.queryByText('Message A')).not.toBeInTheDocument();
  });
});
