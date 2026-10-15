// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests for the SecureInput component — the zero-visibility KMS injection input.
// Tests cover: rendering, binding flow, error states, and DOM cleansing.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

// Mock lucide-react icons since the package isn't installed as a prod dependency.
vi.mock('lucide-react', () => ({
  Lock: (props: Record<string, unknown>) => <svg data-testid="lock-icon" {...props} />,
  AlertCircle: (props: Record<string, unknown>) => <svg data-testid="alert-icon" {...props} />,
  CheckCircle2: (props: Record<string, unknown>) => <svg data-testid="check-icon" {...props} />,
}));

// Must import SecureInput AFTER mocking lucide-react
import { SecureInput } from '@/components/SecureInput';

describe('SecureInput', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // Reset the global fetch mock for each test
    global.fetch = vi.fn();
  });

  // ── Basic rendering ─────────────────────────────────────────────────────
  it('renders the label', () => {
    render(<SecureInput label="OpenAI Key" provider="OpenAI" tenantId="org_123" />);
    expect(screen.getByText('OpenAI Key')).toBeInTheDocument();
  });

  it('renders the KMS description', () => {
    render(<SecureInput label="Test Key" provider="Anthropic" tenantId="org_123" />);
    expect(screen.getByText('Zero-Visibility KMS Injection')).toBeInTheDocument();
  });

  it('renders the password input with correct placeholder', () => {
    render(<SecureInput label="Test" provider="OpenAI" tenantId="org_123" />);
    const input = screen.getByPlaceholderText('paste-openai-secret-key...');
    expect(input).toBeInTheDocument();
    expect(input).toHaveAttribute('type', 'password');
    expect(input).toHaveAttribute('autocomplete', 'off');
  });

  it('renders provider-specific placeholder text', () => {
    render(<SecureInput label="Test" provider="Anthropic" tenantId="org_123" />);
    expect(screen.getByPlaceholderText('paste-anthropic-secret-key...')).toBeInTheDocument();
  });

  it('renders Bind to Vault button in idle state', () => {
    render(<SecureInput label="Test" provider="OpenAI" tenantId="org_123" />);
    expect(screen.getByText('Bind to Vault')).toBeInTheDocument();
  });

  it('renders the lock icon', () => {
    render(<SecureInput label="Test" provider="OpenAI" tenantId="org_123" />);
    expect(screen.getByTestId('lock-icon')).toBeInTheDocument();
  });

  // ── Binding success flow ──────────────────────────────────────────────
  it('shows success state after successful binding', async () => {
    global.fetch = vi.fn(() =>
      Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as Response)
    );

    render(<SecureInput label="Test" provider="OpenAI" tenantId="org_123" />);

    // Type a key into the input
    const input = screen.getByPlaceholderText('paste-openai-secret-key...') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'sk-test-key-12345' } });

    // Click bind
    fireEvent.click(screen.getByText('Bind to Vault'));

    await waitFor(() => {
      expect(screen.getByText('[SUCCESS] CiphertextBlob generated. Plain text destroyed.')).toBeInTheDocument();
    });
  });

  it('clears the input after binding attempt', async () => {
    global.fetch = vi.fn(() =>
      Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as Response)
    );

    render(<SecureInput label="Test" provider="OpenAI" tenantId="org_123" />);
    const input = screen.getByPlaceholderText('paste-openai-secret-key...') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'sk-secret' } });
    fireEvent.click(screen.getByText('Bind to Vault'));

    await waitFor(() => {
      expect(input.value).toBe('');
    });
  });

  // ── Error handling ────────────────────────────────────────────────────
  it('shows error state when binding fails', async () => {
    global.fetch = vi.fn(() =>
      Promise.resolve({ ok: false } as Response)
    );

    render(<SecureInput label="Test" provider="OpenAI" tenantId="org_123" />);
    const input = screen.getByPlaceholderText('paste-openai-secret-key...');
    fireEvent.change(input, { target: { value: 'bad-key' } });
    fireEvent.click(screen.getByText('Bind to Vault'));

    await waitFor(() => {
      expect(screen.getByText('[ERROR] Verification swarm rejected key binding.')).toBeInTheDocument();
    });
  });

  it('shows error when network request fails', async () => {
    global.fetch = vi.fn(() => Promise.reject(new Error('Network error')));

    render(<SecureInput label="Test" provider="OpenAI" tenantId="org_123" />);
    const input = screen.getByPlaceholderText('paste-openai-secret-key...');
    fireEvent.change(input, { target: { value: 'sk-test' } });
    fireEvent.click(screen.getByText('Bind to Vault'));

    await waitFor(() => {
      expect(screen.getByText('[ERROR] Verification swarm rejected key binding.')).toBeInTheDocument();
    });
  });

  // ── No-op when empty ──────────────────────────────────────────────────
  it('does nothing when input is empty', () => {
    render(<SecureInput label="Test" provider="OpenAI" tenantId="org_123" />);
    fireEvent.click(screen.getByText('Bind to Vault'));
    
    // Should remain in idle state — no fetch called
    expect(global.fetch).not.toHaveBeenCalled();
    expect(screen.getByText('Bind to Vault')).toBeInTheDocument();
  });
});
