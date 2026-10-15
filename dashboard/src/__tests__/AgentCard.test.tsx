// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests for the AgentCard component — the core element in the registry grid.
// Tests cover: rendering, trust tiers, status badges, scope tags, action stats, and callbacks.
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { AgentCard, AgentCardProps } from '@/components/AgentCard';

const defaultProps: AgentCardProps = {
  name: 'Invoice Processor',
  agentId: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  trustTier: 'elevated',
  trustScore: 82,
  status: 'Active',
  totalActions: 1500,
  blockedActions: 23,
  declaredScopes: ['read:invoices', 'write:payments', 'read:contacts'],
  lastSeen: '2026-05-09T14:00:00Z',
};

describe('AgentCard', () => {
  // ── Basic rendering ─────────────────────────────────────────────────────
  it('renders the agent name', () => {
    render(<AgentCard {...defaultProps} />);
    expect(screen.getByText('Invoice Processor')).toBeInTheDocument();
  });

  it('displays truncated agent ID in uppercase', () => {
    render(<AgentCard {...defaultProps} />);
    expect(screen.getByText('A1B2C3D4-E5F')).toBeInTheDocument();
  });

  it('shows the trust tier badge', () => {
    render(<AgentCard {...defaultProps} />);
    expect(screen.getByText('elevated')).toBeInTheDocument();
  });

  it('shows the trust score percentage', () => {
    render(<AgentCard {...defaultProps} />);
    expect(screen.getByText('82%')).toBeInTheDocument();
  });

  // ── Action statistics ─────────────────────────────────────────────────
  it('displays total actions', () => {
    render(<AgentCard {...defaultProps} />);
    expect(screen.getByText('1,500')).toBeInTheDocument();
  });

  it('computes allowed actions correctly', () => {
    render(<AgentCard {...defaultProps} />);
    // 1500 - 23 = 1477
    expect(screen.getByText('1,477')).toBeInTheDocument();
  });

  it('displays blocked actions', () => {
    render(<AgentCard {...defaultProps} />);
    expect(screen.getByText('23')).toBeInTheDocument();
  });

  it('computes block rate correctly', () => {
    render(<AgentCard {...defaultProps} />);
    // 23/1500 * 100 = 1.5%
    expect(screen.getByText('1.5% blocked')).toBeInTheDocument();
  });

  it('shows 0.0% blocked when no actions exist', () => {
    render(<AgentCard {...defaultProps} totalActions={0} blockedActions={0} />);
    expect(screen.getByText('0.0% blocked')).toBeInTheDocument();
  });

  // ── Scope rendering ───────────────────────────────────────────────────
  it('renders up to 3 scope tags', () => {
    render(<AgentCard {...defaultProps} />);
    expect(screen.getByText('read:invoices')).toBeInTheDocument();
    expect(screen.getByText('write:payments')).toBeInTheDocument();
    expect(screen.getByText('read:contacts')).toBeInTheDocument();
  });

  it('shows "+N more" when scopes exceed 3', () => {
    render(
      <AgentCard
        {...defaultProps}
        declaredScopes={['a', 'b', 'c', 'd', 'e']}
      />
    );
    expect(screen.getByText('+2 more')).toBeInTheDocument();
  });

  it('hides scope section when no scopes exist', () => {
    const { container } = render(
      <AgentCard {...defaultProps} declaredScopes={[]} />
    );
    // No scope tags should be rendered
    expect(container.querySelectorAll('[class*="flex-wrap"]')).toHaveLength(0);
  });

  // ── Trust tier themes ─────────────────────────────────────────────────
  it.each(['unverified', 'nominal', 'elevated', 'critical'] as const)(
    'renders %s tier without crashing',
    (tier) => {
      const { container } = render(
        <AgentCard {...defaultProps} trustTier={tier} />
      );
      expect(container.firstChild).toBeTruthy();
    }
  );

  // ── Revoked status ────────────────────────────────────────────────────
  it('shows revoked badge when status is Revoked', () => {
    render(<AgentCard {...defaultProps} status="Revoked" />);
    expect(screen.getByText('Revoked')).toBeInTheDocument();
  });

  it('does not show revoked badge when status is Active', () => {
    render(<AgentCard {...defaultProps} status="Active" />);
    // Only the tier badge should render, not a "Revoked" badge.
    const badges = screen.queryAllByText('Revoked');
    expect(badges).toHaveLength(0);
  });

  // ── Last seen ─────────────────────────────────────────────────────────
  it('renders the last seen date', () => {
    render(<AgentCard {...defaultProps} />);
    const dateStr = new Date('2026-05-09T14:00:00Z').toLocaleDateString();
    expect(screen.getByText(`Last seen ${dateStr}`)).toBeInTheDocument();
  });

  it('shows "Never" when lastSeen is empty', () => {
    render(<AgentCard {...defaultProps} lastSeen="" />);
    expect(screen.getByText('Last seen Never')).toBeInTheDocument();
  });

  // ── Interaction ───────────────────────────────────────────────────────
  it('calls onViewDetail when View Detail is clicked', () => {
    const handler = vi.fn();
    render(<AgentCard {...defaultProps} onViewDetail={handler} />);
    fireEvent.click(screen.getByText('View Detail'));
    expect(handler).toHaveBeenCalledOnce();
  });

  it('renders View Detail button even without handler', () => {
    render(<AgentCard {...defaultProps} />);
    expect(screen.getByText('View Detail')).toBeInTheDocument();
  });
});
