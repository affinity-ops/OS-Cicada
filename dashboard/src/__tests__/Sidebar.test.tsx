// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests for the Sidebar component — the primary navigation for the Operator Dashboard.
// Tests cover: rendering, navigation links, collapse toggle, agent admin submenu, and CTA.
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Sidebar } from '@/components/Sidebar';

describe('Sidebar', () => {
  // ── Basic rendering ─────────────────────────────────────────────────────
  it('renders the CICADA brand', () => {
    render(<Sidebar />);
    expect(screen.getByText('CICADA')).toBeInTheDocument();
  });

  it('renders the Admin Panel subtitle', () => {
    render(<Sidebar />);
    expect(screen.getByText('Admin Panel')).toBeInTheDocument();
  });

  it('renders the operator profile', () => {
    render(<Sidebar />);
    expect(screen.getByText('System Operator')).toBeInTheDocument();
    expect(screen.getByText('Admin')).toBeInTheDocument();
  });

  // ── Navigation links ─────────────────────────────────────────────────────
  const expectedLinks = [
    { label: 'Global Overview', href: '/' },
    { label: 'Security Monitor', href: '/compute' },
    { label: 'Live Call Inspector', href: '/pipeline' },
    { label: 'Agent Fleet', href: '/nodes' },
    { label: 'Security Policies', href: '/security' },
    { label: 'Agent Registry', href: '/registry' },
    { label: 'Credential Vault', href: '/vault' },
    { label: 'Activity Ledger', href: '/logs' },
    { label: 'Action Rollbacks', href: '/sagas' },
    { label: 'Client Companies', href: '/crm' },
    { label: 'Aegis AI Assistant', href: '/aegis' },
    { label: 'Shadow Sandbox', href: '/sandbox' },
    { label: 'Shadow Agent Radar', href: '/discovery' },
  ];

  it.each(expectedLinks)(
    'renders "$label" link pointing to $href',
    ({ label, href }) => {
      render(<Sidebar />);
      const link = screen.getByText(label).closest('a');
      expect(link).toBeTruthy();
      expect(link).toHaveAttribute('href', href);
    }
  );

  it('renders the Register Agent CTA linking to Developer Portal', () => {
    render(<Sidebar />);
    const cta = screen.getByText('Register Agent');
    expect(cta).toBeInTheDocument();
    expect(cta.closest('a')).toHaveAttribute('href', 'http://localhost:3001/scaffold');
    expect(cta.closest('a')).toHaveAttribute('target', '_blank');
  });

  // ── Collapse toggle ───────────────────────────────────────────────────
  it('hides navigation labels when collapsed', () => {
    render(<Sidebar />);
    
    // Find and click the collapse button (the one with chevron_left icon)
    const collapseButton = screen.getByText('chevron_left').closest('button');
    expect(collapseButton).toBeTruthy();
    fireEvent.click(collapseButton!);

    // In collapsed mode, the expanded-mode span labels are removed from DOM.
    // However, tooltip divs with the same text remain (but are CSS-hidden).
    // We verify by checking that the brand text 'CICADA' is removed.
    expect(screen.queryByText('CICADA')).not.toBeInTheDocument();
    expect(screen.queryByText('Admin Panel')).not.toBeInTheDocument();
    // The nav labels still exist as tooltip divs — that's correct behaviour.
  });

  it('shows chevron_right icon when collapsed', () => {
    render(<Sidebar />);
    
    const collapseButton = screen.getByText('chevron_left').closest('button');
    fireEvent.click(collapseButton!);

    expect(screen.getByText('chevron_right')).toBeInTheDocument();
  });

  it('restores labels when expanded after collapse', () => {
    render(<Sidebar />);
    
    const collapseButton = screen.getByText('chevron_left').closest('button');
    // Collapse — CICADA brand text disappears
    fireEvent.click(collapseButton!);
    expect(screen.queryByText('CICADA')).not.toBeInTheDocument();

    // Expand — CICADA brand text reappears
    const expandButton = screen.getByText('chevron_right').closest('button');
    fireEvent.click(expandButton!);
    expect(screen.getByText('CICADA')).toBeInTheDocument();
    expect(screen.getByText('Admin Panel')).toBeInTheDocument();
  });

  // ── Agent Admin submenu ───────────────────────────────────────────────
  it('toggles the Agent Admin submenu on click', () => {
    render(<Sidebar />);
    
    // Initially, submenu items should not be visible (pathname is '/', not '/agent-admin')
    expect(screen.queryByText('Agent Biographies')).not.toBeInTheDocument();

    // Click the Agent Admin button — use getAllByText since 'Agent Admin' appears
    // both as the section header <p> and the button <span>.
    const adminButtons = screen.getAllByText('Agent Admin');
    const adminButton = adminButtons.map(el => el.closest('button')).find(Boolean);
    expect(adminButton).toBeTruthy();
    fireEvent.click(adminButton!);

    // Submenu items should now be visible
    expect(screen.getByText('Agent Biographies')).toBeInTheDocument();
    expect(screen.getByText('HITL Approval Queue')).toBeInTheDocument();
    expect(screen.getByText('Blocked Agents')).toBeInTheDocument();
    expect(screen.getByText('Operator Audit Logs')).toBeInTheDocument();
    expect(screen.getByText('Compliance Export')).toBeInTheDocument();
    expect(screen.getByText('Alert Rules')).toBeInTheDocument();
    expect(screen.getByText('Data Retention')).toBeInTheDocument();
    expect(screen.getByText('Threat Correlation')).toBeInTheDocument();
    expect(screen.getByText('Behaviour Baselines')).toBeInTheDocument();
  });

  it('hides submenu when Agent Admin is clicked again', () => {
    render(<Sidebar />);
    
    const adminButtons = screen.getAllByText('Agent Admin');
    const adminButton = adminButtons.map(el => el.closest('button')).find(Boolean);
    
    // Open
    fireEvent.click(adminButton!);
    expect(screen.getByText('Agent Biographies')).toBeInTheDocument();

    // Close
    fireEvent.click(adminButton!);
    expect(screen.queryByText('Agent Biographies')).not.toBeInTheDocument();
  });

  // ── Help link ─────────────────────────────────────────────────────────
  it('renders the Help & Manual link', () => {
    render(<Sidebar />);
    // The text uses &amp; in HTML, but React renders it as &
    const helpLink = screen.getByText('Help & Manual');
    expect(helpLink).toBeInTheDocument();
    expect(helpLink.closest('a')).toHaveAttribute('href', '/help');
  });

  // ── Security section header ───────────────────────────────────────────
  it('renders the SECURITY section header', () => {
    render(<Sidebar />);
    expect(screen.getByText('SECURITY')).toBeInTheDocument();
  });
});
