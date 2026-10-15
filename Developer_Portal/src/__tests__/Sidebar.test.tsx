// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests for the Developer Portal Sidebar component.
// Covers: rendering, navigation links, collapse toggle, and user profile.
import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Sidebar } from '@/components/Sidebar';

describe('Portal Sidebar', () => {
  // ── Brand ─────────────────────────────────────────────────────────────
  it('renders the CICADA brand text', () => {
    render(<Sidebar />);
    expect(screen.getByText('CICADA')).toBeInTheDocument();
  });

  it('renders Developer Portal subtitle', () => {
    render(<Sidebar />);
    expect(screen.getByText('Developer Portal')).toBeInTheDocument();
  });

  // ── Navigation links ─────────────────────────────────────────────────
  const expectedLinks = [
    { label: 'Provision Agent', href: '/onboarding' },
    { label: 'Billing & Quotas', href: '/billing' },
  ];

  it.each(expectedLinks)(
    'renders "$label" link pointing to $href',
    ({ label, href }) => {
      render(<Sidebar />);
      // Use getAllByText since the tooltip text also exists in collapsed mode
      const elements = screen.getAllByText(label);
      const link = elements.map(el => el.closest('a')).find(Boolean);
      expect(link).toBeTruthy();
      expect(link).toHaveAttribute('href', href);
    }
  );

  it('renders the My Agents section header', () => {
    render(<Sidebar />);
    expect(screen.getByText('My Agents')).toBeInTheDocument();
  });

  // ── User profile ──────────────────────────────────────────────────────
  it('renders Developer profile in footer', () => {
    render(<Sidebar />);
    expect(screen.getByText('Developer')).toBeInTheDocument();
    expect(screen.getByText('API Access')).toBeInTheDocument();
  });

  // ── Collapse toggle ───────────────────────────────────────────────────
  it('starts in expanded mode with chevron_left', () => {
    render(<Sidebar />);
    expect(screen.getByText('chevron_left')).toBeInTheDocument();
  });

  it('hides brand text when collapsed', () => {
    render(<Sidebar />);

    const collapseButton = screen.getByText('chevron_left').closest('button');
    fireEvent.click(collapseButton!);

    // Brand text should be hidden in collapsed mode
    expect(screen.queryByText('CICADA')).not.toBeInTheDocument();
    expect(screen.queryByText('Developer Portal')).not.toBeInTheDocument();
  });

  it('shows chevron_right when collapsed', () => {
    render(<Sidebar />);

    const collapseButton = screen.getByText('chevron_left').closest('button');
    fireEvent.click(collapseButton!);

    expect(screen.getByText('chevron_right')).toBeInTheDocument();
  });

  it('restores brand when expanded after collapse', () => {
    render(<Sidebar />);

    const collapseButton = screen.getByText('chevron_left').closest('button');
    fireEvent.click(collapseButton!);
    expect(screen.queryByText('CICADA')).not.toBeInTheDocument();

    const expandButton = screen.getByText('chevron_right').closest('button');
    fireEvent.click(expandButton!);
    expect(screen.getByText('CICADA')).toBeInTheDocument();
  });

  // ── Cicada logo image ─────────────────────────────────────────────────
  it('renders the Cicada logo image', () => {
    render(<Sidebar />);
    const logo = screen.getByAltText('Cicada Logo');
    expect(logo).toBeInTheDocument();
    expect(logo).toHaveAttribute('src', '/cicada-logo.png');
  });
});
