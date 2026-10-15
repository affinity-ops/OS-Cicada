// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests for the KPICard component — the most reused dashboard component.
// Tests cover: rendering, color variants, progress bars, link wrapping, and edge cases.
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { KPICard, KPICardProps } from '@/components/KPICard';

const defaultProps: KPICardProps = {
  title: 'Active Agents',
  value: 42,
  trendText: '+12.5%',
  trendIcon: 'trending_up',
  colorVariant: 'primary',
  progressPercentage: 75,
};

describe('KPICard', () => {
  it('renders the title and value', () => {
    render(<KPICard {...defaultProps} />);
    expect(screen.getByText('Active Agents')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
  });

  it('displays the trend text', () => {
    render(<KPICard {...defaultProps} />);
    expect(screen.getByText('+12.5%')).toBeInTheDocument();
  });

  it('renders the trend icon', () => {
    render(<KPICard {...defaultProps} />);
    expect(screen.getByText('trending_up')).toBeInTheDocument();
  });

  it('renders the progress bar with correct width', () => {
    const { container } = render(<KPICard {...defaultProps} />);
    const bar = container.querySelector('[style*="width: 75%"]');
    expect(bar).toBeTruthy();
  });

  it('accepts a string value', () => {
    render(<KPICard {...defaultProps} value="$1,234" />);
    expect(screen.getByText('$1,234')).toBeInTheDocument();
  });

  it('wraps content in a link when href is provided', () => {
    render(<KPICard {...defaultProps} href="/registry" />);
    const link = screen.getByRole('link');
    expect(link).toHaveAttribute('href', '/registry');
  });

  it('does not render a link when href is absent', () => {
    render(<KPICard {...defaultProps} />);
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  // ── Color variant rendering ─────────────────────────────────────────────
  it.each(['primary', 'secondary', 'error', 'tertiary'] as const)(
    'renders %s variant without errors',
    (variant) => {
      const { container } = render(
        <KPICard {...defaultProps} colorVariant={variant} />
      );
      expect(container.firstChild).toBeTruthy();
    }
  );

  it('handles zero progress gracefully', () => {
    const { container } = render(
      <KPICard {...defaultProps} progressPercentage={0} />
    );
    const bar = container.querySelector('[style*="width: 0%"]');
    expect(bar).toBeTruthy();
  });

  it('handles 100% progress', () => {
    const { container } = render(
      <KPICard {...defaultProps} progressPercentage={100} />
    );
    const bar = container.querySelector('[style*="width: 100%"]');
    expect(bar).toBeTruthy();
  });
});
