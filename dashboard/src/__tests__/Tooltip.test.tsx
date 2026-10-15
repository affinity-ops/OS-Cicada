// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests for the Tooltip component — universal context hover system.
// Tests cover: rendering, visibility on hover, warning mode, and content display.
import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Tooltip } from '@/components/Tooltip';

describe('Tooltip', () => {
  it('renders children', () => {
    render(
      <Tooltip content="Help text">
        <button>Hover Me</button>
      </Tooltip>
    );
    expect(screen.getByText('Hover Me')).toBeInTheDocument();
  });

  it('does not show tooltip content initially', () => {
    render(
      <Tooltip content="Help text">
        <button>Hover Me</button>
      </Tooltip>
    );
    expect(screen.queryByText('Help text')).not.toBeInTheDocument();
  });

  it('shows tooltip content on mouse enter', () => {
    render(
      <Tooltip content="Help text">
        <button>Hover Me</button>
      </Tooltip>
    );

    // Find the wrapper div (parent of the button)
    const wrapper = screen.getByText('Hover Me').closest('div');
    expect(wrapper).toBeTruthy();
    fireEvent.mouseEnter(wrapper!);
    expect(screen.getByText('Help text')).toBeInTheDocument();
  });

  it('hides tooltip content on mouse leave', () => {
    render(
      <Tooltip content="Help text">
        <button>Hover Me</button>
      </Tooltip>
    );

    const wrapper = screen.getByText('Hover Me').closest('div');
    fireEvent.mouseEnter(wrapper!);
    expect(screen.getByText('Help text')).toBeInTheDocument();

    fireEvent.mouseLeave(wrapper!);
    expect(screen.queryByText('Help text')).not.toBeInTheDocument();
  });

  it('renders in warning mode with distinct styling', () => {
    render(
      <Tooltip content="Danger zone" warning>
        <span>⚠️</span>
      </Tooltip>
    );

    const wrapper = screen.getByText('⚠️').closest('div');
    fireEvent.mouseEnter(wrapper!);

    const tooltip = screen.getByText('Danger zone');
    expect(tooltip.className).toContain('error');
  });

  it('renders in default mode without warning styling', () => {
    render(
      <Tooltip content="Normal help">
        <span>ℹ️</span>
      </Tooltip>
    );

    const wrapper = screen.getByText('ℹ️').closest('div');
    fireEvent.mouseEnter(wrapper!);

    const tooltip = screen.getByText('Normal help');
    expect(tooltip.className).not.toContain('error');
  });
});
