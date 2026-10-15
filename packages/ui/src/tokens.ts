// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @cicada/ui — Shared Design Tokens
 *
 * Central design token definitions for the Cicada platform.
 * All apps should reference these tokens for visual consistency.
 *
 * Usage:
 *   import { colors, fonts, spacing } from '@cicada/ui/tokens';
 */

/** Cicada brand colour palette */
export const colors = {
  /** Primary brand orange — used for CTAs, links, active states */
  primary: '#ff9f4a',
  /** Primary hover state */
  primaryHover: '#ffb66e',
  /** Primary muted — used for borders, subtle backgrounds */
  primaryMuted: 'rgba(255, 159, 74, 0.15)',
  /** Primary border — low-opacity orange for card borders */
  primaryBorder: 'rgba(255, 159, 74, 0.20)',

  /** App background */
  bgApp: '#0a0a0a',
  /** Card / surface background */
  bgSurface: '#1a1a1a',
  /** Elevated surface (modals, dropdowns) */
  bgElevated: '#222222',
  /** Sidebar background */
  bgSidebar: '#111111',

  /** Primary text */
  textPrimary: '#f5f5f5',
  /** Secondary text (labels, descriptions) */
  textSecondary: '#a3a3a3',
  /** Muted text (timestamps, hints) */
  textMuted: '#737373',

  /** Success / healthy */
  success: '#22c55e',
  /** Warning */
  warning: '#eab308',
  /** Error / critical */
  error: '#ef4444',
  /** Error muted border */
  errorBorder: 'rgba(239, 68, 68, 0.30)',
  /** Error muted shadow */
  errorShadow: 'rgba(239, 68, 68, 0.10)',

  /** Info / neutral accent */
  info: '#3b82f6',
} as const;

/** Typography families */
export const fonts = {
  /** Display / heading font */
  display: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
  /** Body / reading font */
  body: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
  /** Monospace / technical font */
  mono: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
} as const;

/** Spacing scale (px values as numbers for calculations, string values for CSS) */
export const spacing = {
  xs: '4px',
  sm: '8px',
  md: '16px',
  lg: '24px',
  xl: '32px',
  '2xl': '48px',
  '3xl': '64px',
} as const;

/** Border radius scale */
export const radii = {
  sm: '6px',
  md: '8px',
  lg: '12px',
  xl: '16px',
  full: '9999px',
} as const;

/** Shadow presets */
export const shadows = {
  /** Subtle card shadow */
  card: '0 1px 3px rgba(0, 0, 0, 0.3)',
  /** Elevated surface shadow */
  elevated: '0 4px 12px rgba(0, 0, 0, 0.4)',
  /** Primary glow — used for active/focus states */
  primaryGlow: '0 0 20px rgba(255, 159, 74, 0.15)',
  /** Error glow */
  errorGlow: '0 0 20px rgba(239, 68, 68, 0.15)',
} as const;

/** Z-index scale */
export const zIndex = {
  sidebar: 40,
  overlay: 50,
  modal: 60,
  toast: 9999,
} as const;
