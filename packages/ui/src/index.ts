// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @cicada/ui — Shared UI Components & Design Tokens
 *
 * This package provides the canonical implementations of shared React
 * components and design tokens used across all Cicada frontend applications
 * (Operator Dashboard, Developer Portal, Gateway Portal, Landing Page).
 *
 * Components are exported as source TypeScript — no build step required.
 * Each Next.js app adds @cicada/ui to its transpilePackages config.
 */

// ── Design Tokens ──
export { colors, fonts, spacing, radii, shadows, zIndex } from './tokens';

// ── Components ──
export { ToastProvider, useToast } from './components/ToastContext';
export type { ToastType } from './components/ToastContext';
