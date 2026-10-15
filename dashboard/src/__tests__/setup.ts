// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Test setup file — extends Vitest with jest-dom matchers and provides
// common mocks for Next.js features (useRouter, useSearchParams, Link).
import '@testing-library/jest-dom/vitest';
import { vi } from 'vitest';

// ── Next.js Router mock ─────────────────────────────────────────────────────
// Next.js App Router hooks are not available outside the Next.js runtime.
// We mock them globally so all component tests can render without errors.
vi.mock('next/navigation', () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    back: vi.fn(),
    refresh: vi.fn(),
    prefetch: vi.fn(),
  }),
  useSearchParams: () => ({
    get: vi.fn(() => null),
    getAll: vi.fn(() => []),
    has: vi.fn(() => false),
    toString: vi.fn(() => ''),
  }),
  usePathname: () => '/',
}));

// ── Next.js Link mock ───────────────────────────────────────────────────────
// Replaces Next.js Link with a plain <a> tag for testing.
vi.mock('next/link', () => ({
  default: ({ children, href, ...props }: { children: React.ReactNode; href: string; [key: string]: unknown }) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const React = require('react');
    return React.createElement('a', { href, ...props }, children);
  },
}));

// ── operatorFetch mock ──────────────────────────────────────────────────────
// Mock the authenticated fetch wrapper used by dashboard components.
vi.mock('@/lib/operatorFetch', () => ({
  operatorFetch: vi.fn(() =>
    Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ status: 'success', data: {} }),
    })
  ),
}));

// ── Material Symbols mock ───────────────────────────────────────────────────
// Material Symbols are loaded via CSS font. In jsdom they render as text
// content, which is fine for testing — no mock needed.

// ── Environment variables ───────────────────────────────────────────────────
process.env.NEXT_PUBLIC_CORE_API_URL = 'http://localhost:8000';
