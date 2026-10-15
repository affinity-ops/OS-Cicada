// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Test setup for the Developer Portal — extends Vitest with jest-dom matchers
// and provides global mocks for Next.js runtime, session context, and localStorage.
import '@testing-library/jest-dom/vitest';
import { vi } from 'vitest';

// ── Next.js Router mock ─────────────────────────────────────────────────────
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
vi.mock('next/link', () => ({
  default: ({ children, href, ...props }: { children: React.ReactNode; href: string; [key: string]: unknown }) => {
    const React = require('react');
    return React.createElement('a', { href, ...props }, children);
  },
}));

// ── localStorage mock ───────────────────────────────────────────────────────
const storage: Record<string, string> = {};
Object.defineProperty(window, 'localStorage', {
  value: {
    getItem: vi.fn((key: string) => storage[key] ?? null),
    setItem: vi.fn((key: string, val: string) => { storage[key] = val; }),
    removeItem: vi.fn((key: string) => { delete storage[key]; }),
    clear: vi.fn(() => { for (const k in storage) delete storage[k]; }),
    get length() { return Object.keys(storage).length; },
    key: vi.fn((i: number) => Object.keys(storage)[i] ?? null),
  },
  writable: true,
});

// ── Environment variables ───────────────────────────────────────────────────
process.env.NEXT_PUBLIC_CORE_API_URL = 'http://localhost:8000';
