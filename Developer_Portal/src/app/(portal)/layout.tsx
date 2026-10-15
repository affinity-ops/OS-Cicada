// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState, createContext, useContext } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

interface Contact { id: string; name: string; email: string; avatar_url: string; }
interface Tenant  { id: string; name: string; plan: string; status: string; }
interface Session { contact: Contact; tenant: Tenant; token: string; }

export const SessionContext = createContext<Session | null>(null);
export const useSession = () => useContext(SessionContext);

const NAV = [
  {
    heading: 'OVERVIEW',
    items: [
      { label: 'Dashboard',    href: '/dashboard',          icon: 'space_dashboard' },
    ],
  },
  {
    heading: 'AGENTS',
    items: [
      { label: 'Registry',     href: '/agents',             icon: 'smart_toy' },
      { label: 'Register New', href: '/agents/register',    icon: 'add_circle' },
      { label: 'Marketplace',  href: '/marketplace',        icon: 'storefront' },
    ],
  },
  {
    heading: 'BUILD',
    items: [
      { label: 'Scaffold Agent', href: '/scaffold',         icon: 'construction' },
      { label: 'Policy Simulator', href: '/simulator',      icon: 'science' },
    ],
  },
  {
    heading: 'TRAFFIC',
    items: [
      { label: 'Outbound',     href: '/traffic/outbound',   icon: 'call_made' },
      { label: 'Inbound',      href: '/traffic/inbound',    icon: 'call_received' },
    ],
  },
  {
    heading: 'HISTORY',
    items: [
      { label: 'Transactions', href: '/transactions',       icon: 'receipt_long' },
    ],
  },
  {
    heading: 'SECURITY & DEPLOYMENT',
    items: [
      { label: 'Mobile Aegis', href: '/aegis',              icon: 'security' },
      { label: 'Enterprise Gateway', href: '/enterprise/deploy', icon: 'dns' },
    ],
  },
  {
    heading: 'ACCOUNT',
    items: [
      { label: 'Company',      href: '/account/company',    icon: 'business' },
      { label: 'Billing',      href: '/account/billing',    icon: 'credit_card' },
    ],
  },
];

export default function PortalLayout({ children }: { children: React.ReactNode }) {
  const router   = useRouter();
  const pathname = usePathname();
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('cicada_token');
    if (!token) { router.replace('/login'); return; }

    fetch(`${CORE_API}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(({ data }) => {
        setSession({ contact: data.contact, tenant: data.tenant, token });
        setLoading(false);
      })
      .catch(() => {
        localStorage.clear();
        router.replace('/login');
      });
  }, [router]);

  function logout() {
    const token = localStorage.getItem('cicada_token');
    fetch(`${CORE_API}/api/v1/auth/logout`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
    localStorage.clear();
    router.replace('/login');
  }

  if (loading) return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="w-10 h-10 border-2 border-primary border-t-transparent rounded-full animate-spin" />
    </div>
  );

  const planColour: Record<string, string> = {
    starter:      'text-gray-400',
    professional: 'text-primary',
    enterprise:   'text-purple-400',
  };

  return (
    <SessionContext.Provider value={session}>
      <div className="min-h-screen flex bg-background text-on-surface">

        {/* Sidebar */}
        <aside className="w-60 flex-shrink-0 flex flex-col border-r border-[rgba(255,159,74,0.10)] bg-[#0a0a0a]">

          {/* Logo */}
          <div className="px-6 py-5 border-b border-[rgba(255,159,74,0.10)]">
            <span className="text-xl font-black tracking-tighter text-primary font-headline">CICADA</span>
            <p className="text-[9px] font-technical text-on-surface-muted uppercase tracking-widest mt-0.5">Developer Portal</p>
          </div>

          {/* Nav */}
          <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
            {NAV.map(group => (
              <div key={group.heading}>
                <p className="text-[9px] font-technical text-on-surface-muted uppercase tracking-widest px-3 mb-1">{group.heading}</p>
                {group.items.map(item => {
                  const active = pathname === item.href || pathname.startsWith(item.href + '/');
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-headline transition-colors ${
                        active
                          ? 'bg-primary/10 text-primary'
                          : 'text-on-surface-muted hover:text-on-surface hover:bg-white/5'
                      }`}
                    >
                      <span className="material-symbols-outlined text-[18px]">{item.icon}</span>
                      {item.label}
                    </Link>
                  );
                })}
              </div>
            ))}
          </nav>

          {/* User panel */}
          <div className="px-4 py-4 border-t border-[rgba(255,159,74,0.10)]">
            <div className="flex items-center gap-3 mb-3">
              {session?.contact.avatar_url
                ? <img src={session.contact.avatar_url} className="w-8 h-8 rounded-full" alt="" />
                : <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary text-xs font-bold">{session?.contact.name[0]}</div>
              }
              <div className="min-w-0">
                <p className="text-xs font-headline font-bold truncate">{session?.contact.name}</p>
                <p className={`text-[10px] font-technical uppercase ${planColour[session?.tenant.plan ?? 'starter']}`}>{session?.tenant.plan}</p>
              </div>
            </div>
            <button
              onClick={logout}
              className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-on-surface-muted hover:text-on-surface hover:bg-white/5 transition-colors font-technical"
            >
              <span className="material-symbols-outlined text-[16px]">logout</span>
              Sign out
            </button>
          </div>
        </aside>

        {/* Main */}
        <main className="flex-1 overflow-auto">
          {children}
        </main>

      </div>
    </SessionContext.Provider>
  );
}
