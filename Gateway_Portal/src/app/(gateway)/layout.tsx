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
    heading: 'COMMAND',
    items: [
      { label: 'Overview',          href: '/overview',   icon: 'space_dashboard' },
      { label: 'Gateway Health',    href: '/health',     icon: 'monitor_heart' },
    ],
  },
  {
    heading: 'TRAFFIC',
    items: [
      { label: 'Inbound Agents',    href: '/inbound',    icon: 'call_received' },
      { label: 'Agent Flow',        href: '/flow',       icon: 'account_tree' },
      { label: 'Outbound Agents',   href: '/outbound',   icon: 'call_made' },
    ],
  },
  {
    heading: 'SECURITY',
    items: [
      { label: 'Threat Intelligence', href: '/threats',  icon: 'security' },
      { label: 'Policy Management',   href: '/policy',   icon: 'policy' },
      { label: 'CIBA Approvals',      href: '/ciba',     icon: 'verified_user' },
      { label: 'Identity Federation', href: '/federation', icon: 'passkey' },
      { label: 'Revocation Webhooks', href: '/revocation', icon: 'webhook' },
    ],
  },
  {
    heading: 'REGISTRY',
    items: [
      { label: 'Certified Agents',  href: '/registry',   icon: 'verified' },
    ],
  },
  {
    heading: 'ACCOUNT',
    items: [
      { label: 'Licence & Company', href: '/account',    icon: 'business' },
    ],
  },
];

export default function GatewayLayout({ children }: { children: React.ReactNode }) {
  const router   = useRouter();
  const pathname = usePathname();
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('cicada_gw_token');
    if (!token) { router.replace('/login'); return; }

    fetch(`${CORE_API}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(({ data }) => { setSession({ contact: data.contact, tenant: data.tenant, token }); setLoading(false); })
      .catch(() => { localStorage.clear(); router.replace('/login'); });
  }, [router]);

  function logout() {
    const token = localStorage.getItem('cicada_gw_token');
    fetch(`${CORE_API}/api/v1/auth/logout`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
    localStorage.clear();
    router.replace('/login');
  }

  if (loading) return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="w-10 h-10 border-2 border-primary border-t-transparent rounded-full animate-spin" />
    </div>
  );

  return (
    <SessionContext.Provider value={session}>
      <div className="min-h-screen flex bg-background text-on-surface">

        <aside className="w-60 flex-shrink-0 flex flex-col border-r border-[rgba(255,159,74,0.10)] bg-[#0a0a0a]">

          <div className="px-6 py-5 border-b border-[rgba(255,159,74,0.10)]">
            <span className="text-xl font-black tracking-tighter text-primary font-headline">CICADA</span>
            <p className="text-[9px] font-technical text-on-surface-muted uppercase tracking-widest mt-0.5">Gateway Portal</p>
          </div>

          {/* Gateway status indicator */}
          <div className="mx-3 mt-3 px-3 py-2 bg-green-500/10 border border-green-500/20 rounded-lg flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse flex-shrink-0" />
            <span className="text-[10px] font-technical text-green-400 uppercase tracking-widest">Gateway Online</span>
          </div>

          <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
            {NAV.map(group => (
              <div key={group.heading}>
                <p className="text-[9px] font-technical text-on-surface-muted uppercase tracking-widest px-3 mb-1">{group.heading}</p>
                {group.items.map(item => {
                  const active = pathname === item.href || pathname.startsWith(item.href + '/');
                  return (
                    <Link key={item.href} href={item.href}
                      className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-headline transition-colors ${
                        active ? 'bg-primary/10 text-primary' : 'text-on-surface-muted hover:text-on-surface hover:bg-white/5'
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

          <div className="px-4 py-4 border-t border-[rgba(255,159,74,0.10)]">
            <div className="flex items-center gap-3 mb-3">
              {session?.contact.avatar_url
                ? <img src={session.contact.avatar_url} className="w-8 h-8 rounded-full" alt="" />
                : <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary text-xs font-bold">{session?.contact.name[0]}</div>
              }
              <div className="min-w-0">
                <p className="text-xs font-headline font-bold truncate">{session?.contact.name}</p>
                <p className="text-[10px] font-technical text-on-surface-muted truncate">{session?.tenant.name}</p>
              </div>
            </div>
            <button onClick={logout}
              className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-on-surface-muted hover:text-on-surface hover:bg-white/5 transition-colors font-technical"
            >
              <span className="material-symbols-outlined text-[16px]">logout</span>
              Sign out
            </button>
          </div>
        </aside>

        <main className="flex-1 overflow-auto">{children}</main>
      </div>
    </SessionContext.Provider>
  );
}
