// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

export const Sidebar: React.FC = () => {
  const pathname = usePathname();
  const [isCollapsed, setIsCollapsed] = useState(false);
  const devPortalUrl = process.env.NEXT_PUBLIC_DEV_PORTAL_URL ?? 'http://localhost:3001';
  const [agentAdminOpen, setAgentAdminOpen] = useState(
    pathname.startsWith('/agent-admin')
  );

  useEffect(() => {
    document.documentElement.style.setProperty('--sidebar-width', isCollapsed ? '6rem' : '18rem');
  }, [isCollapsed]);

  const getLinkClasses = (path: string) => {
    const isActive = pathname === path || (path === '/architecture' && pathname === '/');
    let base = "flex items-center rounded-xl transition-all duration-200 group relative cursor-pointer ";

    if (isCollapsed) {
      base += "justify-center py-3 w-12 mx-auto ";
    } else {
      base += "gap-4 px-4 py-3 min-w-full ";
    }

    if (isActive) {
      return base + "bg-orange-500/20 text-orange-400 border-r-4 border-orange-500 font-bold";
    }
    return base + "text-neutral-500 hover:bg-white/5 hover:text-orange-300";
  };

  return (
    <aside className="fixed left-0 top-0 h-full flex flex-col py-6 bg-neutral-900/60 backdrop-blur-xl rounded-r-2xl border-r border-orange-500/10 z-50 transition-all duration-300" style={{ width: 'var(--sidebar-width, 18rem)' }}>

      <button
        onClick={() => setIsCollapsed(!isCollapsed)}
        className="absolute -right-3 top-10 bg-surface-container-highest border border-white/10 w-6 h-6 rounded-full flex items-center justify-center text-neutral-400 hover:text-primary z-50 transition-colors"
      >
        <span className="material-symbols-outlined text-[14px]">
          {isCollapsed ? 'chevron_right' : 'chevron_left'}
        </span>
      </button>

      <div className={`mb-10 px-6 flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} transition-all`}>
        <img src="/cicada-logo.png" alt="Cicada Logo" className="h-10 w-auto rounded-lg border border-orange-500/20 shadow-lg shadow-orange-500/10 object-contain flex-shrink-0" />
        {!isCollapsed && (
          <div className="overflow-hidden whitespace-nowrap">
            <span className="text-2xl font-black tracking-tighter text-orange-500 uppercase font-headline">CICADA</span>
            <p className="text-[10px] font-technical text-on-surface-variant/60 tracking-widest uppercase">Admin Panel</p>
          </div>
        )}
      </div>

      <nav className={`flex-1 space-y-2 overflow-y-auto pb-4 ${isCollapsed ? 'px-2' : 'px-6'}`}>
        <Link href="/" className={getLinkClasses('/architecture')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="architecture">architecture</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Global Overview</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Global Overview</div>}
        </Link>
        <Link href="/ztna-posture" className={getLinkClasses('/ztna-posture')}>
          <span className="material-symbols-outlined flex-shrink-0 text-cyan-400" data-icon="shield">shield</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap text-cyan-400">ZTNA Posture</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-cyan-500/10 text-cyan-400 border-cyan-500/20 text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border z-50">ZTNA Posture</div>}
        </Link>
        <Link href="/compute" className={getLinkClasses('/compute')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="security">security</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Security Monitor</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Security Monitor</div>}
        </Link>
        <Link href="/pipeline" className={getLinkClasses('/pipeline')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="manage_search">manage_search</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Live Call Inspector</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Live Call Inspector</div>}
        </Link>
        <Link href="/nodes" className={getLinkClasses('/nodes')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="smart_toy">smart_toy</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Agent Fleet</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Agent Fleet</div>}
        </Link>
        <Link href="/security" className={getLinkClasses('/security')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="security">security</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Security Policies</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Security Policies</div>}
        </Link>
        <Link href="/registry" className={getLinkClasses('/registry')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="verified_user">verified_user</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Agent Registry</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Agent Registry</div>}
        </Link>
        <Link href="/vault" className={getLinkClasses('/vault')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="lock">lock</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Credential Vault</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Credential Vault</div>}
        </Link>
        <Link href="/logs" className={getLinkClasses('/logs')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="terminal">terminal</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Activity Ledger</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Activity Ledger</div>}
        </Link>
        <Link href="/sagas" className={getLinkClasses('/sagas')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="undo">undo</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap text-orange-400">Action Rollbacks</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Action Rollbacks</div>}
        </Link>
        <Link href="/crm" className={getLinkClasses('/crm')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="groups">groups</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Client Companies</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Client Companies</div>}
        </Link>

        {/* ── Agent Admin ── */}
        {!isCollapsed && <p className="uppercase text-[#888] font-technical tracking-[0.2em] pt-4 pb-1 text-[10px]">Agent Admin</p>}
        <button
          onClick={() => setAgentAdminOpen(o => !o)}
          className={`flex items-center rounded-xl transition-all duration-200 w-full ${isCollapsed ? 'justify-center py-3 w-12 mx-auto' : 'gap-4 px-4 py-3'} ${pathname.startsWith('/agent-admin') ? 'bg-orange-500/20 text-orange-400 border-r-4 border-orange-500 font-bold' : 'text-neutral-500 hover:bg-white/5 hover:text-orange-300'}`}
        >
          <span className="material-symbols-outlined flex-shrink-0">admin_panel_settings</span>
          {!isCollapsed && <><span className="font-headline font-medium whitespace-nowrap flex-1 text-left">Agent Admin</span><span className="material-symbols-outlined text-[16px]">{agentAdminOpen ? 'expand_less' : 'expand_more'}</span></>}
        </button>
        {agentAdminOpen && !isCollapsed && (
          <div className="pl-4 space-y-1 border-l border-orange-500/20 ml-4">
            {[
              { href: '/agent-admin/biographies',  icon: 'manage_history',        label: 'Agent Biographies' },
              { href: '/agent-admin/hitl',         icon: 'pending_actions',       label: 'HITL Approval Queue' },
              { href: '/agent-admin/ciba',         icon: 'smartphone',            label: 'CIBA Pending Queue' },
              { href: '/agent-admin/rogue',        icon: 'gpp_bad',               label: 'Blocked Agents' },
              { href: '/agent-admin/operator-logs',icon: 'list_alt',              label: 'Operator Audit Logs' },
              { href: '/agent-admin/audit',        icon: 'receipt_long',          label: 'Compliance Export' },
              { href: '/agent-admin/alerts',       icon: 'notification_important', label: 'Alert Rules' },
              { href: '/agent-admin/retention',    icon: 'policy',                label: 'Data Retention' },
              { href: '/agent-admin/correlation',  icon: 'hub',                   label: 'Threat Correlation' },
              { href: '/agent-admin/baselines',    icon: 'insights',              label: 'Behaviour Baselines' },
            ].map(({ href, icon, label }) => (
              <Link key={href} href={href} className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all ${pathname === href ? 'bg-orange-500/20 text-orange-400 font-bold' : 'text-neutral-500 hover:bg-white/5 hover:text-orange-300'}`}>
                <span className="material-symbols-outlined text-[16px] flex-shrink-0">{icon}</span>
                <span className="font-headline font-medium whitespace-nowrap">{label}</span>
              </Link>
            ))}
          </div>
        )}

        <Link href="/aegis" className={getLinkClasses('/aegis')}>
          <span className="material-symbols-outlined flex-shrink-0 text-blue-500" data-icon="trip_origin">trip_origin</span>
          {!isCollapsed && <span className="font-headline font-black whitespace-nowrap text-blue-500">Aegis AI Assistant</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-blue-500/10 text-blue-400 border-blue-500/20 text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border z-50">Aegis AI Assistant</div>}
        </Link>
        <Link href="/sandbox" className={getLinkClasses('/sandbox')}>
          <span className="material-symbols-outlined flex-shrink-0 text-purple-500" data-icon="grid_goldenratio">grid_goldenratio</span>
          {!isCollapsed && <span className="font-headline font-black whitespace-nowrap text-purple-500">Shadow Sandbox</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-purple-500/10 text-purple-400 border-purple-500/20 text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border z-50">Shadow Sandbox</div>}
        </Link>
      </nav>

      <div className={`mt-auto space-y-6 ${isCollapsed ? 'px-2' : 'px-6'} transition-all`}>

        <Link href="/help" className={`flex items-center rounded-xl transition-all duration-200 group relative cursor-pointer pt-4 border-t border-white/5 ${isCollapsed ? 'justify-center py-3 w-12 mx-auto' : 'gap-4 px-4 min-w-full hover:bg-white/5'}`}>
          <span className="material-symbols-outlined flex-shrink-0 text-neutral-500 group-hover:text-primary transition-colors" data-icon="menu_book">menu_book</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap text-neutral-500 group-hover:text-primary transition-colors">Help &amp; Manual</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Help &amp; Manual</div>}
        </Link>

        {!isCollapsed ? (
            <a href={`${devPortalUrl}/scaffold`} target="_blank" rel="noopener noreferrer" className="w-full py-4 text-center flex items-center justify-center gap-2 bg-gradient-to-br from-primary to-primary-container text-on-primary rounded-xl font-headline font-bold text-sm tracking-tight hover:brightness-110 active:scale-95 transition-all shadow-lg shadow-primary/10 whitespace-nowrap">
                Register Agent
                <span className="material-symbols-outlined text-[14px] opacity-60">open_in_new</span>
            </a>
        ) : (
            <a href={`${devPortalUrl}/scaffold`} target="_blank" rel="noopener noreferrer" className="mx-auto w-12 h-12 flex items-center justify-center bg-gradient-to-br from-primary to-primary-container text-on-primary rounded-xl hover:brightness-110 active:scale-95 transition-all shadow-lg shadow-primary/10">
                <span className="material-symbols-outlined flex-shrink-0 text-[20px]">add</span>
            </a>
        )}
        <h3 className={`uppercase text-[#888] font-technical tracking-[0.2em] mt-8 mb-4 ${isCollapsed ? 'opacity-0 h-0 hidden' : 'opacity-100'}`}>SECURITY</h3>
        <Link href="/discovery" className={getLinkClasses('/discovery')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="radar">radar</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Shadow Agent Radar</span>}
          {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Shadow Agent Radar</div>}
        </Link>
        <div className={`flex items-center ${isCollapsed ? 'justify-center' : 'gap-3 justify-between'} px-2 mt-4`}>
            <div className={`flex items-center ${isCollapsed ? '' : 'gap-3'}`}>
              <img className="w-10 h-10 rounded-full border border-orange-500/30 flex-shrink-0" alt="Operator" src="https://ui-avatars.com/api/?name=System+Operator&background=FF8A00&color=fff" onError={(e) => { e.currentTarget.style.display = 'none'; }} />
              {!isCollapsed && (
                <div className="overflow-hidden whitespace-nowrap">
                    <p className="text-sm font-bold text-on-surface font-headline">System Operator</p>
                    <p className="text-[10px] font-technical text-orange-500/70 uppercase">Admin</p>
                </div>
              )}
            </div>
            <button
              onClick={() => {
                document.cookie = 'operator_session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
                window.location.href = '/login';
              }}
              title="Sign Out"
              className={`group relative flex items-center justify-center rounded-lg transition-all duration-200 text-neutral-500 hover:text-red-400 hover:bg-red-500/10 ${isCollapsed ? 'w-10 h-10 mt-2' : 'w-9 h-9 flex-shrink-0'}`}
            >
              <span className="material-symbols-outlined text-[18px]">logout</span>
              {isCollapsed && <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-red-400 text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">Sign Out</div>}
            </button>
        </div>
      </div>
    </aside>
  );
};
