// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

export const Sidebar: React.FC = () => {
  const pathname = usePathname();
  const [isCollapsed, setIsCollapsed] = useState(false);

  useEffect(() => {
    document.documentElement.style.setProperty('--sidebar-width', isCollapsed ? '6rem' : '18rem');
  }, [isCollapsed]);

  const getLinkClasses = (path: string) => {
    const isActive = pathname === path;
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

  const Tooltip = ({ label }: { label: string }) => (
    <div className="absolute left-full ml-4 px-2 py-1 bg-[#262626] text-white text-xs font-technical rounded opacity-0 invisible group-hover:visible group-hover:opacity-100 transition-all whitespace-nowrap border border-white/10 z-50">
      {label}
    </div>
  );

  return (
    <aside
      className="fixed left-0 top-0 h-full flex flex-col py-6 bg-neutral-900/60 backdrop-blur-xl rounded-r-2xl border-r border-orange-500/10 z-50 transition-all duration-300"
      style={{ width: 'var(--sidebar-width, 18rem)' }}
    >
      {/* Toggle */}
      <button
        onClick={() => setIsCollapsed(!isCollapsed)}
        className="absolute -right-3 top-10 bg-surface-container-highest border border-white/10 w-6 h-6 rounded-full flex items-center justify-center text-neutral-400 hover:text-primary z-50 transition-colors"
      >
        <span className="material-symbols-outlined text-[14px]">
          {isCollapsed ? 'chevron_right' : 'chevron_left'}
        </span>
      </button>

      {/* Brand */}
      <div className={`mb-10 px-6 flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} transition-all`}>
        <img
          src="/cicada-logo.png"
          alt="Cicada Logo"
          className="h-10 w-auto rounded-lg border border-orange-500/20 shadow-lg shadow-orange-500/10 object-contain flex-shrink-0"
        />
        {!isCollapsed && (
          <div className="overflow-hidden whitespace-nowrap">
            <span className="text-2xl font-black tracking-tighter text-orange-500 uppercase font-headline">CICADA</span>
            <p className="text-[10px] font-technical text-on-surface-variant/60 tracking-widest uppercase">Developer Portal</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className={`flex-1 space-y-2 ${isCollapsed ? 'px-2' : 'px-6'}`}>
        {!isCollapsed && (
          <h3 className="uppercase text-[#888] font-technical tracking-[0.2em] mb-4 text-[10px]">My Agents</h3>
        )}

        <Link href="/onboarding" className={getLinkClasses('/onboarding')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="add_circle">add_circle</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Provision Agent</span>}
          {isCollapsed && <Tooltip label="Provision Agent" />}
        </Link>

        <Link href="/billing" className={getLinkClasses('/billing')}>
          <span className="material-symbols-outlined flex-shrink-0" data-icon="credit_card">credit_card</span>
          {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap">Billing &amp; Quotas</span>}
          {isCollapsed && <Tooltip label="Billing & Quotas" />}
        </Link>
        
        <div className="pt-4 mt-4 border-t border-white/5">
          <Link href="/enterprise/deploy" className={getLinkClasses('/enterprise/deploy')}>
            <span className="material-symbols-outlined flex-shrink-0 text-orange-400" data-icon="dns">dns</span>
            {!isCollapsed && <span className="font-headline font-medium whitespace-nowrap text-orange-400">Enterprise Gateway</span>}
            {isCollapsed && <Tooltip label="Enterprise Gateway" />}
          </Link>
        </div>
      </nav>

      {/* Footer */}
      <div className={`mt-auto space-y-4 ${isCollapsed ? 'px-2' : 'px-6'}`}>
        <div className={`flex items-center ${isCollapsed ? 'justify-center' : 'gap-3'} px-2 mt-4`}>
          <div className="w-10 h-10 rounded-full border border-orange-500/30 flex-shrink-0 bg-orange-500/10 flex items-center justify-center">
            <span className="material-symbols-outlined text-orange-500 text-[18px]">person</span>
          </div>
          {!isCollapsed && (
            <div className="overflow-hidden whitespace-nowrap">
              <p className="text-sm font-bold text-on-surface font-headline">Developer</p>
              <p className="text-[10px] font-technical text-orange-500/70 uppercase">API Access</p>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
};
