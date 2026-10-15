// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

export default function Sidebar() {
  const pathname = usePathname();

  const adminNavItems = [
    { name: 'Gateway Fleet', path: '/', icon: 'router' },
    { name: 'Mesh Topology', path: '/mesh', icon: 'hub' },
    { name: 'Threat Intel', path: '/intel', icon: 'shield' },
    { name: 'License Minting', path: '/licenses', icon: 'key' },
  ];

  const handleLogout = () => {
    document.cookie = 'cicada_master_session=; path=/; max-age=0';
    window.location.href = '/login';
  };

  return (
    <aside className="w-64 bg-surface/60 backdrop-blur-xl border-r border-border flex flex-col h-full shrink-0 shadow-[4px_0_24px_rgba(0,0,0,0.5)] z-50 rounded-r-2xl">
      <div className="p-6 border-b border-border">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-8 h-8 bg-gradient-to-br from-primary to-primary-dark rounded-lg flex items-center justify-center shadow-[0_0_15px_rgba(255,159,74,0.3)]">
            <span className="material-symbols-outlined text-background text-lg">admin_panel_settings</span>
          </div>
          <span className="font-black font-headline text-xl tracking-tighter text-white uppercase">CICADA</span>
        </div>
        <div className="text-[10px] text-primary/70 font-technical tracking-[0.2em] uppercase mt-2">Master Admin</div>
      </div>

      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        <div className="text-[10px] text-on-surface-muted/50 font-technical tracking-[0.2em] uppercase px-4 py-2">Operations</div>
        {adminNavItems.map((item) => {
          const isActive = pathname === item.path;
          return (
            <Link
              key={item.name}
              href={item.path}
              className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 group ${
                isActive 
                  ? 'bg-primary/20 text-primary border-l-4 border-primary shadow-inner font-bold' 
                  : 'text-on-surface-muted hover:bg-white/5 hover:text-primary border-l-4 border-transparent'
              }`}
            >
              <span className={`material-symbols-outlined text-[18px] transition-transform duration-200 ${isActive ? 'scale-110' : 'group-hover:scale-110'}`}>{item.icon}</span>
              <span className="text-sm font-headline font-medium">{item.name}</span>
            </Link>
          );
        })}
      </nav>

      <div className="p-4 border-t border-border bg-surface/30">
        <div className="flex items-center gap-3 px-4 py-3 bg-background/50 rounded-xl border border-white/5 shadow-inner mb-3">
          <img className="w-8 h-8 rounded-full border border-primary/30 flex-shrink-0" alt="Vendor Ops" src="https://ui-avatars.com/api/?name=Vendor+Ops&background=FF8A00&color=fff" onError={(e) => { e.currentTarget.style.display = 'none'; }} />
          <div>
            <div className="text-sm font-bold text-on-surface font-headline">Vendor Operator</div>
            <div className="text-[10px] text-primary/70 font-technical uppercase tracking-widest">SysAdmin</div>
          </div>
        </div>
        
        <button 
          onClick={handleLogout}
          className="w-full flex items-center justify-center gap-2 px-4 py-2 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg transition-colors text-sm font-bold"
        >
          <span className="material-symbols-outlined text-[18px]">logout</span>
          Secure Logout
        </button>
      </div>
    </aside>
  );
}
