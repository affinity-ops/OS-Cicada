// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useToast } from './ToastContext';
import { operatorFetch } from '@/lib/operatorFetch';

interface AlertData {
  unread_count: number;
  alerts: { trace_id: string; action_type: string; tenant_name: string; agent_name: string; created_at: string }[];
}

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

export const TopAppBar: React.FC = () => {
  const router = useRouter();
  const pathname = usePathname();
  const [searchQuery, setSearchQuery] = useState('');
  const { showToast } = useToast();
  const [alertData, setAlertData] = useState<AlertData | null>(null);

  // ── Global CIBA Monitoring ──
  const [cibaPendingCount, setCibaPendingCount] = useState(0);
  // Use a ref (not state) for seen IDs to avoid re-render loops.
  // Previously, cibaSeenIds was useState + a useEffect dependency, which
  // caused an infinite loop: pollCiba → setCibaSeenIds (new Set) → React
  // sees new reference → re-runs useEffect → pollCiba → repeat forever.
  // A ref holds the value without triggering re-renders.
  const cibaSeenIdsRef = useRef<Set<string>>(new Set());
  const [sirenMuted, setSirenMuted] = useState(false);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const oscillatorRef = useRef<OscillatorNode | null>(null);
  const isOnCibaPage = pathname === '/agent-admin/ciba';

  const stopSiren = useCallback(() => {
    if (oscillatorRef.current) {
      try { oscillatorRef.current.stop(); } catch {}
      oscillatorRef.current = null;
    }
    if (audioCtxRef.current) {
      try { audioCtxRef.current.close(); } catch {}
      audioCtxRef.current = null;
    }
  }, []);

  const startSiren = useCallback(() => {
    if (sirenMuted || isOnCibaPage) return; // CIBA page has its own siren
    if (oscillatorRef.current) return;

    try {
      const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
      audioCtxRef.current = ctx;
      const oscillator = ctx.createOscillator();
      const gain = ctx.createGain();
      oscillator.type = 'sine';
      oscillator.frequency.value = 800;
      gain.gain.value = 0.12;
      const now = ctx.currentTime;
      for (let i = 0; i < 60; i++) {
        oscillator.frequency.setValueAtTime(600, now + i * 1.0);
        oscillator.frequency.linearRampToValueAtTime(1000, now + i * 1.0 + 0.5);
        oscillator.frequency.linearRampToValueAtTime(600, now + i * 1.0 + 1.0);
      }
      oscillator.connect(gain);
      gain.connect(ctx.destination);
      oscillator.start();
      oscillatorRef.current = oscillator;
    } catch (e) {
      console.warn('Global siren failed:', e);
    }
  }, [sirenMuted, isOnCibaPage]);

  // Poll CIBA pending globally (every 30 seconds).
  // IMPORTANT: cibaSeenIdsRef is intentionally NOT in the dependency array.
  // Using state for seen IDs caused an infinite re-render loop because
  // setCibaSeenIds creates a new Set on every poll, which React interprets
  // as a dependency change, re-triggering the effect immediately.
  useEffect(() => {
    const pollCiba = () => {
      operatorFetch(`${API}/api/v1/admin/ciba/pending`, {
        headers: { Accept: 'application/json' },
      })
        .then(r => r.json())
        .then(body => {
          const count = body.count ?? 0;
          setCibaPendingCount(count);

          // Check for NEW alerts we haven't seen
          if (body.data && Array.isArray(body.data)) {
            const currentIds = new Set<string>(body.data.map((d: any) => d.trace_id as string));
            const newIds = body.data.filter((d: any) => !cibaSeenIdsRef.current.has(d.trace_id));
            cibaSeenIdsRef.current = currentIds;

            if (newIds.length > 0 && !isOnCibaPage) {
              // New alert arrived — trigger siren
              startSiren();
            }
          }
        })
        .catch(() => {});
    };
    pollCiba();
    const interval = setInterval(pollCiba, 30000);
    return () => clearInterval(interval);
  }, [isOnCibaPage, startSiren]);

  // Stop siren when no pending or navigated to CIBA page
  useEffect(() => {
    if (cibaPendingCount === 0 || isOnCibaPage) {
      stopSiren();
    }
  }, [cibaPendingCount, isOnCibaPage, stopSiren]);

  // Cleanup on unmount
  useEffect(() => {
    return () => stopSiren();
  }, [stopSiren]);

  // ── Standard alerts polling ──
  useEffect(() => {
    const load = () => {
      fetch(`${API}/api/v1/alerts`)
        .then(r => r.json())
        .then(body => { if (body.status === 'success') setAlertData(body.data); })
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, 30_000);
    return () => clearInterval(interval);
  }, []);

  const handleSearch = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && searchQuery.trim()) {
      router.push(`/pipeline?trace=${encodeURIComponent(searchQuery.trim())}`);
      setSearchQuery('');
    }
  };

  // ── Dynamic breadcrumbs from pathname ──
  const breadcrumbs = (() => {
    const segments = pathname.split('/').filter(Boolean);
    if (segments.length === 0) return [{ label: 'Global Overview', href: '/' }];
    const crumbs: { label: string; href: string }[] = [];
    let path = '';
    for (const seg of segments) {
      path += '/' + seg;
      const label = seg
        .replace(/-/g, ' ')
        .replace(/\b\w/g, c => c.toUpperCase());
      crumbs.push({ label, href: path });
    }
    return crumbs;
  })();

  // ── Dropdown state ──
  const [showNotifDropdown, setShowNotifDropdown] = useState(false);
  const [showProfileDropdown, setShowProfileDropdown] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  // Close dropdowns on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) setShowNotifDropdown(false);
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) setShowProfileDropdown(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleNotificationClick = () => {
    if (cibaPendingCount > 0) {
      router.push('/agent-admin/ciba');
      return;
    }
    setShowNotifDropdown(prev => !prev);
    setShowProfileDropdown(false);
  };

  const handleProfileClick = () => {
    setShowProfileDropdown(prev => !prev);
    setShowNotifDropdown(false);
  };

  const handleLogout = async () => {
    // Clear the HttpOnly session cookie via the server-side logout route.
    // Client-side JavaScript cannot delete HttpOnly cookies.
    await fetch('/api/auth/logout', { method: 'POST' });
    router.push('/login');
  };

  const unreadCount = alertData?.unread_count ?? 0;
  const totalAlerts = unreadCount + cibaPendingCount;

  return (
    <>
      <header className="fixed top-0 right-0 z-40 flex items-center justify-between px-8 bg-[#000000]/80 backdrop-blur-md h-20 border-b border-white/5 transition-all duration-300" style={{ left: 'var(--sidebar-width, 18rem)' }}>
        <div className="flex items-center gap-8">
          <span className="text-xl font-bold text-neutral-100 font-headline tracking-tight">CICADA CLOUD</span>
          <div className="flex items-center gap-4">
            <div className="flex items-center bg-surface-container-low px-4 py-2 rounded-xl border border-white/5 group focus-within:border-primary/50 transition-all">
              <span className="material-symbols-outlined text-on-surface-variant text-lg">search</span>
              <input
                className="bg-transparent border-none focus:ring-0 text-sm text-on-surface w-64 placeholder:text-neutral-600 focus:outline-none ml-2"
                placeholder="Search by reference ID... (Press Enter)"
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                onKeyDown={handleSearch}
              />
            </div>
          </div>
        </div>

        <div className="flex items-center gap-6">
          {/* ── Global CIBA Alert Banner ── */}
          {cibaPendingCount > 0 && !isOnCibaPage && (
            <button
              onClick={() => { stopSiren(); router.push('/agent-admin/ciba'); }}
              className="flex items-center gap-2 px-4 py-2 bg-red-500/15 border border-red-500/40 rounded-xl text-red-400 hover:bg-red-500/25 transition-all animate-pulse group"
            >
              <span className="material-symbols-outlined text-lg text-red-500">crisis_alert</span>
              <span className="text-xs font-technical font-bold uppercase tracking-wide">
                {cibaPendingCount} CIBA Alert{cibaPendingCount !== 1 ? 's' : ''} Pending
              </span>
              <span className="material-symbols-outlined text-sm text-red-500/50 group-hover:text-red-400 transition-colors">arrow_forward</span>
            </button>
          )}

          {/* Siren Mute (only when siren is active) */}
          {cibaPendingCount > 0 && !isOnCibaPage && (
            <button
              onClick={() => { setSirenMuted(!sirenMuted); if (!sirenMuted) stopSiren(); }}
              className={`p-2 rounded-lg transition-colors ${sirenMuted ? 'text-neutral-600 hover:text-neutral-400' : 'text-red-400 hover:text-red-300'}`}
              title={sirenMuted ? 'Unmute siren' : 'Mute siren'}
            >
              <span className="material-symbols-outlined text-lg">
                {sirenMuted ? 'volume_off' : 'volume_up'}
              </span>
            </button>
          )}

          {/* ── Breadcrumbs (dynamic) ── */}
          <nav className="flex items-center gap-2 font-mono text-[10px] text-neutral-400">
            <button onClick={() => router.push('/')} className="text-orange-500 hover:text-orange-400 transition-colors cursor-pointer">
              Dashboard
            </button>
            {breadcrumbs.map((crumb, i) => (
              <span key={crumb.href} className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[12px] text-neutral-600">chevron_right</span>
                {i === breadcrumbs.length - 1 ? (
                  <span className="text-neutral-100 border-b border-orange-500">{crumb.label}</span>
                ) : (
                  <button onClick={() => router.push(crumb.href)} className="text-neutral-400 hover:text-orange-400 transition-colors cursor-pointer">
                    {crumb.label}
                  </button>
                )}
              </span>
            ))}
          </nav>

          <div className="flex items-center gap-2 ml-4">
            {/* ── Notification Bell + Dropdown ── */}
            <div ref={notifRef} className="relative">
              <button
                onClick={handleNotificationClick}
                className="p-2 hover:bg-neutral-800/50 rounded-lg text-neutral-400 transition-colors relative"
              >
                <span className="material-symbols-outlined">notifications</span>
                {totalAlerts > 0 && (
                  <span className={`absolute top-1.5 right-1.5 min-w-[16px] h-4 rounded-full flex items-center justify-center text-[9px] font-bold text-white px-1 ${cibaPendingCount > 0 ? 'bg-red-500 animate-pulse' : 'bg-error'}`}>
                    {totalAlerts > 99 ? '99+' : totalAlerts}
                  </span>
                )}
                {totalAlerts === 0 && (
                  <span className="absolute top-2 right-2 w-2 h-2 bg-primary rounded-full"></span>
                )}
              </button>

              {showNotifDropdown && (
                <div className="absolute right-0 top-12 w-80 bg-[#131313] border border-white/10 rounded-xl shadow-2xl overflow-hidden z-50 animate-in fade-in slide-in-from-top-2 duration-200">
                  <div className="px-4 py-3 border-b border-white/10 bg-[#1a1a1a] flex justify-between items-center">
                    <span className="text-xs font-bold text-white font-headline uppercase tracking-wider">Notifications</span>
                    <span className="text-[10px] font-technical text-neutral-500">{totalAlerts} alert{totalAlerts !== 1 ? 's' : ''}</span>
                  </div>
                  <div className="max-h-64 overflow-y-auto">
                    {alertData && alertData.alerts.length > 0 ? (
                      alertData.alerts.slice(0, 8).map((alert, i) => (
                        <button key={alert.trace_id || i}
                          className="w-full px-4 py-3 text-left hover:bg-white/5 transition-colors border-b border-white/5 last:border-0"
                          onClick={() => { router.push(`/pipeline?trace=${alert.trace_id}`); setShowNotifDropdown(false); }}
                        >
                          <p className="text-xs text-white font-bold truncate">{alert.action_type.replace(/_/g, ' ')}</p>
                          <p className="text-[10px] text-neutral-500 mt-0.5 truncate">
                            {alert.agent_name || 'System'} — {alert.tenant_name || 'Unknown'}
                          </p>
                          <p className="text-[10px] text-neutral-600 mt-0.5">{new Date(alert.created_at).toLocaleString()}</p>
                        </button>
                      ))
                    ) : (
                      <div className="px-4 py-6 text-center">
                        <span className="material-symbols-outlined text-2xl text-neutral-700 mb-2 block">notifications_none</span>
                        <p className="text-xs text-neutral-500">No pending alerts</p>
                      </div>
                    )}
                  </div>
                  {alertData && alertData.alerts.length > 0 && (
                    <button
                      className="w-full px-4 py-2.5 text-center text-[10px] font-bold font-technical uppercase tracking-wider text-orange-500 hover:bg-orange-500/10 transition-colors border-t border-white/10"
                      onClick={() => { router.push('/agent-admin/alerts'); setShowNotifDropdown(false); }}
                    >
                      View All Alerts
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* ── Profile Button + Dropdown ── */}
            <div ref={profileRef} className="relative">
              <button
                onClick={handleProfileClick}
                className="p-2 hover:bg-neutral-800/50 rounded-lg text-neutral-400 transition-colors"
                title="Account"
              >
                <span className="material-symbols-outlined">account_circle</span>
              </button>

              {showProfileDropdown && (
                <div className="absolute right-0 top-12 w-56 bg-[#131313] border border-white/10 rounded-xl shadow-2xl overflow-hidden z-50 animate-in fade-in slide-in-from-top-2 duration-200">
                  <div className="px-4 py-3 border-b border-white/10 bg-[#1a1a1a]">
                    <p className="text-xs font-bold text-white font-headline">System Operator</p>
                    <p className="text-[10px] text-neutral-500 font-technical mt-0.5">Admin</p>
                  </div>
                  <div className="py-1">
                    <button onClick={() => { router.push('/crm'); setShowProfileDropdown(false); }}
                      className="w-full px-4 py-2.5 text-left text-xs text-neutral-300 hover:bg-white/5 hover:text-white transition-colors flex items-center gap-3">
                      <span className="material-symbols-outlined text-[16px] text-neutral-500">business</span>
                      Company CRM
                    </button>
                    <button onClick={() => { router.push('/agent-admin/operator-logs'); setShowProfileDropdown(false); }}
                      className="w-full px-4 py-2.5 text-left text-xs text-neutral-300 hover:bg-white/5 hover:text-white transition-colors flex items-center gap-3">
                      <span className="material-symbols-outlined text-[16px] text-neutral-500">history</span>
                      Operator Audit Logs
                    </button>
                    <button onClick={() => { router.push('/help'); setShowProfileDropdown(false); }}
                      className="w-full px-4 py-2.5 text-left text-xs text-neutral-300 hover:bg-white/5 hover:text-white transition-colors flex items-center gap-3">
                      <span className="material-symbols-outlined text-[16px] text-neutral-500">help</span>
                      Help & Documentation
                    </button>
                  </div>
                  <div className="border-t border-white/10 py-1">
                    <button onClick={handleLogout}
                      className="w-full px-4 py-2.5 text-left text-xs text-red-400 hover:bg-red-500/10 transition-colors flex items-center gap-3">
                      <span className="material-symbols-outlined text-[16px] text-red-500">logout</span>
                      Logout
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>
    </>
  );
};
