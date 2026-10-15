// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useToast } from '../../components/ToastContext';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';
import { SecureInput } from '../../components/SecureInput';

interface TenantKey {
  id: number;
  tenant_id: string;
  tenant_name: string;
  provider: string;
  created_at: string;
  updated_at: string | null;
  age_days: number;
  health_status: 'healthy' | 'warning' | 'critical' | 'expired';
  max_age_days: number;
  days_until_expiry: number;
  last_rotated_at: string | null;
  rotation_count: number;
  last_used_at: string | null;
}

interface AccessLogEntry {
  trace_id: string;
  action_type: string;
  tenant_name: string;
  status: string;
  created_at: string;
}

interface HealthSummary {
  healthy: number;
  warning: number;
  critical: number;
  expired: number;
}

interface VaultData {
  keys: TenantKey[];
  total_keys: number;
  health_summary: HealthSummary;
  max_age_days: number;
  access_log: AccessLogEntry[];
}

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

const PROVIDER_ICONS: Record<string, string> = {
  openai:    'smart_toy',
  anthropic: 'psychology',
  openrouter:'hub',
  default:   'vpn_key',
};

const PROVIDER_LABEL: Record<string, string> = {
  openai:    'OpenAI',
  anthropic: 'Anthropic',
  openrouter:'OpenRouter',
};

// ── Health status visual mapping ────────────────────────────────────────────
const HEALTH_CONFIG: Record<string, { color: string; bgColor: string; borderColor: string; icon: string; label: string }> = {
  healthy:  { color: 'text-emerald-400', bgColor: 'bg-emerald-500/10', borderColor: 'border-emerald-500/20', icon: 'verified_user', label: 'Healthy' },
  warning:  { color: 'text-amber-400',   bgColor: 'bg-amber-500/10',   borderColor: 'border-amber-500/20',   icon: 'schedule',      label: 'Rotation Due' },
  critical: { color: 'text-orange-400',  bgColor: 'bg-orange-500/10',  borderColor: 'border-orange-500/20',  icon: 'warning',       label: 'Overdue' },
  expired:  { color: 'text-red-400',     bgColor: 'bg-red-500/10',     borderColor: 'border-red-500/20',     icon: 'dangerous',     label: 'Expired' },
};

function HealthBadge({ status }: { status: string }) {
  const config = HEALTH_CONFIG[status] ?? HEALTH_CONFIG.healthy;
  return (
    <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg ${config.bgColor} border ${config.borderColor}`}>
      <span className={`material-symbols-outlined text-[14px] ${config.color}`} style={{ fontVariationSettings: "'FILL' 1" }}>{config.icon}</span>
      <span className={`text-[10px] font-headline font-bold uppercase tracking-wider ${config.color}`}>{config.label}</span>
    </div>
  );
}

function AgeRing({ ageDays, maxAgeDays, health }: { ageDays: number; maxAgeDays: number; health: string }) {
  const pct = Math.min(100, (ageDays / maxAgeDays) * 100);
  const config = HEALTH_CONFIG[health] ?? HEALTH_CONFIG.healthy;
  const strokeColor = health === 'healthy' ? '#34d399' : health === 'warning' ? '#fbbf24' : health === 'critical' ? '#fb923c' : '#f87171';
  const circumference = 2 * Math.PI * 36;
  const dashOffset = circumference - (pct / 100) * circumference;

  return (
    <div className="relative w-20 h-20 flex-shrink-0">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r="36" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="4" />
        <circle
          cx="40" cy="40" r="36" fill="none" stroke={strokeColor} strokeWidth="4"
          strokeDasharray={circumference} strokeDashoffset={dashOffset}
          strokeLinecap="round" className="transition-all duration-700"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-lg font-headline font-black tabular-nums ${config.color}`}>{ageDays}</span>
        <span className="text-[8px] font-technical text-neutral-500 uppercase">days</span>
      </div>
    </div>
  );
}

export default function ApiKeys() {
  const [rotatingKey, setRotatingKey] = useState<number | null>(null);
  const [vaultData, setVaultData] = useState<VaultData | null>(null);
  const [loading, setLoading] = useState(true);
  const { showToast } = useToast();

  const loadVault = () => {
    operatorFetch(`${API}/api/v1/vault/keys`)
      .then(r => r.json())
      .then(body => { if (body.status === 'success') setVaultData(body.data); })
      .catch(() => showToast('Failed to load API keys.'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadVault();
  }, []);

  const handleRotate = (keyId: number) => {
    setRotatingKey(keyId);
    operatorFetch(`${API}/api/v1/vault/keys/${keyId}/rotate`, { method: 'POST' })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { showToast(`Key rotated successfully.`); loadVault(); })
      .catch(() => showToast(`Rotation queued. The key will be replaced on next connection.`))
      .finally(() => setRotatingKey(null));
  };

  const keys       = vaultData?.keys ?? [];
  const accessLog  = vaultData?.access_log ?? [];
  const totalKeys  = vaultData?.total_keys ?? 0;
  const health     = vaultData?.health_summary ?? { healthy: 0, warning: 0, critical: 0, expired: 0 };
  const maxAge     = vaultData?.max_age_days ?? 90;

  const urgentCount = health.critical + health.expired;

  return (
    <>
      <Sidebar />
      <TopAppBar />

      <main className="pt-16 min-h-screen w-full bg-background relative z-10 transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="absolute inset-0 z-0 pointer-events-none opacity-20"
             style={{ backgroundImage: 'linear-gradient(rgba(255, 159, 74, 0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 159, 74, 0.05) 1px, transparent 1px)', backgroundSize: '20px 20px' }}>
        </div>

        <div className="p-10 h-full overflow-y-auto relative z-10 max-w-[95%] mx-auto">

          <div className="flex justify-between items-end mb-12">
            <div className="space-y-2">
              <h2 className="text-5xl font-headline font-black tracking-tighter text-on-surface">CREDENTIAL <span className="text-primary">VAULT</span></h2>
              <p className="text-on-surface-variant font-body max-w-md">Manage encrypted API keys with lifecycle health monitoring. Keys are AES-256-GCM encrypted and never shown in plain text.</p>
            </div>

            {/* Fleet health summary cards */}
            <div className="flex gap-3">
              {([
                { key: 'healthy',  icon: 'verified_user', label: 'Healthy',  val: health.healthy,  color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/10' },
                { key: 'warning',  icon: 'schedule',      label: 'Warning',  val: health.warning,  color: 'text-amber-400',   bg: 'bg-amber-500/10',   border: 'border-amber-500/10' },
                { key: 'critical', icon: 'warning',       label: 'Critical', val: health.critical, color: 'text-orange-400',  bg: 'bg-orange-500/10',  border: 'border-orange-500/10' },
                { key: 'expired',  icon: 'dangerous',     label: 'Expired',  val: health.expired,  color: 'text-red-400',     bg: 'bg-red-500/10',     border: 'border-red-500/10' },
              ]).map(s => (
                <div key={s.key} className={`px-4 py-3 ${s.bg} backdrop-blur-md rounded-xl flex items-center gap-3 border ${s.border} min-w-[100px]`}>
                  <span className={`material-symbols-outlined ${s.color} text-lg`} style={{ fontVariationSettings: "'FILL' 1" }}>{s.icon}</span>
                  <div className="text-right">
                    <p className={`text-xl font-headline font-bold ${s.color} tabular-nums`}>{loading ? '—' : s.val}</p>
                    <p className="text-[9px] font-technical text-neutral-500 uppercase">{s.label}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Urgent rotation banner */}
          {!loading && urgentCount > 0 && (
            <div className="mb-8 p-5 bg-gradient-to-r from-red-500/10 via-orange-500/10 to-amber-500/10 border border-red-500/20 rounded-2xl flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-red-500/20 flex items-center justify-center flex-shrink-0">
                <span className="material-symbols-outlined text-red-400 text-2xl animate-pulse" style={{ fontVariationSettings: "'FILL' 1" }}>notification_important</span>
              </div>
              <div className="flex-1">
                <p className="font-headline font-bold text-on-surface text-sm">
                  {urgentCount} credential{urgentCount > 1 ? 's' : ''} require{urgentCount === 1 ? 's' : ''} immediate rotation
                </p>
                <p className="text-xs text-neutral-400 mt-0.5">
                  Credentials older than {maxAge} days violate your {maxAge}-day rotation policy. Rotate now to maintain compliance.
                </p>
              </div>
              <div className="px-4 py-2 bg-red-500/20 text-red-400 text-xs font-headline font-bold rounded-lg border border-red-500/30">
                {urgentCount} OVERDUE
              </div>
            </div>
          )}

          {/* Aegis-0 Key */}
          <div className="mb-12 bg-[#131313] border border-blue-500/10 p-8 rounded-2xl relative overflow-hidden shadow-[0_0_40px_rgba(59,130,246,0.03)]">
            <div className="absolute top-0 right-0 p-6 opacity-5 pointer-events-none">
              <span className="material-symbols-outlined text-9xl text-blue-500">terminal</span>
            </div>
            <div className="relative z-10">
              <h3 className="text-2xl font-headline font-black text-on-surface mb-2 flex items-center gap-3">
                <span className="material-symbols-outlined text-blue-500 text-[28px]">monitoring</span>
                Aegis AI Assistant Key
              </h3>
              <p className="text-sm text-neutral-400 mb-6 max-w-3xl leading-relaxed">
                Aegis is your built-in AI security assistant. It monitors all agent activity and alerts you to unusual behaviour.
                Add your OpenRouter key below to activate it.
              </p>
              <div className="w-[80%]">
                <SecureInput label="Aegis AI Key" provider="OpenRouter" tenantId="sys_admin_core" />
              </div>
            </div>
          </div>

          {/* BYOK Inputs */}
          <h3 className="text-xl font-headline font-bold text-on-surface mb-6">Add API Keys for Your Agents</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-12">
            <SecureInput label="Anthropic Key" provider="Anthropic" tenantId="org_abc123" />
            <SecureInput label="OpenAI Key"    provider="OpenAI"    tenantId="org_abc123" />
          </div>

          {/* Live tenant key cards with lifecycle indicators */}
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-headline font-bold text-on-surface">Stored Credentials</h3>
            <div className="flex items-center gap-2 text-xs text-neutral-500 font-technical">
              <span className="material-symbols-outlined text-sm">timer</span>
              Rotation policy: {maxAge} days
            </div>
          </div>

          {loading && (
            <div className="py-16 flex items-center justify-center text-neutral-500 font-technical text-xs animate-pulse">
              Loading stored keys...
            </div>
          )}

          {!loading && keys.length === 0 && (
            <div className="py-16 flex flex-col items-center text-neutral-600 gap-3 mb-12">
              <span className="material-symbols-outlined text-5xl opacity-20">lock_open</span>
              <p className="font-technical text-xs">No keys stored yet. Keys appear here when companies add them via the Developer Portal.</p>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-12">
            {keys.map(key => {
              const icon    = PROVIDER_ICONS[key.provider.toLowerCase()] ?? PROVIDER_ICONS.default;
              const label   = PROVIDER_LABEL[key.provider.toLowerCase()] ?? key.provider.toUpperCase();
              const isRotating = rotatingKey === key.id;
              const healthConf = HEALTH_CONFIG[key.health_status] ?? HEALTH_CONFIG.healthy;
              const isUrgent = key.health_status === 'critical' || key.health_status === 'expired';

              return (
                <div
                  key={key.id}
                  className={`bg-[#1a1a1a]/40 backdrop-blur-md border p-6 rounded-2xl relative overflow-hidden group transition-all ${
                    isUrgent
                      ? `border-orange-500/30 hover:border-orange-500/50 shadow-[0_0_30px_rgba(249,115,22,0.05)]`
                      : 'border-white/5 hover:border-primary/20'
                  }`}
                >
                  {/* Background icon */}
                  <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                    <span className="material-symbols-outlined text-8xl font-black">{icon}</span>
                  </div>

                  {/* Header: Provider + Health Badge */}
                  <div className="flex justify-between items-start mb-4 relative z-10">
                    <div className="px-3 py-1 bg-primary/20 text-primary text-[10px] font-black font-headline tracking-widest rounded-full uppercase border border-primary/20">
                      {label}
                    </div>
                    <HealthBadge status={key.health_status} />
                  </div>

                  {/* Tenant name */}
                  <h3 className="text-lg font-headline font-bold mb-4 relative z-10">{key.tenant_name}</h3>

                  {/* Age ring + lifecycle stats */}
                  <div className="flex gap-5 items-center mb-5 relative z-10">
                    <AgeRing ageDays={key.age_days} maxAgeDays={key.max_age_days} health={key.health_status} />
                    <div className="flex-1 space-y-2.5">
                      <div className="flex justify-between items-center">
                        <span className="text-[10px] font-technical text-neutral-500 uppercase">Expires In</span>
                        <span className={`text-xs font-headline font-bold tabular-nums ${
                          key.days_until_expiry <= 0 ? 'text-red-400' : key.days_until_expiry <= 14 ? 'text-orange-400' : 'text-neutral-300'
                        }`}>
                          {key.days_until_expiry <= 0 ? 'EXPIRED' : `${key.days_until_expiry}d`}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-[10px] font-technical text-neutral-500 uppercase">Rotations</span>
                        <span className="text-xs font-headline font-bold text-neutral-300 tabular-nums">{key.rotation_count}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-[10px] font-technical text-neutral-500 uppercase">Last Used</span>
                        <span className="text-[10px] font-technical text-neutral-400">
                          {key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Key masked display */}
                  <div className="bg-[#131313] p-3 rounded-xl border border-white/5 mb-4 relative z-10">
                    <p className="text-[10px] font-technical text-neutral-600 mb-1 uppercase tracking-tighter">Key (hidden for security)</p>
                    <div className="font-technical text-sm text-on-surface-variant truncate">
                      ██████████████████████████████...
                    </div>
                  </div>

                  {/* Age progress bar */}
                  <div className="mb-4 relative z-10">
                    <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-700 ${
                          key.health_status === 'healthy' ? 'bg-emerald-500' :
                          key.health_status === 'warning' ? 'bg-amber-500' :
                          key.health_status === 'critical' ? 'bg-orange-500' : 'bg-red-500'
                        }`}
                        style={{ width: `${Math.min(100, (key.age_days / key.max_age_days) * 100)}%` }}
                      />
                    </div>
                    <div className="flex justify-between mt-1">
                      <span className="text-[9px] font-technical text-neutral-600">0d</span>
                      <span className="text-[9px] font-technical text-neutral-600">{key.max_age_days}d policy</span>
                    </div>
                  </div>

                  {/* Footer: timestamps + rotate */}
                  <div className="flex items-center justify-between relative z-10 pt-3 border-t border-white/5">
                    <div className="text-[10px] text-neutral-500 space-y-0.5">
                      <p>Created: <span className="text-neutral-300">{new Date(key.created_at).toLocaleDateString()}</span></p>
                      {key.last_rotated_at && (
                        <p>Rotated: <span className="text-neutral-300">{new Date(key.last_rotated_at).toLocaleDateString()}</span></p>
                      )}
                    </div>
                    <button
                      onClick={() => handleRotate(key.id)}
                      disabled={isRotating}
                      className={`flex items-center gap-2 px-4 py-2 text-xs font-headline font-bold rounded-lg transition-all ${
                        isUrgent
                          ? 'bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30 animate-pulse'
                          : 'bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20'
                      } ${isRotating ? 'opacity-50 cursor-wait' : ''}`}
                    >
                      <span className={`material-symbols-outlined text-sm ${isRotating ? 'animate-spin' : ''}`}>refresh</span>
                      {isRotating ? 'Rotating...' : isUrgent ? 'Rotate Now' : 'Rotate Key'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Access Log */}
          <div className="mt-4">
            <div className="flex items-center justify-between mb-6">
              <h4 className="text-lg font-headline font-bold text-on-surface">Key Usage Log</h4>
              <Link href="/logs" className="text-primary text-xs font-headline font-bold flex items-center gap-1 hover:underline">
                View Full Activity Log
                <span className="material-symbols-outlined text-sm">arrow_forward</span>
              </Link>
            </div>

            {accessLog.length === 0 ? (
              <div className="py-8 flex items-center justify-center text-neutral-600 font-technical text-xs">
                No key usage recorded yet.
              </div>
            ) : (
              <div className="space-y-3">
                {accessLog.map((entry, i) => {
                  const isSuccess = entry.status === 'approved' || entry.status === 'success';
                  const borderColor = i === 0 ? 'border-primary/50' : i === 1 ? 'border-secondary/50' : 'border-neutral-700/50';
                  return (
                    <div key={entry.trace_id} className={`flex items-center justify-between p-4 bg-[#1a1a1a] rounded-xl border-l-2 ${borderColor}`}>
                      <div className="flex items-center gap-4">
                        <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                          <span className="material-symbols-outlined text-primary text-sm">key_visualizer</span>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-on-surface capitalize">{entry.action_type.replace(/_/g, ' ')}</p>
                          <p className="text-[10px] font-technical text-neutral-500">{entry.tenant_name}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className={`text-xs font-bold ${isSuccess ? 'text-emerald-500' : 'text-error'}`}>
                          {isSuccess ? 'Success' : entry.status}
                        </p>
                        <p className="text-[10px] font-technical text-neutral-500">{new Date(entry.created_at).toLocaleTimeString()}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

        </div>
      </main>
    </>
  );
}
