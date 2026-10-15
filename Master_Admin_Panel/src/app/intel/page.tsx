// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState, useEffect } from 'react';

interface ThreatSignal {
  signal_id: string;
  category: string;
  fingerprint: string;
  severity: string;
  timestamp: number;
  ttl: number;
  relayed_at: number;
}

const SEVERITY_STYLES: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
};

const CATEGORY_ICONS: Record<string, string> = {
  prompt_injection: 'bug_report',
  exfiltration: 'data_alert',
  velocity_anomaly: 'speed',
  credential_scan: 'vpn_key',
  honeytoken: 'phishing',
  session_abuse: 'person_alert',
};

export default function ThreatIntelPage() {
  const [signals, setSignals] = useState<ThreatSignal[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchIntel = async () => {
      try {
        const res = await fetch('/api/v1/mesh/intel/feed?since=0');
        if (res.ok) {
          const data = await res.json();
          setSignals(data.signals || []);
        }
      } catch (error) {
        console.error('Failed to fetch threat intel:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchIntel();
    const interval = setInterval(fetchIntel, 15000);
    return () => clearInterval(interval);
  }, []);

  const categoryCounts = signals.reduce((acc, sig) => {
    acc[sig.category] = (acc[sig.category] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const severityCounts = signals.reduce((acc, sig) => {
    acc[sig.severity] = (acc[sig.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="p-10 font-body">
      <div className="flex justify-between items-end mb-10">
        <div>
          <h1 className="text-3xl font-black font-headline text-white tracking-tight mb-2">Threat Intelligence</h1>
          <p className="text-on-surface-muted max-w-2xl">
            Anonymised attack fingerprints flowing through the mesh. These are SHA-256 hashes of pattern names — no raw payloads, 
            no PII, no tenant-identifiable data. The source company is unknown by design.
          </p>
        </div>
      </div>

      {/* Data Sovereignty Notice */}
      <div className="flex items-center gap-3 bg-blue-500/5 border border-blue-500/20 rounded-xl px-5 py-3 mb-8">
        <span className="material-symbols-outlined text-blue-400">verified_user</span>
        <div className="text-sm text-blue-300/80">
          <strong>Anonymised by construction:</strong> Every fingerprint is a SHA-256 hash of the detection pattern name, not the content 
          that triggered it. Source company, agent ID, and payload are mathematically irreversible from the hash.
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-xl p-5">
          <div className="text-3xl font-black font-headline text-white">{signals.length}</div>
          <div className="text-xs text-on-surface-muted font-technical uppercase tracking-widest mt-1">Total Signals</div>
        </div>
        <div className="bg-surface/80 backdrop-blur-xl border border-red-500/20 rounded-xl p-5">
          <div className="text-3xl font-black font-headline text-red-400">{severityCounts['critical'] || 0}</div>
          <div className="text-xs text-red-400/70 font-technical uppercase tracking-widest mt-1">Critical</div>
        </div>
        <div className="bg-surface/80 backdrop-blur-xl border border-orange-500/20 rounded-xl p-5">
          <div className="text-3xl font-black font-headline text-orange-400">{severityCounts['high'] || 0}</div>
          <div className="text-xs text-orange-400/70 font-technical uppercase tracking-widest mt-1">High</div>
        </div>
        <div className="bg-surface/80 backdrop-blur-xl border border-yellow-500/20 rounded-xl p-5">
          <div className="text-3xl font-black font-headline text-yellow-400">{severityCounts['medium'] || 0}</div>
          <div className="text-xs text-yellow-400/70 font-technical uppercase tracking-widest mt-1">Medium</div>
        </div>
      </div>

      {/* Signal Feed */}
      <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-2xl overflow-hidden shadow-2xl">
        <div className="p-6 border-b border-border bg-surface-raised/50 flex justify-between items-center">
          <h2 className="text-lg font-bold font-headline text-white flex items-center gap-2">
            <span className="material-symbols-outlined text-primary drop-shadow-[0_0_8px_rgba(255,159,74,0.5)]">shield</span>
            Live Signal Feed
          </h2>
          <div className="flex items-center gap-2">
            {Object.entries(categoryCounts).map(([cat, count]) => (
              <span key={cat} className="px-2 py-1 bg-white/5 border border-white/10 rounded text-[10px] font-technical text-on-surface-muted">
                {cat}: {count}
              </span>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="p-20 flex flex-col items-center justify-center text-on-surface-muted">
            <span className="material-symbols-outlined animate-spin text-4xl mb-4 text-primary">autorenew</span>
            <p>Polling mesh directory for threat signals...</p>
          </div>
        ) : signals.length === 0 ? (
          <div className="p-20 flex flex-col items-center justify-center text-on-surface-muted">
            <span className="material-symbols-outlined text-4xl mb-3 opacity-30 text-green-400">shield</span>
            <p className="font-body">No threat signals in the mesh. The collective is quiet.</p>
          </div>
        ) : (
          <div className="divide-y divide-white/5">
            {signals.slice().reverse().map((signal) => {
              const style = SEVERITY_STYLES[signal.severity] || SEVERITY_STYLES['medium'];
              const icon = CATEGORY_ICONS[signal.category] || 'warning';
              const detectedAt = new Date(signal.timestamp / 1000000); // nanos to ms
              return (
                <div key={signal.signal_id} className="px-6 py-4 hover:bg-white/5 transition-colors flex items-center gap-4">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${style.bg} border ${style.border}`}>
                    <span className={`material-symbols-outlined ${style.text}`}>{icon}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-white font-technical">{signal.category.replace(/_/g, ' ').toUpperCase()}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${style.bg} ${style.text} border ${style.border}`}>
                        {signal.severity}
                      </span>
                    </div>
                    <div className="text-xs text-on-surface-muted font-technical mt-1 truncate">
                      Fingerprint: {signal.fingerprint.substring(0, 16)}...{signal.fingerprint.substring(signal.fingerprint.length - 8)}
                    </div>
                  </div>
                  <div className="text-right text-xs text-on-surface-muted font-technical">
                    <div>{detectedAt.toLocaleTimeString()}</div>
                    <div>{detectedAt.toLocaleDateString()}</div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
