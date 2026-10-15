// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';

const GW_URL = process.env.NEXT_PUBLIC_GATEWAY_URL || 'http://localhost:8080';

interface HealthCheck { label: string; status: 'ok' | 'warn' | 'error' | 'checking'; detail?: string; }

export default function GatewayHealth() {
  const [checks, setChecks] = useState<HealthCheck[]>([
    { label: 'Gateway Process',         status: 'checking' },
    { label: 'PostgreSQL Connection',   status: 'checking' },
    { label: 'Redis Connection',        status: 'checking' },
    { label: 'Ed25519 Key Loaded',      status: 'checking' },
    { label: 'Edge Ledger (SQLite)',    status: 'checking' },
    { label: 'Central Ledger Sync',     status: 'checking' },
  ]);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  async function runChecks() {
    setChecks(c => c.map(ch => ({ ...ch, status: 'checking' })));

    // Gateway process check — use /health which always exists
    try {
      const r = await fetch(`${GW_URL}/health`, { signal: AbortSignal.timeout(3000) });
      if (r.ok) {
        update('Gateway Process', 'ok', 'Responding on :8080');

        // Parse component statuses from the same response
        const data = await r.json().catch(() => ({}));
        update('PostgreSQL Connection', data.postgres === true ? 'ok' : 'warn', data.postgres_detail ?? 'Health endpoint did not report');
        update('Redis Connection',      data.redis === true ? 'ok' : 'warn', data.redis_detail ?? 'Health endpoint did not report');
        update('Ed25519 Key Loaded',    data.ed25519 === true ? 'ok' : 'warn', data.ed25519 === true ? 'Loaded' : 'Not loaded');
        update('Edge Ledger (SQLite)',  data.ledger === true ? 'ok' : 'warn', data.ledger_detail ?? 'Health endpoint did not report');
        update('Central Ledger Sync',   data.sync === true ? 'ok' : 'warn', data.sync_detail ?? 'Health endpoint did not report');
      } else {
        update('Gateway Process', 'error', `Health returned ${r.status}`);
        markUnknown();
      }
    } catch {
      update('Gateway Process', 'error', 'Not responding on :8080');
      markUnknown();
    }

    setLastChecked(new Date());
  }

  function update(label: string, status: 'ok' | 'warn' | 'error', detail?: string) {
    setChecks(c => c.map(ch => ch.label === label ? { ...ch, status, detail } : ch));
  }

  function markUnknown() {
    ['PostgreSQL Connection', 'Redis Connection', 'Ed25519 Key Loaded', 'Edge Ledger (SQLite)', 'Central Ledger Sync']
      .forEach(label => update(label, 'warn', 'Health endpoint not available — check logs'));
  }

  useEffect(() => { runChecks(); }, []);

  const colour: Record<string, string> = {
    ok:       'text-green-400 bg-green-400/10 border-green-400/20',
    warn:     'text-yellow-400 bg-yellow-400/10 border-yellow-400/20',
    error:    'text-red-400 bg-red-400/10 border-red-400/20',
    checking: 'text-gray-400 bg-gray-400/10 border-gray-400/20',
  };
  const icon: Record<string, string> = { ok: 'check_circle', warn: 'warning', error: 'error', checking: 'pending' };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-black font-headline tracking-tighter">Gateway Health</h1>
          <p className="text-on-surface-muted text-sm mt-1">
            {lastChecked ? `Last checked ${lastChecked.toLocaleTimeString()}` : 'Running checks…'}
          </p>
        </div>
        <button onClick={runChecks}
          className="flex items-center gap-2 px-5 py-2.5 border border-primary/30 text-primary rounded-xl font-headline font-bold text-sm hover:bg-primary/5 transition-colors"
        >
          <span className="material-symbols-outlined text-[18px]">refresh</span>
          Recheck
        </button>
      </div>

      <div className="space-y-3">
        {checks.map(ch => (
          <div key={ch.label} className={`flex items-center justify-between p-5 bg-surface-raised border rounded-xl ${
            ch.status !== 'checking' ? `border-${ch.status === 'ok' ? 'green' : ch.status === 'warn' ? 'yellow' : 'red'}-500/10` : 'border-[rgba(255,159,74,0.08)]'
          }`}>
            <div className="flex items-center gap-4">
              <span className={`material-symbols-outlined text-xl ${
                ch.status === 'ok' ? 'text-green-400' : ch.status === 'warn' ? 'text-yellow-400' : ch.status === 'error' ? 'text-red-400' : 'text-gray-400 animate-pulse'
              }`}>{icon[ch.status]}</span>
              <div>
                <p className="font-headline font-bold text-sm">{ch.label}</p>
                {ch.detail && <p className="text-xs text-on-surface-muted font-technical">{ch.detail}</p>}
              </div>
            </div>
            <span className={`text-[10px] font-technical uppercase tracking-widest px-2.5 py-1 rounded-full border ${colour[ch.status]}`}>
              {ch.status}
            </span>
          </div>
        ))}
      </div>

      <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6">
        <h2 className="font-headline font-bold mb-2 flex items-center gap-2">
          <span className="material-symbols-outlined text-primary text-xl">terminal</span>
          Logs
        </h2>
        <p className="text-sm text-on-surface-muted">
          Detailed Gateway logs are written to <code className="font-mono text-primary bg-primary/10 px-1.5 py-0.5 rounded">logs/sentry.log</code> in your Gateway installation directory.
        </p>
      </div>
    </div>
  );
}
