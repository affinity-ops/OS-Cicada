// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useSession } from '../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

interface Agent {
  id: string; name: string; agent_type: string; version: string;
  trust_tier: string; status: string; certified_at: string | null;
  recertification_due_at: string | null; revoked_at: string | null;
  evar_preview: string | null; created_at: string;
}

const STATUS_CONFIG: Record<string, { label: string; colour: string; icon: string }> = {
  certified:                { label: 'Certified',            colour: 'text-green-400 bg-green-400/10',  icon: 'verified' },
  pending_certification:    { label: 'Pending Cert.',        colour: 'text-yellow-400 bg-yellow-400/10', icon: 'pending' },
  recertification_required: { label: 'Recert. Required',     colour: 'text-orange-400 bg-orange-400/10', icon: 'refresh' },
  terminated:               { label: 'Terminated',           colour: 'text-red-400 bg-red-400/10',      icon: 'cancel' },
};

export default function AgentRegistry() {
  const session = useSession();
  const [agents, setAgents]   = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter]   = useState('all');

  useEffect(() => {
    if (!session) return;
    fetch(`${CORE_API}/api/v1/portal/agents`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    }).then(r => r.json()).then(({ data }) => { setAgents(data.agents); setLoading(false); });
  }, [session]);

  const filtered = filter === 'all' ? agents : agents.filter(a => a.status === filter);

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-black font-headline tracking-tighter">Agent Registry</h1>
          <p className="text-on-surface-muted text-sm mt-1">All agents registered under your account</p>
        </div>
        <Link href="/agents/register"
          className="flex items-center gap-2 px-5 py-2.5 bg-primary text-black rounded-xl font-headline font-bold text-sm hover:brightness-110 transition-all"
        >
          <span className="material-symbols-outlined text-[18px]">add</span>
          Register Agent
        </Link>
      </div>

      {/* Filter tabs */}
      <div className="flex gap-2">
        {[
          { key: 'all',                      label: 'All' },
          { key: 'certified',                label: 'Certified' },
          { key: 'pending_certification',    label: 'Pending' },
          { key: 'recertification_required', label: 'Needs Recert.' },
          { key: 'terminated',               label: 'Terminated' },
        ].map(f => (
          <button key={f.key} onClick={() => setFilter(f.key)}
            className={`px-4 py-1.5 rounded-full text-xs font-technical transition-colors ${
              filter === f.key ? 'bg-primary text-black' : 'bg-white/5 text-on-surface-muted hover:bg-white/10'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl">
          <span className="material-symbols-outlined text-on-surface-muted text-5xl mb-3">robot_2</span>
          <p className="text-on-surface-muted text-sm">No agents found.</p>
          <Link href="/agents/register" className="mt-4 text-primary text-sm hover:underline font-technical">
            Register your first agent →
          </Link>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(agent => {
            const s = STATUS_CONFIG[agent.status] ?? STATUS_CONFIG.pending_certification;
            return (
              <Link key={agent.id} href={`/agents/${agent.id}`}
                className="flex items-center justify-between p-5 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-xl hover:border-primary/30 hover:bg-white/[0.02] transition-all cursor-pointer group"
              >
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center group-hover:bg-primary/20 transition-colors">
                    <span className="material-symbols-outlined text-primary text-xl">smart_toy</span>
                  </div>
                  <div>
                    <p className="font-headline font-bold group-hover:text-primary transition-colors">{agent.name ?? 'Unnamed Agent'}</p>
                    <p className="text-xs text-on-surface-muted font-technical">
                      {agent.agent_type} · v{agent.version}
                      {agent.certified_at && ` · Certified ${new Date(agent.certified_at).toLocaleDateString()}`}
                      {agent.recertification_due_at && ` · Recert. due ${new Date(agent.recertification_due_at).toLocaleDateString()}`}
                      {agent.revoked_at && ` · Terminated ${new Date(agent.revoked_at).toLocaleDateString()}`}
                    </p>
                    {agent.evar_preview && (
                      <p className="text-[10px] font-technical text-on-surface-muted/50 mt-0.5 font-mono">{agent.evar_preview}</p>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`flex items-center gap-1.5 text-xs font-technical px-2.5 py-1 rounded-full ${s.colour}`}>
                    <span className="material-symbols-outlined text-[14px]">{s.icon}</span>
                    {s.label}
                  </span>
                  <span className="material-symbols-outlined text-on-surface-muted/40 text-[18px] group-hover:text-primary/60 transition-colors">chevron_right</span>
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
