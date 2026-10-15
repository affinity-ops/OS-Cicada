// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useSession } from '../../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

const STATUS_CONFIG: Record<string, { label: string; colour: string; bg: string; icon: string }> = {
  certified:                { label: 'Certified',           colour: 'text-green-400',  bg: 'bg-green-400/10',  icon: 'verified' },
  pending_certification:    { label: 'Pending Review',      colour: 'text-yellow-400', bg: 'bg-yellow-400/10', icon: 'pending' },
  pending_review:           { label: 'Pending Review',      colour: 'text-yellow-400', bg: 'bg-yellow-400/10', icon: 'pending' },
  escalation_required:      { label: 'Escalation Required', colour: 'text-red-400',    bg: 'bg-red-400/10',    icon: 'warning' },
  suspended:                { label: 'Suspended',           colour: 'text-orange-400', bg: 'bg-orange-400/10', icon: 'pause_circle' },
  recertification_required: { label: 'Recert. Required',    colour: 'text-orange-400', bg: 'bg-orange-400/10', icon: 'refresh' },
  terminated:               { label: 'Terminated',          colour: 'text-red-400',    bg: 'bg-red-400/10',    icon: 'cancel' },
};

const EVENT_LABELS: Record<string, string> = {
  registered:           'Registered',
  escalation_flagged:   'Escalation Flagged',
  certified:            'Certified',
  recertified:          'Recertified',
  suspended:            'Suspended',
  terminated:           'Terminated',
  recertification_due:  'Recertification Due',
};

export default function AgentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const session = useSession();
  const agentId = params.agentId as string;

  const [agent, setAgent] = useState<any>(null);
  const [transactions, setTransactions] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [actionResult, setActionResult] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchAgent = useCallback(() => {
    if (!session || !agentId) return;

    Promise.all([
      fetch(`${CORE_API}/api/v1/portal/agents/${agentId}`, {
        headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
      }).then(r => r.json()),
      fetch(`${CORE_API}/api/v1/portal/agents/${agentId}/certification-events`, {
        headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
      }).then(r => r.json()).catch(() => ({ data: { events: [] } })),
    ]).then(([agentRes, eventsRes]) => {
      setAgent(agentRes.data?.agent ?? null);
      setTransactions(Array.isArray(agentRes.data?.recent_transactions) ? agentRes.data.recent_transactions : []);
      setEvents(Array.isArray(eventsRes.data?.events) ? eventsRes.data.events : []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [session, agentId]);

  useEffect(() => { fetchAgent(); }, [fetchAgent]);

  const performAction = async (action: string, label: string) => {
    if (!session) return;
    const reason = prompt(`Reason for ${label.toLowerCase()}:`);
    if (reason === null) return; // User cancelled

    setActionLoading(action);
    setActionResult(null);

    try {
      const res = await fetch(`${CORE_API}/api/v1/portal/agents/${agentId}/${action}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${session.token}`,
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ reason: reason || `Operator ${action}` }),
      });
      const data = await res.json();

      if (data.status === 'success') {
        setActionResult({ type: 'success', message: data.message });
        // Refresh agent data
        fetchAgent();
      } else {
        setActionResult({ type: 'error', message: data.message || 'Action failed.' });
      }
    } catch {
      setActionResult({ type: 'error', message: 'Network error — could not reach Core API.' });
    } finally {
      setActionLoading(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!agent) {
    return (
      <div className="p-8">
        <p className="text-red-400">Agent not found.</p>
        <button onClick={() => router.push('/registry')} className="text-primary underline mt-2 text-sm">← Back to Registry</button>
      </div>
    );
  }

  const s = STATUS_CONFIG[agent.approval_status] ?? STATUS_CONFIG[agent.status] ?? STATUS_CONFIG.pending_certification;
  const scopes = Array.isArray(agent.scope_entitlements) ? agent.scope_entitlements : [];
  const failureScope = Array.isArray(agent.failure_scope) ? agent.failure_scope : [];
  const tools = Array.isArray(agent.tools) ? agent.tools : [];
  const isTerminated = agent.revoked_at || agent.approval_status === 'terminated';
  const isSuspended = agent.approval_status === 'suspended';
  const isCertified = agent.approval_status === 'certified';
  const canCertify = !isTerminated && !isCertified;
  const canSuspend = !isTerminated && !isSuspended;
  const canRecertify = !isTerminated && (agent.approval_status === 'recertification_required' || isCertified);

  return (
    <div className="p-8 space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex items-center gap-2 text-on-surface-muted text-sm">
        <button onClick={() => router.push('/registry')} className="hover:text-primary transition-colors">Registry</button>
        <span>/</span>
        <span className="text-on-surface">{agent.name ?? agentId}</span>
      </div>

      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-primary/10 flex items-center justify-center">
            <span className="material-symbols-outlined text-primary text-3xl">smart_toy</span>
          </div>
          <div>
            <h1 className="text-2xl font-black font-headline tracking-tighter">{agent.name ?? 'Unnamed Agent'}</h1>
            <p className="text-sm text-on-surface-muted font-technical">{agent.agent_type} · v{agent.version} · Trust Tier {agent.trust_tier ?? '—'}</p>
          </div>
        </div>
        <span className={`flex items-center gap-1.5 text-sm font-technical px-3 py-1.5 rounded-full ${s.colour} ${s.bg}`}>
          <span className="material-symbols-outlined text-[16px]">{s.icon}</span>
          {s.label}
        </span>
      </div>

      {agent.description && (
        <p className="text-on-surface-muted text-sm">{agent.description}</p>
      )}

      {/* Action Result Banner */}
      {actionResult && (
        <div className={`p-3 rounded-xl text-sm font-technical ${
          actionResult.type === 'success' ? 'bg-green-400/10 text-green-400 border border-green-400/20' : 'bg-red-400/10 text-red-400 border border-red-400/20'
        }`}>
          {actionResult.message}
        </div>
      )}

      {/* Action Bar */}
      <div className="flex gap-3 flex-wrap">
        {canCertify && (
          <button
            onClick={() => performAction('certify', 'Certify')}
            disabled={!!actionLoading}
            className="flex items-center gap-2 px-4 py-2 bg-green-500/20 text-green-400 rounded-xl text-sm font-technical hover:bg-green-500/30 transition-colors border border-green-500/20 disabled:opacity-50"
          >
            <span className="material-symbols-outlined text-[16px]">verified</span>
            {actionLoading === 'certify' ? 'Certifying...' : 'Certify Agent'}
          </button>
        )}
        {canRecertify && agent.approval_status === 'recertification_required' && (
          <button
            onClick={() => performAction('recertify', 'Recertify')}
            disabled={!!actionLoading}
            className="flex items-center gap-2 px-4 py-2 bg-blue-500/20 text-blue-400 rounded-xl text-sm font-technical hover:bg-blue-500/30 transition-colors border border-blue-500/20 disabled:opacity-50"
          >
            <span className="material-symbols-outlined text-[16px]">refresh</span>
            {actionLoading === 'recertify' ? 'Recertifying...' : 'Recertify Agent'}
          </button>
        )}
        {canSuspend && (
          <button
            onClick={() => performAction('suspend', 'Suspend')}
            disabled={!!actionLoading}
            className="flex items-center gap-2 px-4 py-2 bg-orange-500/20 text-orange-400 rounded-xl text-sm font-technical hover:bg-orange-500/30 transition-colors border border-orange-500/20 disabled:opacity-50"
          >
            <span className="material-symbols-outlined text-[16px]">pause_circle</span>
            {actionLoading === 'suspend' ? 'Suspending...' : 'Suspend Agent'}
          </button>
        )}
        {!isTerminated && (
          <button
            onClick={() => performAction('terminate', 'Terminate')}
            disabled={!!actionLoading}
            className="flex items-center gap-2 px-4 py-2 bg-red-500/20 text-red-400 rounded-xl text-sm font-technical hover:bg-red-500/30 transition-colors border border-red-500/20 disabled:opacity-50"
          >
            <span className="material-symbols-outlined text-[16px]">cancel</span>
            {actionLoading === 'terminate' ? 'Terminating...' : 'Terminate Agent'}
          </button>
        )}
      </div>

      {/* Details Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Identity */}
        <div className="p-5 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-xl space-y-3">
          <h3 className="text-sm font-technical text-on-surface-muted uppercase tracking-wider">Identity</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-on-surface-muted">Agent ID</span><span className="font-mono text-xs">{agent.id}</span></div>
            <div className="flex justify-between"><span className="text-on-surface-muted">Type</span><span>{agent.agent_type ?? '—'}</span></div>
            <div className="flex justify-between"><span className="text-on-surface-muted">Version</span><span>{agent.version ?? '—'}</span></div>
            <div className="flex justify-between"><span className="text-on-surface-muted">Trust Tier</span><span>{agent.trust_tier ?? '—'}</span></div>
            {agent.evar_preview && (
              <div className="flex justify-between"><span className="text-on-surface-muted">EVAR</span><span className="font-mono text-[10px] text-on-surface-muted/60">{agent.evar_preview}</span></div>
            )}
          </div>
        </div>

        {/* Certification */}
        <div className="p-5 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-xl space-y-3">
          <h3 className="text-sm font-technical text-on-surface-muted uppercase tracking-wider">Certification</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between"><span className="text-on-surface-muted">Status</span><span className={s.colour}>{s.label}</span></div>
            <div className="flex justify-between"><span className="text-on-surface-muted">Registered</span><span>{agent.created_at ? new Date(agent.created_at).toLocaleDateString() : '—'}</span></div>
            <div className="flex justify-between"><span className="text-on-surface-muted">Certified</span><span>{agent.certified_at ? new Date(agent.certified_at).toLocaleDateString() : 'Never'}</span></div>
            <div className="flex justify-between"><span className="text-on-surface-muted">Recert. Due</span><span>{agent.recertification_due_at ? new Date(agent.recertification_due_at).toLocaleDateString() : '—'}</span></div>
            {agent.revoked_at && (
              <div className="flex justify-between"><span className="text-on-surface-muted">Revoked</span><span className="text-red-400">{new Date(agent.revoked_at).toLocaleDateString()}</span></div>
            )}
          </div>
        </div>

        {/* Scope Entitlements */}
        <div className="p-5 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-xl space-y-3">
          <h3 className="text-sm font-technical text-on-surface-muted uppercase tracking-wider">Scope Entitlements</h3>
          {scopes.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {scopes.map((scope: string, i: number) => (
                <span key={i} className="px-2.5 py-1 bg-primary/10 text-primary text-xs font-mono rounded-lg">{scope}</span>
              ))}
            </div>
          ) : (
            <p className="text-on-surface-muted text-sm">No scopes defined.</p>
          )}
          {failureScope.length > 0 && (
            <>
              <h4 className="text-xs font-technical text-on-surface-muted mt-2">Failure Scope</h4>
              <div className="flex flex-wrap gap-2">
                {failureScope.map((scope: string, i: number) => (
                  <span key={i} className="px-2.5 py-1 bg-red-400/10 text-red-400 text-xs font-mono rounded-lg">{scope}</span>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Tools */}
        <div className="p-5 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-xl space-y-3">
          <h3 className="text-sm font-technical text-on-surface-muted uppercase tracking-wider">Declared Tools</h3>
          {tools.length > 0 ? (
            <div className="space-y-2">
              {tools.map((tool: any, i: number) => (
                <div key={i} className="p-2.5 bg-white/5 rounded-lg">
                  <p className="text-sm font-bold">{tool.name ?? tool.tool_name ?? 'Unknown'}</p>
                  {tool.url_pattern && <p className="text-[10px] font-mono text-on-surface-muted/60 mt-0.5">{tool.url_pattern}</p>}
                  {tool.methods && <p className="text-[10px] font-technical text-on-surface-muted/40">{Array.isArray(tool.methods) ? tool.methods.join(', ') : tool.methods}</p>}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-on-surface-muted text-sm">No tools declared.</p>
          )}
        </div>
      </div>

      {/* Certification Timeline */}
      {events.length > 0 && (
        <div className="p-5 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-xl space-y-3">
          <h3 className="text-sm font-technical text-on-surface-muted uppercase tracking-wider">Certification Timeline</h3>
          <div className="space-y-3">
            {events.map((event: any) => (
              <div key={event.id} className="flex items-start gap-3 text-sm">
                <div className="w-2 h-2 rounded-full bg-primary mt-1.5 shrink-0" />
                <div>
                  <p className="font-technical">
                    <span className="font-bold">{EVENT_LABELS[event.event_type] ?? event.event_type}</span>
                    <span className="text-on-surface-muted"> by {event.performed_by}</span>
                  </p>
                  {event.reason && <p className="text-on-surface-muted text-xs mt-0.5">{event.reason}</p>}
                  <p className="text-on-surface-muted/50 text-[10px] font-mono mt-0.5">{new Date(event.created_at).toLocaleString()}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Transactions */}
      {transactions.length > 0 && (
        <div className="p-5 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-xl space-y-3">
          <h3 className="text-sm font-technical text-on-surface-muted uppercase tracking-wider">Recent Activity (Last 10)</h3>
          <div className="space-y-2">
            {transactions.map((tx: any, i: number) => (
              <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded-lg text-xs font-technical">
                <div className="flex items-center gap-3">
                  <span className={`w-2 h-2 rounded-full ${tx.status === 'allowed' ? 'bg-green-400' : tx.status === 'blocked' ? 'bg-red-400' : 'bg-yellow-400'}`} />
                  <span className="font-mono text-on-surface-muted/60">{tx.trace_id ?? '—'}</span>
                  <span>{tx.action_class ?? tx.decision ?? '—'}</span>
                </div>
                <span className="text-on-surface-muted/50">{tx.created_at ? new Date(tx.created_at).toLocaleString() : ''}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
