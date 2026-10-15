// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect, useCallback } from 'react';
import { Sidebar } from '../../../components/Sidebar';
import { TopAppBar } from '../../../components/TopAppBar';
import { useToast } from '../../../components/ToastContext';

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

interface AuditLog {
  id: string;
  operator_id: string | null;
  operator_email: string;
  action_type: string;
  target_type: string;
  target_id: string;
  previous_state: string | null;
  new_state: string | null;
  justification: string | null;
  ip_address: string | null;
  user_agent: string | null;
  session_id: string | null;
  created_at: string;
}

const ACTION_TYPES = [
  'hitl_approved', 'hitl_denied', 'agent_quarantined', 'agent_unquarantined',
  'policy_exception_created', 'trust_level_upgraded', 'security_rule_updated',
  'alert_rule_modified', 'data_retention_changed', 'api_key_rotated',
  'aegis_directive_saved', 'alert_dismissed', 'trace_flagged_false_positive',
];

const ACTION_COLORS: Record<string, string> = {
  hitl_approved: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  hitl_denied: 'text-red-400 bg-red-500/10 border-red-500/20',
  agent_quarantined: 'text-red-400 bg-red-500/10 border-red-500/20',
  agent_unquarantined: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  api_key_rotated: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  security_rule_updated: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  alert_dismissed: 'text-neutral-400 bg-neutral-500/10 border-neutral-500/20',
  trust_level_upgraded: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
  policy_exception_created: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  aegis_directive_saved: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  trace_flagged_false_positive: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
};

const ACTION_ICONS: Record<string, string> = {
  hitl_approved: 'check_circle',
  hitl_denied: 'block',
  agent_quarantined: 'shield_lock',
  agent_unquarantined: 'lock_open',
  api_key_rotated: 'key',
  security_rule_updated: 'security',
  alert_dismissed: 'notifications_off',
  trust_level_upgraded: 'verified',
  policy_exception_created: 'policy',
  aegis_directive_saved: 'terminal',
  data_retention_changed: 'delete_sweep',
  alert_rule_modified: 'tune',
  trace_flagged_false_positive: 'flag',
};

const SEVERITY_MAP: Record<string, { label: string; color: string }> = {
  hitl_approved: { label: 'HIGH', color: 'text-amber-400' },
  hitl_denied: { label: 'HIGH', color: 'text-amber-400' },
  agent_quarantined: { label: 'CRITICAL', color: 'text-red-400' },
  agent_unquarantined: { label: 'HIGH', color: 'text-amber-400' },
  api_key_rotated: { label: 'MEDIUM', color: 'text-orange-400' },
  security_rule_updated: { label: 'HIGH', color: 'text-amber-400' },
  alert_dismissed: { label: 'LOW', color: 'text-neutral-400' },
  trust_level_upgraded: { label: 'MEDIUM', color: 'text-orange-400' },
  policy_exception_created: { label: 'HIGH', color: 'text-amber-400' },
  aegis_directive_saved: { label: 'MEDIUM', color: 'text-orange-400' },
  trace_flagged_false_positive: { label: 'LOW', color: 'text-neutral-400' },
};

export default function OperatorAuditLog() {
  const { showToast } = useToast();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Filters
  const [actionFilter, setActionFilter] = useState('');
  const [operatorFilter, setOperatorFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  const loadLogs = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams();
    params.set('per_page', '100');
    if (actionFilter) params.set('action_type', actionFilter);
    if (operatorFilter) params.set('operator', operatorFilter);
    if (dateFrom) params.set('from', dateFrom);
    if (dateTo) params.set('to', dateTo);

    operatorFetch(`${API}/api/v1/admin/audit-logs?${params.toString()}`)
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success') {
          setLogs(data.data.data ?? []);
        }
      })
      .catch(() => showToast('Failed to load audit logs.'))
      .finally(() => setLoading(false));
  }, [actionFilter, operatorFilter, dateFrom, dateTo, showToast]);

  useEffect(() => { loadLogs(); }, [loadLogs]);

  // ── Exports ──
  const exportCSV = () => {
    if (logs.length === 0) { showToast('No records to export.'); return; }
    const header = 'ID,Timestamp,Operator ID,Operator Email,Action,Target Type,Target ID,Justification,IP Address,User Agent,Session ID\n';
    const rows = logs.map(l =>
      `"${l.id}","${new Date(l.created_at).toISOString()}","${l.operator_id ?? ''}","${l.operator_email}","${l.action_type}","${l.target_type}","${l.target_id}","${(l.justification ?? '').replace(/"/g, '""')}","${l.ip_address ?? ''}","${(l.user_agent ?? '').replace(/"/g, '""')}","${l.session_id ?? ''}"`
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `operator-audit-log-${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
    showToast('CSV export downloaded.');
  };

  const exportJSON = () => {
    if (logs.length === 0) { showToast('No records to export.'); return; }
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `operator-audit-log-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
    showToast('JSON export downloaded.');
  };

  // ── Diff Renderer ──
  function renderDiff(prev: string | null, next: string | null) {
    let prevObj: Record<string, unknown> = {};
    let nextObj: Record<string, unknown> = {};
    try { prevObj = prev ? JSON.parse(prev) : {}; } catch { prevObj = {}; }
    try { nextObj = next ? JSON.parse(next) : {}; } catch { nextObj = {}; }

    const allKeys = Array.from(new Set([...Object.keys(prevObj), ...Object.keys(nextObj)]));
    if (allKeys.length === 0) return <p className="text-neutral-600 text-xs italic">No state diff captured for this action.</p>;

    return (
      <div className="space-y-1 font-mono text-xs">
        {allKeys.map(key => {
          const pv = JSON.stringify(prevObj[key] ?? null);
          const nv = JSON.stringify(nextObj[key] ?? null);
          const changed = pv !== nv;
          return (
            <div key={key}>
              {changed && prevObj[key] !== undefined && (
                <p className="text-red-400/80">- <span className="text-red-300">{key}</span>: {pv}</p>
              )}
              {changed && nextObj[key] !== undefined && (
                <p className="text-emerald-400/80">+ <span className="text-emerald-300">{key}</span>: {nv}</p>
              )}
              {!changed && (
                <p className="text-neutral-600">  {key}: {pv}</p>
              )}
            </div>
          );
        })}
      </div>
    );
  }

  function formatAction(action: string) {
    return action.replace(/_/g, ' ');
  }

  function getTimeAgo(dateStr: string): string {
    const diff = Date.now() - new Date(dateStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  }

  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 px-8 pb-12 min-h-screen bg-background transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="max-w-[95%] mx-auto space-y-8">
          {/* Header */}
          <div className="flex flex-col lg:flex-row lg:justify-between lg:items-end gap-4">
            <div>
              <h1 className="text-5xl font-black font-headline tracking-tighter">Operator <span className="text-orange-500">Audit Logs</span></h1>
              <p className="text-neutral-400 mt-2 max-w-2xl font-technical text-sm">
                SOC2-compliant, immutable audit trail. Every state-changing action performed by a human operator is recorded here with full forensic context. This table cannot be edited, cleared, or deleted.
              </p>
            </div>
            <div className="flex gap-3 items-center flex-wrap">
              <button onClick={exportCSV}
                className="px-4 py-2 bg-[#2d1b1b] border border-orange-500/20 text-orange-400 rounded-lg font-headline font-bold text-xs uppercase tracking-wider hover:bg-orange-500/10 transition-colors shadow-lg shadow-orange-500/10">
                Export CSV
              </button>
              <button onClick={exportJSON}
                className="px-4 py-2 bg-[#1b252d] border border-blue-500/20 text-blue-400 rounded-lg font-headline font-bold text-xs uppercase tracking-wider hover:bg-blue-500/10 transition-colors shadow-lg shadow-blue-500/10">
                Export JSON
              </button>
              <button onClick={loadLogs}
                className="px-4 py-2 bg-primary border border-white/5 text-on-primary rounded-lg font-headline font-bold text-xs uppercase tracking-wider hover:brightness-110 transition-all shadow-lg shadow-primary/20 flex gap-2 items-center">
                <span className="material-symbols-outlined text-[14px]">refresh</span> Refresh
              </button>
            </div>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap gap-3 items-center bg-[#131313] border border-white/5 rounded-xl p-4">
            <select value={actionFilter} onChange={e => setActionFilter(e.target.value)}
              className="px-3 py-2 bg-black/40 border border-white/10 text-white rounded-lg font-technical text-xs focus:outline-none focus:border-orange-500/50">
              <option value="">All Actions</option>
              {ACTION_TYPES.map(a => (
                <option key={a} value={a}>{a.replace(/_/g, ' ')}</option>
              ))}
            </select>
            <input value={operatorFilter} onChange={e => setOperatorFilter(e.target.value)}
              placeholder="Filter by operator..."
              className="px-3 py-2 bg-black/40 border border-white/10 text-white rounded-lg font-technical text-xs focus:outline-none focus:border-orange-500/50 w-48"
            />
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-technical text-neutral-500 uppercase">From</span>
              <input type="date" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
                className="px-3 py-2 bg-black/40 border border-white/10 text-white rounded-lg font-technical text-xs focus:outline-none focus:border-orange-500/50" />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-technical text-neutral-500 uppercase">To</span>
              <input type="date" value={dateTo} onChange={e => setDateTo(e.target.value)}
                className="px-3 py-2 bg-black/40 border border-white/10 text-white rounded-lg font-technical text-xs focus:outline-none focus:border-orange-500/50" />
            </div>
            {(actionFilter || operatorFilter || dateFrom || dateTo) && (
              <button onClick={() => { setActionFilter(''); setOperatorFilter(''); setDateFrom(''); setDateTo(''); }}
                className="px-3 py-2 text-neutral-500 hover:text-white font-technical text-xs transition-colors">
                Clear Filters
              </button>
            )}
          </div>

          {/* Audit Log Entries */}
          <div className="space-y-3">
            {loading ? (
              <div className="bg-[#131313] border border-white/5 rounded-2xl p-12 text-center text-neutral-500 font-technical text-sm animate-pulse">Loading audit logs...</div>
            ) : logs.length === 0 ? (
              <div className="bg-[#131313] border border-white/5 rounded-2xl p-12 text-center">
                <span className="material-symbols-outlined text-4xl text-neutral-700 mb-3 block">description</span>
                <p className="text-neutral-500 font-technical text-sm">No operator actions match your filters.</p>
              </div>
            ) : (
              logs.map((log) => {
                const isExpanded = expandedId === log.id;
                const actionColor = ACTION_COLORS[log.action_type] ?? 'text-neutral-400 bg-neutral-500/10 border-neutral-500/20';
                const actionIcon = ACTION_ICONS[log.action_type] ?? 'history';
                const severity = SEVERITY_MAP[log.action_type] ?? { label: 'INFO', color: 'text-neutral-400' };

                return (
                  <div key={log.id} className={`bg-[#131313] border rounded-2xl overflow-hidden transition-all duration-200 ${isExpanded ? 'border-orange-500/30 shadow-lg shadow-orange-500/5' : 'border-white/5 hover:border-white/10'}`}>
                    {/* Collapsed Row — always visible */}
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : log.id)}
                      className="w-full px-6 py-5 flex items-center gap-5 text-left group transition-colors hover:bg-white/[0.02]"
                    >
                      {/* Action Icon */}
                      <div className={`w-10 h-10 rounded-xl flex items-center justify-center border ${actionColor} shrink-0`}>
                        <span className="material-symbols-outlined text-lg">{actionIcon}</span>
                      </div>

                      {/* Main Info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3">
                          <span className={`inline-block px-2.5 py-0.5 border rounded text-[10px] font-bold uppercase tracking-wider ${actionColor}`}>
                            {formatAction(log.action_type)}
                          </span>
                          <span className={`text-[9px] font-bold font-technical uppercase tracking-widest ${severity.color}`}>
                            {severity.label}
                          </span>
                        </div>
                        <p className="text-xs text-neutral-400 mt-1.5 truncate">
                          <span className="text-orange-400 font-bold">{log.operator_email}</span>
                          <span className="text-neutral-600 mx-2">→</span>
                          <span className="capitalize text-neutral-300">{log.target_type}</span>
                          <span className="text-neutral-600 mx-1">:</span>
                          <span className="font-mono text-neutral-500">{log.target_id.substring(0, 20)}{log.target_id.length > 20 ? '…' : ''}</span>
                        </p>
                      </div>

                      {/* Right Side — Timestamp + Expand */}
                      <div className="text-right shrink-0">
                        <p className="text-xs text-white font-bold">{new Date(log.created_at).toLocaleDateString()}</p>
                        <p className="text-[10px] text-neutral-500 mt-0.5">{new Date(log.created_at).toLocaleTimeString()}</p>
                        <p className="text-[9px] text-neutral-600 font-technical mt-0.5">{getTimeAgo(log.created_at)}</p>
                      </div>

                      <span className={`material-symbols-outlined text-neutral-600 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>
                        expand_more
                      </span>
                    </button>

                    {/* Expanded Detail Panel */}
                    {isExpanded && (
                      <div className="border-t border-white/5 bg-black/30">
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-0 lg:divide-x divide-white/5">

                          {/* ── Column 1: Operator Identity ── */}
                          <div className="p-6 space-y-4">
                            <h4 className="text-[10px] font-bold font-technical text-orange-500 uppercase tracking-[0.2em] flex items-center gap-2">
                              <span className="material-symbols-outlined text-xs">person</span>
                              Operator Identity
                            </h4>

                            <div className="space-y-3">
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Operator Email</p>
                                <p className="text-sm text-white font-bold">{log.operator_email}</p>
                              </div>
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Operator ID</p>
                                <p className="text-xs text-neutral-300 font-mono break-all">{log.operator_id ?? '—'}</p>
                              </div>
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Session Hash</p>
                                <p className="text-xs text-neutral-300 font-mono">{log.session_id ?? 'Not captured'}</p>
                              </div>
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Auth Method</p>
                                <p className="text-xs text-neutral-300">WebAuthn / Hardware Key</p>
                              </div>
                            </div>
                          </div>

                          {/* ── Column 2: Action Context ── */}
                          <div className="p-6 space-y-4 border-t lg:border-t-0 border-white/5">
                            <h4 className="text-[10px] font-bold font-technical text-orange-500 uppercase tracking-[0.2em] flex items-center gap-2">
                              <span className="material-symbols-outlined text-xs">description</span>
                              Action Context
                            </h4>

                            <div className="space-y-3">
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Action Performed</p>
                                <div className="flex items-center gap-2">
                                  <span className={`inline-block px-2.5 py-1 border rounded text-[10px] font-bold uppercase tracking-wider ${actionColor}`}>
                                    {formatAction(log.action_type)}
                                  </span>
                                </div>
                              </div>
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Target Entity</p>
                                <p className="text-sm text-white capitalize">{log.target_type}</p>
                              </div>
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Target ID</p>
                                <p className="text-xs text-neutral-300 font-mono break-all select-all">{log.target_id}</p>
                              </div>
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Justification / Notes</p>
                                <p className="text-xs text-neutral-300 leading-relaxed">{log.justification || <span className="text-neutral-600 italic">No justification recorded</span>}</p>
                              </div>
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Severity</p>
                                <p className={`text-xs font-bold ${severity.color}`}>{severity.label}</p>
                              </div>
                            </div>
                          </div>

                          {/* ── Column 3: Network Forensics ── */}
                          <div className="p-6 space-y-4 border-t lg:border-t-0 border-white/5">
                            <h4 className="text-[10px] font-bold font-technical text-orange-500 uppercase tracking-[0.2em] flex items-center gap-2">
                              <span className="material-symbols-outlined text-xs">dns</span>
                              Network Forensics
                            </h4>

                            <div className="space-y-3">
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Timestamp (UTC)</p>
                                <p className="text-sm text-white font-bold">{new Date(log.created_at).toISOString().replace('T', ' ').replace('Z', ' UTC')}</p>
                              </div>
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Source IP Address</p>
                                <p className="text-xs text-neutral-300 font-mono">{log.ip_address ?? 'Not captured'}</p>
                              </div>
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">User Agent</p>
                                <p className="text-xs text-neutral-400 break-all leading-relaxed">{log.user_agent || <span className="text-neutral-600 italic">Not captured</span>}</p>
                              </div>
                              <div>
                                <p className="text-[9px] text-neutral-600 uppercase tracking-widest font-technical mb-0.5">Record ID</p>
                                <p className="text-xs text-neutral-300 font-mono break-all select-all">{log.id}</p>
                              </div>
                            </div>
                          </div>
                        </div>

                        {/* ── State Diff Section (full width) ── */}
                        {(log.previous_state || log.new_state) && (
                          <div className="border-t border-white/5 p-6">
                            <h4 className="text-[10px] font-bold font-technical text-orange-500 uppercase tracking-[0.2em] flex items-center gap-2 mb-4">
                              <span className="material-symbols-outlined text-xs">difference</span>
                              Configuration State Diff
                            </h4>
                            <div className="bg-black/40 rounded-xl p-4 border border-white/5">
                              {renderDiff(log.previous_state, log.new_state)}
                            </div>
                          </div>
                        )}

                        {/* ── Footer ── */}
                        <div className="border-t border-white/5 px-6 py-3 bg-[#0a0a0a] flex justify-between items-center">
                          <p className="text-[9px] text-neutral-600 font-technical uppercase tracking-widest">
                            Immutable Record — Append Only — Cannot Be Modified or Deleted
                          </p>
                          <p className="text-[9px] text-neutral-600 font-mono">{log.id}</p>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>

          {/* Footer Stats */}
          {!loading && logs.length > 0 && (
            <div className="bg-[#131313] border border-white/5 rounded-xl px-6 py-4 flex justify-between items-center">
              <div className="flex items-center gap-4">
                <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">Immutable Records: {logs.length}</p>
                <span className="text-neutral-700">|</span>
                <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">
                  Unique Operators: {new Set(logs.map(l => l.operator_email)).size}
                </p>
                <span className="text-neutral-700">|</span>
                <p className="text-[10px] font-technical text-neutral-500 uppercase tracking-widest">
                  Action Types: {new Set(logs.map(l => l.action_type)).size}
                </p>
              </div>
              <p className="text-[10px] font-technical text-neutral-600 italic">Append-only — no edit or delete operations available.</p>
            </div>
          )}
        </div>
      </main>
    </>
  );
}
