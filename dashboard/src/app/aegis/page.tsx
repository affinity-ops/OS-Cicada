// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';
import { useState, useEffect, useCallback } from 'react';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';
import { SecureInput } from '../../components/SecureInput';
import { useToast } from '../../components/ToastContext';

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';
const GATEWAY = process.env.NEXT_PUBLIC_GATEWAY_URL ?? 'http://localhost:8080';

// ── Types ──────────────────────────────────────────────────────────────────────

interface AegisAlert {
  id: string; action_type: string; agent_id: string; tenant_id: string;
  status: string; target_api: string | null; created_at: string; isRemoving?: boolean;
}
interface AegisActivityEntry {
  trace_id: string | null; action_type: string; agent_id: string; tenant_id: string;
  target_api: string | null; status: string; created_at: string;
}
interface AegisRule {
  id: string; slug: string; name: string; category: string; rule_type: string;
  rule_config: string; description: string; is_active: boolean; is_system: boolean; priority: number;
}
interface AegisTool {
  id: string; tool_name: string; display_name: string; description: string; category: string;
  is_enabled: boolean; requires_hitl: boolean; max_per_hour: number | null;
}
interface AegisTrace {
  trace_id: string; created_at: string; total_tokens_in: number; total_tokens_out: number;
  duration_ms: number; step_count: number; trigger: Record<string, unknown> | null;
  decision: Record<string, unknown> | null; gate_passed: boolean | null; outcome: string; model_id: string | null;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const ACTION_LABELS: Record<string, string> = {
  aegis_directive: 'Directive Applied', aegis_quarantine: 'Agent Quarantined',
  aegis_ghost_mode: 'Ghost Mode Engaged', aegis_rollback: 'Saga Rollback Triggered',
  aegis_triggered_rollback: 'Saga Rollback Triggered', quarantine: 'Agent Quarantined',
  ghost_mode_engaged: 'Ghost Mode Engaged',
  // Layer 1d Skill Routing
  skill_blocked: 'Skill Contract Violation', skill_schema_violation: 'Schema Mutation Detected',
  skill_delegation_blocked: 'Unauthorised Skill Delegation',
  // Anti-Rot Memory Flush
  memory_flush: 'Context Rot Flush Triggered',
};
function formatActionType(type: string): string {
  return ACTION_LABELS[type] ?? type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
const CATEGORY_COLORS: Record<string, string> = {
  escalation: 'text-red-400 bg-red-500/10 border-red-500/20',
  rate_limit: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  threshold: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  scope: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  permission: 'text-green-400 bg-green-500/10 border-green-500/20',
  custom: 'text-neutral-400 bg-neutral-500/10 border-neutral-500/20',
};
const TOOL_CATEGORY_COLORS: Record<string, string> = {
  telemetry: 'text-green-400 bg-green-500/10 border-green-500/20',
  registry: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  control: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  policy: 'text-red-400 bg-red-500/10 border-red-500/20',
};

const DEFAULT_DIRECTIVES = `Monitor all agent traffic for unusual patterns.
If an agent exceeds 5 blocked requests per second, flag the account for review.
If suspicious behaviour persists across multiple agents on the same account, escalate immediately.`;

const TABS = ['Command', 'Rules', 'Tools', 'Trace Log'] as const;
type Tab = typeof TABS[number];

// ═══════════════════════════════════════════════════════════════════════════════
export default function AegisCommandCenter() {
  const [activeTab, setActiveTab] = useState<Tab>('Command');
  const [model, setModel] = useState("deepseek/deepseek-r1");
  const [promptData, setPromptData] = useState(DEFAULT_DIRECTIVES);
  const [isSaving, setIsSaving] = useState(false);
  const [activeAlerts, setActiveAlerts] = useState<AegisAlert[]>([]);
  const [activityLog, setActivityLog] = useState<AegisActivityEntry[]>([]);
  const [availableModels, setAvailableModels] = useState<{id: string, name: string}[]>([]);
  const [gatewayConnected, setGatewayConnected] = useState<boolean | null>(null);
  const [keyBound, setKeyBound] = useState<boolean | null>(null);
  const [isLoadingConfig, setIsLoadingConfig] = useState(true);
  const [rules, setRules] = useState<AegisRule[]>([]);
  const [tools, setTools] = useState<AegisTool[]>([]);
  const [traces, setTraces] = useState<AegisTrace[]>([]);
  const [traceRetention, setTraceRetention] = useState(30);
  const [ruleFilter, setRuleFilter] = useState('all');
  const [showAddRule, setShowAddRule] = useState(false);
  const [newRule, setNewRule] = useState({ name: '', category: 'custom', rule_type: 'boolean', description: '', rule_config: '{"enabled": true}' });
  const { showToast } = useToast();

  // ── Data Loading ────────────────────────────────────────────────────────────

  useEffect(() => {
    operatorFetch(`${API}/api/v1/aegis/models`).then(r => r.json())
      .then(b => { if (b?.status === 'success' && Array.isArray(b.data)) setAvailableModels(b.data); }).catch(() => {});
  }, []);

  const loadConfiguration = useCallback(async () => {
    try {
      const [dRes, mRes, sRes] = await Promise.all([
        operatorFetch(`${API}/api/v1/aegis/directives`).then(r => r.json()).catch(() => null),
        operatorFetch(`${API}/api/v1/aegis/model`).then(r => r.json()).catch(() => null),
        operatorFetch(`${API}/api/v1/aegis/settings`).then(r => r.json()).catch(() => null),
      ]);
      if (dRes?.status === 'success' && dRes.data?.prompt_data) setPromptData(dRes.data.prompt_data);
      if (mRes?.status === 'success' && mRes.data?.model_id) setModel(mRes.data.model_id);
      if (sRes?.status === 'success' && sRes.data?.trace_retention_days) setTraceRetention(sRes.data.trace_retention_days);
    } catch {} finally { setIsLoadingConfig(false); }
  }, []);
  useEffect(() => { loadConfiguration(); }, [loadConfiguration]);

  const loadAlerts = useCallback(async () => {
    try { const r = await operatorFetch(`${API}/api/v1/aegis/alerts`); const b = await r.json();
      if (b?.status === 'success') setActiveAlerts((b.data ?? []).map((a: AegisAlert) => ({ ...a, isRemoving: false }))); } catch {}
  }, []);
  useEffect(() => { loadAlerts(); const i = setInterval(loadAlerts, 30000); return () => clearInterval(i); }, [loadAlerts]);

  const loadActivity = useCallback(async () => {
    try { const r = await operatorFetch(`${API}/api/v1/aegis/activity`); const b = await r.json();
      if (b?.status === 'success') setActivityLog(b.data ?? []); } catch {}
  }, []);
  useEffect(() => { loadActivity(); const i = setInterval(loadActivity, 30000); return () => clearInterval(i); }, [loadActivity]);

  const loadRules = useCallback(async () => {
    try { const r = await operatorFetch(`${API}/api/v1/aegis/rules`); const b = await r.json();
      if (b?.status === 'success') setRules(b.data ?? []); } catch {}
  }, []);

  const loadTools = useCallback(async () => {
    try { const r = await operatorFetch(`${API}/api/v1/aegis/tools`); const b = await r.json();
      if (b?.status === 'success') setTools(b.data ?? []); } catch {}
  }, []);

  const loadTraces = useCallback(async () => {
    try { const r = await operatorFetch(`${API}/api/v1/aegis/traces?limit=20`); const b = await r.json();
      if (b?.status === 'success') setTraces(b.data ?? []); } catch {}
  }, []);

  useEffect(() => { if (activeTab === 'Rules') loadRules(); }, [activeTab, loadRules]);
  useEffect(() => { if (activeTab === 'Tools') loadTools(); }, [activeTab, loadTools]);
  useEffect(() => { if (activeTab === 'Trace Log') loadTraces(); }, [activeTab, loadTraces]);

  useEffect(() => {
    fetch(`${GATEWAY}/health`, { signal: AbortSignal.timeout(5000) })
      .then(r => setGatewayConnected(r.ok)).catch(() => setGatewayConnected(false));
    operatorFetch(`${API}/api/v1/vault/keys`).then(r => r.json())
      .then(b => { const k = b?.data?.keys ?? [];
        setKeyBound(k.some((k: { tenant_id: string; provider: string }) => k.tenant_id === 'sys_admin_core' || k.provider === 'openrouter')); })
      .catch(() => setKeyBound(false));
  }, []);

  // ── Actions ─────────────────────────────────────────────────────────────────

  const handleSaveDirectives = async () => {
    setIsSaving(true);
    try { const r = await operatorFetch(`${API}/api/v1/aegis/directives`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ prompt_data: promptData }) });
      if (!r.ok) throw new Error(); showToast("Aegis instructions saved successfully.");
    } catch { showToast("Could not reach server."); } finally { setIsSaving(false); }
  };
  const handleModelChange = async (v: string) => {
    setModel(v);
    try { await operatorFetch(`${API}/api/v1/aegis/model`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ model_id: v }) });
      showToast(`Model updated to ${v.split('/').pop()}`); } catch { showToast("Saved locally."); }
  };
  const handleReleaseAlert = (id: string) => {
    setActiveAlerts(p => p.map(c => c.id === id ? { ...c, isRemoving: true } : c));
    operatorFetch(`${API}/api/v1/aegis/alerts/${encodeURIComponent(id)}/release`, { method: 'POST' }).catch(() => {})
      .finally(() => { setTimeout(() => setActiveAlerts(p => p.filter(c => c.id !== id)), 500); showToast(`Alert dismissed.`); });
  };
  const handleToggleRule = async (rule: AegisRule) => {
    try { await operatorFetch(`${API}/api/v1/aegis/rules/${rule.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ is_active: !rule.is_active }) });
      setRules(p => p.map(r => r.id === rule.id ? { ...r, is_active: !r.is_active } : r)); showToast(`${rule.name} ${rule.is_active ? 'disabled' : 'enabled'}.`);
    } catch { showToast('Failed to update rule.'); }
  };
  const handleDeleteRule = async (rule: AegisRule) => {
    try { await operatorFetch(`${API}/api/v1/aegis/rules/${rule.id}`, { method: 'DELETE' });
      setRules(p => p.filter(r => r.id !== rule.id)); showToast(`${rule.name} deleted.`);
    } catch { showToast('Cannot delete system rules.'); }
  };
  const handleCreateRule = async () => {
    try {
      let config;
      try { config = JSON.parse(newRule.rule_config); } catch { showToast('Invalid JSON in rule config.'); return; }
      await operatorFetch(`${API}/api/v1/aegis/rules`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...newRule, rule_config: config }) });
      setShowAddRule(false); setNewRule({ name: '', category: 'custom', rule_type: 'boolean', description: '', rule_config: '{"enabled": true}' });
      loadRules(); showToast('Rule created.');
    } catch { showToast('Failed to create rule.'); }
  };
  const handleToggleTool = async (tool: AegisTool, field: 'is_enabled' | 'requires_hitl') => {
    const update = { [field]: !tool[field] };
    try { await operatorFetch(`${API}/api/v1/aegis/tools/${tool.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(update) });
      setTools(p => p.map(t => t.id === tool.id ? { ...t, [field]: !t[field] } : t)); showToast(`${tool.display_name} updated.`);
    } catch { showToast('Failed to update tool.'); }
  };
  const handleRetentionChange = async (days: number) => {
    setTraceRetention(days);
    try { await operatorFetch(`${API}/api/v1/aegis/settings`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ trace_retention_days: days }) });
      showToast(`Trace retention set to ${days} days.`); } catch { showToast('Failed to save setting.'); }
  };

  // ── Derived ─────────────────────────────────────────────────────────────────
  const latestReasoning = activityLog.length > 0 ? activityLog[0] : null;
  const latestAction = activityLog.find(e => e.action_type !== 'aegis_directive' && e.status !== 'operator_released') ?? null;
  const isActive = activityLog.length > 0 && (Date.now() - new Date(activityLog[0].created_at).getTime()) < 300000;
  const filteredRules = ruleFilter === 'all' ? rules : rules.filter(r => r.category === ruleFilter);

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <>
      <Sidebar />
      <TopAppBar />
      <main className="pt-24 pb-12 px-8 min-h-screen bg-background relative z-10 transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="absolute inset-0 z-0 pointer-events-none opacity-10" style={{ backgroundImage: 'radial-gradient(circle at 50% 50%, rgba(59, 130, 246, 0.15) 0%, transparent 50%), linear-gradient(rgba(59, 130, 246, 0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(59, 130, 246, 0.05) 1px, transparent 1px)', backgroundSize: '100% 100%, 30px 30px, 30px 30px' }}></div>

        {/* Header + Tabs */}
        <section className="mb-6 relative z-10">
          <h1 className="text-4xl font-headline font-black text-on-surface tracking-tighter mb-1 uppercase">Aegis AI Assistant</h1>
          <p className="text-xs font-technical text-blue-400 uppercase tracking-widest bg-blue-500/10 inline-block px-3 py-1 rounded-full border border-blue-500/20 mb-4">Automated Security Governance</p>
          <div className="flex gap-1 bg-[#0a0a0a] border border-white/5 rounded-xl p-1 w-fit">
            {TABS.map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)}
                className={`px-4 py-2 text-xs font-technical uppercase tracking-widest rounded-lg transition-all duration-200 ${activeTab === tab ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' : 'text-neutral-500 hover:text-neutral-300 border border-transparent'}`}>
                {tab}
              </button>
            ))}
          </div>
        </section>

        {/* ═══════════════ TAB: COMMAND ═══════════════ */}
        {activeTab === 'Command' && (
          <div className="relative z-10 mx-auto flex flex-col xl:flex-row gap-6" style={{ height: '72vh' }}>
            {/* COL 1: Reasoning + Actions */}
            <div className="w-full xl:w-[35%] flex flex-col gap-4 h-full">
              {/* Reasoning */}
              <div className="flex-1 bg-[#050505] border border-amber-500/20 rounded-2xl flex flex-col overflow-hidden shadow-[inset_0_0_40px_rgba(245,158,11,0.02)]">
                <div className="bg-[#0a0a0a] border-b border-amber-500/20 px-4 py-2 flex items-center justify-between">
                  <div className="flex items-center gap-2"><span className="text-[10px] font-technical uppercase text-amber-500 tracking-widest">Aegis: Reasoning</span></div>
                  {isActive ? <span className="flex items-center gap-2 text-[10px] font-technical text-amber-500"><span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse"></span> ANALYSING</span>
                    : <span className="flex items-center gap-2 text-[10px] font-technical text-neutral-500"><span className="w-1.5 h-1.5 rounded-full bg-neutral-600"></span> IDLE</span>}
                </div>
                <div className="flex-1 p-4 overflow-y-auto font-mono text-[11px] text-amber-200/70 leading-relaxed whitespace-pre-wrap">
                  {latestReasoning ? (<>
                    <strong className="text-amber-400 opacity-80">&gt;&gt; Latest activity — {timeAgo(latestReasoning.created_at)}</strong><br/><br/>
                    Event: <span className="text-amber-500">{formatActionType(latestReasoning.action_type)}</span><br/>
                    {latestReasoning.agent_id !== '00000000-0000-0000-0000-000000000000' && <>Agent: {latestReasoning.agent_id}<br/></>}
                    Status: <span className={latestReasoning.status === 'approved' || latestReasoning.status === 'success' ? 'text-green-400' : 'text-amber-400'}>{latestReasoning.status}</span><br/>
                    {activityLog.length > 1 && <><br/><span className="text-neutral-600">── {activityLog.length - 1} earlier events ──</span><br/>
                      {activityLog.slice(1, 4).map((e, i) => <span key={i} className="text-neutral-600">{timeAgo(e.created_at)} — {formatActionType(e.action_type)} ({e.status})<br/></span>)}</>}
                  </>) : (<div className="flex flex-col items-center justify-center h-full text-neutral-600 gap-2">
                    <span className="material-symbols-outlined text-3xl opacity-20">psychology</span>
                    <span className="text-xs font-technical">Aegis is monitoring. No recent events.</span></div>)}
                </div>
              </div>
              {/* Action Log */}
              <div className="flex-1 bg-[#050814] border border-cyan-500/20 rounded-2xl flex flex-col overflow-hidden shadow-[inset_0_0_40px_rgba(6,182,212,0.02)]">
                <div className="bg-[#0a101a] border-b border-cyan-500/20 px-4 py-2 flex items-center justify-between">
                  <span className="text-[10px] font-technical uppercase text-cyan-500 tracking-widest">Action Taken</span>
                  {latestAction && <span className="text-[10px] font-technical text-green-400 border border-green-500/30 bg-green-500/10 px-2 py-0.5 rounded">{timeAgo(latestAction.created_at)}</span>}
                </div>
                <div className="flex-1 p-4 overflow-y-auto font-mono text-[11px] text-cyan-200/70 leading-relaxed whitespace-pre-wrap">
                  {latestAction ? (<>
                    <strong className="text-cyan-400 opacity-80">Sent to Security Gateway:</strong><br/>
{`{\n  "action": "${latestAction.action_type}",\n  "target": "${latestAction.agent_id !== '00000000-0000-0000-0000-000000000000' ? latestAction.agent_id : latestAction.tenant_id}",\n  "trace": "${latestAction.trace_id ?? 'N/A'}"\n}`}<br/><br/>
                    <strong className={latestAction.status === 'approved' || latestAction.status === 'success' ? 'text-green-500 uppercase' : 'text-amber-500 uppercase'}>
                      &lt;&lt; {latestAction.status === 'approved' || latestAction.status === 'success' ? 'Confirmed' : latestAction.status}</strong>
                  </>) : (<div className="flex flex-col items-center justify-center h-full text-neutral-600 gap-2">
                    <span className="material-symbols-outlined text-3xl opacity-20">terminal</span>
                    <span className="text-xs font-technical">No actions taken yet.</span></div>)}
                </div>
              </div>
            </div>

            {/* COL 2: Active Alerts */}
            <div className="flex-1 bg-[#111] border border-white/5 rounded-2xl flex flex-col overflow-hidden">
              <div className="bg-[#181818] border-b border-white/5 px-6 py-4 flex items-center gap-2">
                <h3 className="text-sm font-headline font-bold text-white uppercase tracking-widest">Active Alerts</h3>
                {activeAlerts.length > 0 && <span className="ml-auto text-[10px] font-technical text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded">{activeAlerts.length} active</span>}
              </div>
              <div className="flex-1 overflow-y-auto p-6 space-y-4 bg-black/40">
                {activeAlerts.length === 0 && (<div className="flex flex-col items-center justify-center h-full text-neutral-600 gap-2">
                  <span className="material-symbols-outlined text-4xl opacity-20">check_circle</span>
                  <p className="font-technical text-xs">All clear. No active alerts.</p></div>)}
                {activeAlerts.map(card => (
                  <div key={card.id} className={`bg-[#151515] border border-green-500/20 rounded-xl p-5 relative overflow-hidden transition-all duration-500 ${card.isRemoving ? 'scale-95 opacity-0' : 'scale-100 opacity-100'}`}>
                    <div className="absolute top-0 left-0 w-1 h-full bg-green-500"></div>
                    <div className="flex justify-between items-start mb-3">
                      <div>
                        <span className="text-[10px] font-technical uppercase bg-green-500/10 text-green-400 px-2 py-0.5 rounded border border-green-500/20 tracking-widest mb-2 inline-block">{card.status.toUpperCase()}</span>
                        <h4 className="text-white font-headline text-lg font-bold">{formatActionType(card.action_type)}</h4>
                        <p className="text-[10px] font-technical text-neutral-500 mt-1">{card.agent_id !== '00000000-0000-0000-0000-000000000000' && `Agent: ${card.agent_id.substring(0, 8)}…`} · {timeAgo(card.created_at)}</p>
                      </div>
                      <button onClick={() => handleReleaseAlert(card.id)} className="bg-red-500/10 hover:bg-red-500 hover:text-white text-red-500 text-[10px] uppercase font-technical font-bold px-3 py-1.5 rounded transition-colors border border-red-500/20">Dismiss</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* COL 3: Settings */}
            <div className="w-full xl:w-[25%] flex flex-col gap-4 h-full">
              {/* Connections */}
              <div className="bg-[#111] border border-white/5 rounded-2xl p-5">
                <h3 className="text-[10px] font-technical uppercase text-neutral-500 tracking-widest mb-4">Connections</h3>
                <div className="space-y-4">
                  <div className="flex justify-between items-center text-xs font-technical uppercase">
                    <span className="text-neutral-300">Security Gateway</span>
                    {gatewayConnected === null ? <span className="text-neutral-500">Checking…</span> : gatewayConnected ? <span className="text-green-400">Connected</span> : <span className="text-red-400">Unreachable</span>}
                  </div>
                  <div className="flex justify-between items-center text-xs font-technical uppercase">
                    <span className="text-neutral-300">Key Storage</span>
                    {keyBound === null ? <span className="text-neutral-500">Checking…</span> : keyBound ? <span className="text-green-400">Key Bound</span> : <span className="text-amber-400">No Key</span>}
                  </div>
                </div>
              </div>
              {/* Model */}
              <div className="bg-[#111] border border-blue-500/20 rounded-2xl p-5">
                <h3 className="text-xs font-headline font-bold text-white uppercase tracking-widest mb-4">AI Model</h3>
                <label className="text-[9px] font-technical uppercase text-neutral-500 mb-1.5 block">Active model</label>
                <select value={model} onChange={e => handleModelChange(e.target.value)} disabled={isLoadingConfig}
                  className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-neutral-200 focus:outline-none focus:border-blue-500 transition-colors cursor-pointer font-technical disabled:opacity-50">
                  {availableModels.length > 0 ? availableModels.map(m => <option key={m.id} value={m.id}>{m.id}</option>)
                    : <><option value="deepseek/deepseek-r1">deepseek-r1 (default)</option><option value="anthropic/claude-3-opus">claude-3-opus</option></>}
                </select>
                <div className="mt-3"><SecureInput label="Aegis API Key" provider="OpenRouter" tenantId="sys_admin_core" /></div>
              </div>
              {/* Retention */}
              <div className="bg-[#111] border border-white/5 rounded-2xl p-5">
                <h3 className="text-[10px] font-technical uppercase text-neutral-500 tracking-widest mb-3">Trace Retention</h3>
                <select value={traceRetention} onChange={e => handleRetentionChange(Number(e.target.value))}
                  className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-neutral-200 focus:outline-none focus:border-blue-500 transition-colors cursor-pointer font-technical">
                  <option value={30}>30 days</option><option value={60}>60 days</option><option value={90}>90 days</option>
                </select>
              </div>
              {/* Instructions */}
              <div className="bg-[#111] border border-white/5 rounded-2xl p-5 flex flex-col flex-1 group relative">
                <div className="flex justify-between items-center mb-3">
                  <h3 className="text-[10px] font-technical text-white uppercase tracking-widest">Aegis Instructions</h3>
                  <button onClick={handleSaveDirectives} disabled={isSaving}
                    className="opacity-0 group-hover:opacity-100 bg-white/10 hover:bg-white/20 p-1.5 rounded text-[10px] font-bold text-white transition-all disabled:opacity-50">{isSaving ? "..." : "SAVE"}</button>
                </div>
                <textarea value={promptData} onChange={e => setPromptData(e.target.value)} disabled={isLoadingConfig}
                  className="flex-1 w-full bg-black border border-white/10 rounded-xl p-4 text-[11px] font-technical text-orange-200 focus:outline-none focus:border-orange-500/50 resize-none leading-relaxed disabled:opacity-50" spellCheck="false" />
              </div>
            </div>
          </div>
        )}

        {/* ═══════════════ TAB: RULES ═══════════════ */}
        {activeTab === 'Rules' && (
          <div className="relative z-10 space-y-4">
            {/* Filters + Add Button */}
            <div className="flex items-center justify-between">
              <div className="flex gap-1 bg-[#0a0a0a] border border-white/5 rounded-lg p-1">
                {['all', 'escalation', 'rate_limit', 'threshold', 'scope', 'permission', 'custom'].map(cat => (
                  <button key={cat} onClick={() => setRuleFilter(cat)}
                    className={`px-3 py-1.5 text-[10px] font-technical uppercase tracking-widest rounded transition-all ${ruleFilter === cat ? 'bg-white/10 text-white' : 'text-neutral-500 hover:text-neutral-300'}`}>
                    {cat === 'all' ? 'All' : cat.replace('_', ' ')}
                  </button>
                ))}
              </div>
              <button onClick={() => setShowAddRule(true)}
                className="bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 text-xs font-technical uppercase px-4 py-2 rounded-lg border border-blue-500/20 transition-colors flex items-center gap-2">
                <span className="material-symbols-outlined text-sm">add</span> Add Rule
              </button>
            </div>

            {/* Rules Table */}
            <div className="bg-[#111] border border-white/5 rounded-2xl overflow-hidden">
              <table className="w-full">
                <thead><tr className="border-b border-white/5">
                  <th className="text-left px-6 py-3 text-[10px] font-technical uppercase text-neutral-500 tracking-widest">Rule</th>
                  <th className="text-left px-4 py-3 text-[10px] font-technical uppercase text-neutral-500 tracking-widest">Category</th>
                  <th className="text-left px-4 py-3 text-[10px] font-technical uppercase text-neutral-500 tracking-widest">Value</th>
                  <th className="text-center px-4 py-3 text-[10px] font-technical uppercase text-neutral-500 tracking-widest">Active</th>
                  <th className="text-center px-4 py-3 text-[10px] font-technical uppercase text-neutral-500 tracking-widest">Type</th>
                  <th className="text-right px-6 py-3 text-[10px] font-technical uppercase text-neutral-500 tracking-widest">Actions</th>
                </tr></thead>
                <tbody>
                  {filteredRules.map(rule => {
                    const config = typeof rule.rule_config === 'string' ? JSON.parse(rule.rule_config) : rule.rule_config;
                    const value = config.enabled !== undefined ? (config.enabled ? 'Yes' : 'No') : config.value !== undefined ? `${config.value}${config.unit ? ` ${config.unit}` : ''}` : config.allowed ? config.allowed.join(', ') : JSON.stringify(config);
                    return (
                      <tr key={rule.id} className="border-b border-white/5 hover:bg-white/[0.02] transition-colors">
                        <td className="px-6 py-4">
                          <div className="text-sm text-white font-medium">{rule.name}</div>
                          <div className="text-[10px] text-neutral-500 mt-0.5">{rule.description}</div>
                        </td>
                        <td className="px-4 py-4"><span className={`text-[10px] font-technical uppercase px-2 py-0.5 rounded border ${CATEGORY_COLORS[rule.category] ?? CATEGORY_COLORS.custom}`}>{rule.category.replace('_', ' ')}</span></td>
                        <td className="px-4 py-4 text-xs font-technical text-neutral-300">{value}</td>
                        <td className="px-4 py-4 text-center">
                          <button onClick={() => handleToggleRule(rule)} className={`w-10 h-5 rounded-full relative transition-colors ${rule.is_active ? 'bg-green-500' : 'bg-neutral-700'}`}>
                            <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${rule.is_active ? 'left-5' : 'left-0.5'}`}></span>
                          </button>
                        </td>
                        <td className="px-4 py-4 text-center"><span className="text-[10px] font-technical text-neutral-500 uppercase">{rule.is_system ? '🔒 System' : 'Custom'}</span></td>
                        <td className="px-6 py-4 text-right">
                          {!rule.is_system && <button onClick={() => handleDeleteRule(rule)} className="text-red-500/50 hover:text-red-500 text-[10px] font-technical uppercase transition-colors">Delete</button>}
                        </td>
                      </tr>
                    );
                  })}
                  {filteredRules.length === 0 && <tr><td colSpan={6} className="px-6 py-12 text-center text-neutral-600 font-technical text-xs">No rules in this category.</td></tr>}
                </tbody>
              </table>
            </div>

            {/* Add Rule Modal */}
            {showAddRule && (
              <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center" onClick={() => setShowAddRule(false)}>
                <div className="bg-[#111] border border-white/10 rounded-2xl p-6 w-full max-w-lg" onClick={e => e.stopPropagation()}>
                  <h3 className="text-lg font-headline font-bold text-white uppercase tracking-wider mb-4">New Aegis Rule</h3>
                  <div className="space-y-3">
                    <div><label className="text-[9px] font-technical uppercase text-neutral-500 mb-1 block">Name</label>
                      <input value={newRule.name} onChange={e => setNewRule(p => ({ ...p, name: e.target.value }))} className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-blue-500 font-technical" placeholder="e.g. Max Ghost Mode Duration" /></div>
                    <div className="flex gap-3">
                      <div className="flex-1"><label className="text-[9px] font-technical uppercase text-neutral-500 mb-1 block">Category</label>
                        <select value={newRule.category} onChange={e => setNewRule(p => ({ ...p, category: e.target.value }))} className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-blue-500 font-technical">
                          {['permission', 'threshold', 'scope', 'escalation', 'rate_limit', 'custom'].map(c => <option key={c} value={c}>{c.replace('_', ' ')}</option>)}
                        </select></div>
                      <div className="flex-1"><label className="text-[9px] font-technical uppercase text-neutral-500 mb-1 block">Type</label>
                        <select value={newRule.rule_type} onChange={e => setNewRule(p => ({ ...p, rule_type: e.target.value }))} className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-blue-500 font-technical">
                          {['boolean', 'numeric', 'select', 'text'].map(t => <option key={t} value={t}>{t}</option>)}
                        </select></div>
                    </div>
                    <div><label className="text-[9px] font-technical uppercase text-neutral-500 mb-1 block">Description</label>
                      <input value={newRule.description} onChange={e => setNewRule(p => ({ ...p, description: e.target.value }))} className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-blue-500 font-technical" placeholder="What does this rule do?" /></div>
                    <div><label className="text-[9px] font-technical uppercase text-neutral-500 mb-1 block">Config (JSON)</label>
                      <textarea value={newRule.rule_config} onChange={e => setNewRule(p => ({ ...p, rule_config: e.target.value }))} className="w-full bg-black border border-white/10 rounded-lg p-3 text-xs text-white focus:outline-none focus:border-blue-500 font-mono h-20 resize-none" spellCheck="false" /></div>
                  </div>
                  <div className="flex justify-end gap-3 mt-6">
                    <button onClick={() => setShowAddRule(false)} className="px-4 py-2 text-xs font-technical uppercase text-neutral-500 hover:text-white transition-colors">Cancel</button>
                    <button onClick={handleCreateRule} className="px-4 py-2 text-xs font-technical uppercase bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors">Create Rule</button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ═══════════════ TAB: TOOLS ═══════════════ */}
        {activeTab === 'Tools' && (
          <div className="relative z-10 space-y-6">
            {['telemetry', 'registry', 'control', 'policy'].map(category => {
              const catTools = tools.filter(t => t.category === category);
              if (catTools.length === 0) return null;
              return (
                <div key={category}>
                  <h3 className={`text-xs font-technical uppercase tracking-widest mb-3 ${TOOL_CATEGORY_COLORS[category]?.split(' ')[0] ?? 'text-neutral-400'}`}>
                    {category} {category === 'control' && '— Privileged'} {category === 'policy' && '— High Impact'}
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                    {catTools.map(tool => (
                      <div key={tool.id} className={`bg-[#111] border rounded-2xl p-5 transition-all ${!tool.is_enabled ? 'opacity-50 border-white/5' : category === 'control' ? 'border-amber-500/20' : category === 'policy' ? 'border-red-500/20' : 'border-white/5'}`}>
                        <div className="flex items-start justify-between mb-3">
                          <div>
                            <h4 className="text-sm text-white font-medium">{tool.display_name}</h4>
                            <span className={`text-[10px] font-technical uppercase px-2 py-0.5 rounded border ${TOOL_CATEGORY_COLORS[tool.category] ?? ''} mt-1 inline-block`}>{tool.category}</span>
                          </div>
                        </div>
                        <p className="text-[10px] text-neutral-500 mb-4 leading-relaxed">{tool.description}</p>
                        <div className="space-y-3 border-t border-white/5 pt-3">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-technical uppercase text-neutral-400">Enabled</span>
                            <button onClick={() => handleToggleTool(tool, 'is_enabled')} className={`w-10 h-5 rounded-full relative transition-colors ${tool.is_enabled ? 'bg-green-500' : 'bg-neutral-700'}`}>
                              <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${tool.is_enabled ? 'left-5' : 'left-0.5'}`}></span>
                            </button>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-technical uppercase text-neutral-400">HITL Required</span>
                            <button onClick={() => handleToggleTool(tool, 'requires_hitl')} className={`w-10 h-5 rounded-full relative transition-colors ${tool.requires_hitl ? 'bg-amber-500' : 'bg-neutral-700'}`}>
                              <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${tool.requires_hitl ? 'left-5' : 'left-0.5'}`}></span>
                            </button>
                          </div>
                          {tool.max_per_hour !== null && (
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-technical uppercase text-neutral-400">Rate Limit</span>
                              <span className="text-[10px] font-technical text-neutral-300">{tool.max_per_hour}/hr</span>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* ═══════════════ TAB: TRACE LOG ═══════════════ */}
        {activeTab === 'Trace Log' && (
          <div className="relative z-10 space-y-4">
            {traces.length === 0 ? (
              <div className="bg-[#111] border border-white/5 rounded-2xl p-16 flex flex-col items-center justify-center text-neutral-600 gap-3">
                <span className="material-symbols-outlined text-5xl opacity-20">timeline</span>
                <p className="font-technical text-sm">No reasoning traces recorded yet.</p>
                <p className="font-technical text-xs text-neutral-700">Traces will appear here as Aegis processes threat signals and makes decisions.</p>
              </div>
            ) : traces.map(trace => (
              <div key={trace.trace_id} className="bg-[#111] border border-white/5 rounded-2xl overflow-hidden transition-all hover:border-white/10">
                <div className="px-6 py-4 flex items-center justify-between border-b border-white/5">
                  <div className="flex items-center gap-4">
                    <span className={`w-2 h-2 rounded-full ${trace.outcome === 'success' ? 'bg-green-500' : trace.outcome === 'blocked' ? 'bg-red-500' : 'bg-amber-500'}`}></span>
                    <div>
                      <span className="text-xs font-technical text-white">{trace.trace_id.substring(0, 12)}…</span>
                      <span className="text-[10px] font-technical text-neutral-500 ml-3">{timeAgo(trace.created_at)}</span>
                    </div>
                    {trace.decision && <span className="text-[10px] font-technical uppercase px-2 py-0.5 rounded border border-cyan-500/20 text-cyan-400 bg-cyan-500/10">{(trace.decision as Record<string, string>).action ?? 'decision'}</span>}
                    {trace.gate_passed !== null && (
                      <span className={`text-[10px] font-technical uppercase px-2 py-0.5 rounded border ${trace.gate_passed ? 'border-green-500/20 text-green-400 bg-green-500/10' : 'border-red-500/20 text-red-400 bg-red-500/10'}`}>
                        {trace.gate_passed ? 'PASSED' : 'BLOCKED'}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-4 text-[10px] font-technical text-neutral-500">
                    <span>{trace.step_count} steps</span>
                    <span>{trace.total_tokens_in + trace.total_tokens_out} tokens</span>
                    <span>{trace.duration_ms}ms</span>
                    {trace.model_id && <span className="text-blue-400">{trace.model_id.split('/').pop()}</span>}
                  </div>
                </div>
                {/* Step summary */}
                <div className="px-6 py-3 flex items-center gap-3 text-[10px] font-technical uppercase tracking-widest">
                  {['trigger', 'context', 'reasoning', 'decision', 'gate', 'execution', 'result'].map((step, i) => (
                    <span key={step} className="flex items-center gap-1">
                      {i > 0 && <span className="text-neutral-700 mx-1">→</span>}
                      <span className={i < trace.step_count ? (step === 'gate' && !trace.gate_passed ? 'text-red-400' : 'text-green-400') : 'text-neutral-700'}>
                        {step}
                      </span>
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

      </main>
    </>
  );
}
