// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import { operatorFetch } from '@/lib/operatorFetch';

import { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';

const API = process.env.NEXT_PUBLIC_CORE_API_URL ?? 'http://localhost:8000';

interface PolicyException {
  agent_id: string;
  agent_name: string;
  reason: string;
  added_at: string;
}

interface PlatformPolicy {
  id: string;
  slug: string;
  name: string;
  description: string;
  filename: string;
  environment: string;
  status: string;
  rule_config: string;
  exceptions: string;
  line_count: number;
}

interface TestResult {
  policy_slug: string;
  agent_id?: string;
  agent_name?: string;
  tenant_name?: string;
  agent_score?: number;
  min_score?: number;
  trust_tier?: string;
  trace_id?: string;
  target_api?: string;
  blocked: boolean;
  reason: string;
}

const RULE_DISPLAY: Record<string, { codeBlocks: { indent?: number; t?: string; v?: string; err?: boolean; comment?: string }[] }> = {
  block_untrusted_traffic: {
    codeBlocks: [
      { t: 'policy:', v: 'global_ingress_v1' },
      { t: 'metadata:', v: '' },
      { indent: 1, t: 'author:', v: '"system_operator"' },
      { indent: 1, t: 'version:', v: '2.4.0' },
      { t: 'rules:', v: '' },
      { indent: 1, comment: '# Block all requests from unrecognised sources' },
      { indent: 1, t: '- name:', v: '"Block_Unknown"' },
      { indent: 2, t: 'action:', v: 'DENY', err: true },
      { indent: 2, t: 'priority:', v: '100' },
      { indent: 2, t: 'condition:' },
      { indent: 3, t: 'source:' },
      { indent: 4, t: 'not_in:', v: '"trusted_zones"' },
    ],
  },
  trust_score_check: {
    codeBlocks: [
      { t: 'package', v: 'sentry.auth.gateway' },
      { t: '', v: '' },
      { t: 'default allow = false' },
      { t: '', v: '' },
      { comment: '# Only allow agents above the minimum trust score' },
      { t: 'allow {', v: '' },
      { indent: 1, t: 'input.agent.trust_score >=', v: '80' },
      { indent: 1, t: 'not', v: 'contains_dangerous_patterns(input.payload)' },
      { t: '}' },
      { t: '', v: '' },
      { comment: '# Approved exceptions' },
      { t: 'exception_list := [', v: '' },
      { indent: 1, t: '"Agent-0x4AA",', v: '' },
      { indent: 1, t: '"QueryWorker-B"', v: '' },
      { t: ']' },
    ],
  },
};

function SecurityPoliciesCore() {
  const searchParams = useSearchParams();
  const [policies, setPolicies] = useState<PlatformPolicy[]>([]);
  const [activeSlug, setActiveSlug] = useState<string>('block_untrusted_traffic');
  const [testPhase, setTestPhase] = useState<'idle' | 'testing' | 'blocked' | 'clear' | 'applying' | 'resolved'>('idle');
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [terminalLogs, setTerminalLogs] = useState<{ time: string; sys: string; msg: string; cls?: string }[]>([
    { time: '--', sys: 'SYSTEM', msg: 'Loaded. Select a rule and click Run Test to check it against live data.' },
  ]);
  const [loadingPolicies, setLoadingPolicies] = useState(true);

  useEffect(() => {
    operatorFetch(`${API}/api/v1/security/policies`)
      .then(r => r.json())
      .then(body => {
        if (body.status === 'success') {
          setPolicies(body.data);
          const urlSlug = searchParams.get('rule');
          if (urlSlug && body.data.find((p: PlatformPolicy) => p.slug === urlSlug)) {
            setActiveSlug(urlSlug);
          }
        }
      })
      .catch(() => {})
      .finally(() => setLoadingPolicies(false));
  }, []);

  const activePolicy = policies.find(p => p.slug === activeSlug);
  const exceptions: PolicyException[] = activePolicy
    ? JSON.parse(activePolicy.exceptions ?? '[]')
    : [];

  const config = activePolicy ? JSON.parse(activePolicy.rule_config ?? '{}') : {};

  const switchPolicy = (slug: string) => {
    setActiveSlug(slug);
    setTestPhase('idle');
    setTestResult(null);
    setTerminalLogs([{ time: '--', sys: 'SYSTEM', msg: `Loaded policy: ${policies.find(p => p.slug === slug)?.name ?? slug}` }]);
  };

  const runTest = async () => {
    setTestPhase('testing');
    setTestResult(null);
    setTerminalLogs([{ time: now(), sys: 'SYSTEM', msg: `Running test for: ${activePolicy?.name}...` }]);

    try {
      const res = await operatorFetch(`${API}/api/v1/security/policies/${activeSlug}/test`, { method: 'POST' });
      const body = await res.json();

      if (body.status !== 'success') throw new Error(body.message ?? 'Test failed');

      const result: TestResult = body.data;
      setTestResult(result);

      if (result.blocked) {
        setTestPhase('blocked');
        setTerminalLogs(prev => [
          ...prev,
          { time: now(), sys: 'CHECK', msg: `Agent: ${result.agent_name} (${result.tenant_name})` },
          { time: now(), sys: 'CHECK', msg: result.min_score ? `Trust score: ${result.agent_score} — minimum required: ${result.min_score}` : `Source trust tier: ${result.trust_tier}` },
          { time: now(), sys: 'BLOCKED', msg: `✗ ${result.reason}`, cls: 'text-error font-bold' },
        ]);
      } else {
        setTestPhase('clear');
        setTerminalLogs(prev => [
          ...prev,
          { time: now(), sys: 'CHECK', msg: result.reason },
          { time: now(), sys: 'PASS', msg: '✓ Policy check passed — no issues found.', cls: 'text-emerald-400 font-bold' },
        ]);
      }
    } catch {
      setTestPhase('idle');
      setTerminalLogs(prev => [...prev, { time: now(), sys: 'ERROR', msg: 'Could not run test. Check API connection.', cls: 'text-error' }]);
    }
  };

  const addException = async () => {
    if (!testResult?.agent_id) return;

    setTestPhase('applying');
    setTerminalLogs(prev => [...prev, { time: now(), sys: 'SYSTEM', msg: `Adding ${testResult.agent_name} to the approved exceptions list...` }]);

    try {
      const res = await operatorFetch(`${API}/api/v1/security/policies/${activeSlug}/exceptions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent_id:   testResult.agent_id,
          agent_name: testResult.agent_name,
          reason:     'Manually approved by operator via security policy test',
        }),
      });

      const body = await res.json();
      if (body.status !== 'success') throw new Error(body.message ?? 'Failed');

      setTestPhase('resolved');
      setTerminalLogs(prev => [
        ...prev,
        { time: now(), sys: 'UPDATE', msg: 'Exception written to database.' },
        { time: now(), sys: 'OK', msg: `✓ ${testResult.agent_name} is now approved. Trust tier updated to: elevated.`, cls: 'text-emerald-400 font-bold' },
      ]);

      // Refresh policy data to show updated exceptions list
      const refresh = await operatorFetch(`${API}/api/v1/security/policies/${activeSlug}`);
      const rbody = await refresh.json();
      if (rbody.status === 'success') {
        setPolicies(prev => prev.map(p => p.slug === activeSlug ? rbody.data : p));
      }
    } catch {
      setTestPhase('blocked');
      setTerminalLogs(prev => [...prev, { time: now(), sys: 'ERROR', msg: 'Could not apply exception. Check API connection.', cls: 'text-error' }]);
    }
  };

  const removeException = async (agentId: string) => {
    await operatorFetch(`${API}/api/v1/security/policies/${activeSlug}/exceptions/${agentId}`, { method: 'DELETE' });
    const refresh = await operatorFetch(`${API}/api/v1/security/policies/${activeSlug}`);
    const rbody = await refresh.json();
    if (rbody.status === 'success') {
      setPolicies(prev => prev.map(p => p.slug === activeSlug ? rbody.data : p));
    }
  };

  const codeBlocks = RULE_DISPLAY[activeSlug]?.codeBlocks ?? [];

  return (
    <>
      <Sidebar />
      <TopAppBar />

      <main className="pt-24 p-8 min-h-screen relative z-10 transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        <div className="max-w-[95%] mx-auto">

          <div className="flex items-end justify-between mb-10">
            <div>
              <h2 className="text-5xl font-black font-headline tracking-tighter text-on-surface uppercase">Security Policies</h2>
              <p className="text-on-surface-variant font-body mt-2 max-w-xl">View and test the rules that control which agents are allowed to operate on your platform.</p>
            </div>
            <div className="flex items-center gap-3">
              <div className={`flex items-center gap-2 px-4 py-2 ${testPhase === 'blocked' ? 'bg-error/10 border-error/20' : testPhase === 'resolved' ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-[#1a1a1a] border-white/5'} rounded-xl border transition-all`}>
                <span className={`w-2 h-2 rounded-full animate-pulse ${testPhase === 'blocked' ? 'bg-error' : testPhase === 'resolved' ? 'bg-emerald-500' : 'bg-neutral-500'}`}></span>
                <span className={`text-xs font-technical uppercase tracking-widest ${testPhase === 'blocked' ? 'text-error' : testPhase === 'resolved' ? 'text-emerald-500' : 'text-neutral-400'}`}>
                  {testPhase === 'blocked' ? 'AGENT BLOCKED' : testPhase === 'resolved' ? 'EXCEPTION APPLIED' : testPhase === 'clear' ? 'ALL CLEAR' : 'READY'}
                </span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-6">

            {/* Rule Selector + Details */}
            <div className="col-span-12 xl:col-span-3 space-y-6">

              <div className="bg-[#131313] rounded-2xl p-6 border border-white/5">
                <p className="text-[10px] font-headline font-bold text-neutral-500 tracking-widest uppercase mb-4">Active Rules</p>
                {loadingPolicies ? (
                  <p className="text-neutral-600 font-technical text-xs animate-pulse">Loading policies...</p>
                ) : (
                  <div className="space-y-3">
                    {policies.map(policy => (
                      <div
                        key={policy.slug}
                        onClick={() => switchPolicy(policy.slug)}
                        className={`p-3 rounded-xl border-l-[3px] transition-all cursor-pointer group ${activeSlug === policy.slug ? 'bg-[#262626] border-primary shadow-md' : 'bg-[#1a1a1a] border-neutral-700 hover:bg-neutral-800'}`}
                      >
                        <p className={`text-xs font-bold transition-colors ${activeSlug === policy.slug ? 'text-primary' : 'text-neutral-500 group-hover:text-neutral-300'}`}>{policy.name}</p>
                        <p className="text-[10px] text-neutral-600 mt-1">{policy.description}</p>
                        {policy.status === 'warning' && activeSlug !== policy.slug && (
                          <p className="text-[9px] font-technical text-secondary mt-2 animate-pulse uppercase">➔ Issue detected</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {activePolicy && (
                <div className="bg-[#131313] rounded-2xl p-6 border border-white/5">
                  <p className="text-[10px] font-headline font-bold text-orange-500 tracking-widest uppercase mb-4">Rule Details</p>
                  <h3 className="font-headline text-sm font-bold mb-4 truncate text-neutral-200">{activePolicy.filename}</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-neutral-500">Lines</span>
                      <span className="font-technical text-neutral-200">{activePolicy.line_count}</span>
                    </div>
                    {config.min_trust_score !== undefined && (
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-neutral-500">Min. trust score</span>
                        <span className="font-technical text-orange-400 font-bold">{config.min_trust_score}</span>
                      </div>
                    )}
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-neutral-500">Status</span>
                      <span className={`font-bold ${activePolicy.status === 'healthy' ? 'text-emerald-500' : 'text-orange-400'}`}>{activePolicy.status === 'healthy' ? 'Healthy' : 'Warning'}</span>
                    </div>
                    <div className="flex justify-between items-center text-xs pt-3 border-t border-white/5">
                      <span className="text-neutral-500">Environment</span>
                      <span className={`px-2 py-0.5 rounded border text-[9px] uppercase tracking-widest ${activePolicy.environment === 'production' ? 'bg-orange-500/10 text-orange-500 border-orange-500/20' : 'bg-secondary/10 text-secondary border-secondary/20'}`}>{activePolicy.environment}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Exceptions list */}
              {exceptions.length > 0 && (
                <div className="bg-[#131313] rounded-2xl p-6 border border-white/5">
                  <p className="text-[10px] font-headline font-bold text-neutral-500 tracking-widest uppercase mb-4">Approved Exceptions</p>
                  <div className="space-y-3">
                    {exceptions.map(ex => (
                      <div key={ex.agent_id} className="flex items-center justify-between gap-2">
                        <div>
                          <p className="text-xs font-bold text-emerald-400">{ex.agent_name}</p>
                          <p className="text-[10px] text-neutral-600">{ex.reason}</p>
                        </div>
                        <button
                          onClick={() => removeException(ex.agent_id)}
                          className="text-[10px] text-neutral-600 hover:text-error transition-colors flex-shrink-0"
                          title="Remove exception"
                        >
                          <span className="material-symbols-outlined text-[14px]">close</span>
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Rule viewer + test terminal */}
            <div className="col-span-12 xl:col-span-9 space-y-6">
              <div className="bg-black rounded-2xl border border-white/10 overflow-hidden shadow-2xl flex flex-col h-[700px]">

                {/* Toolbar */}
                <div className="bg-[#1a1a1a] border-b border-white/5 px-6 py-3 flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="flex items-center gap-1.5">
                      <span className="w-3 h-3 rounded-full bg-[#ff5f56]"></span>
                      <span className="w-3 h-3 rounded-full bg-[#ffbd2e]"></span>
                      <span className="w-3 h-3 rounded-full bg-[#27c93f]"></span>
                    </div>
                    <div className="h-4 w-[1px] bg-neutral-700 mx-2"></div>
                    <span className="font-technical text-xs text-neutral-400">{activePolicy?.filename ?? 'No policy selected'}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={runTest}
                      disabled={testPhase === 'testing' || testPhase === 'applying' || !activePolicy}
                      className={`px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${testPhase === 'testing' || testPhase === 'applying' ? 'opacity-50 cursor-not-allowed border border-white/10 text-neutral-500' : 'bg-primary/10 text-primary border border-primary/20 hover:bg-primary hover:text-black'}`}
                    >
                      {testPhase === 'testing' ? 'TESTING...' : 'RUN TEST'}
                    </button>
                    {testPhase === 'blocked' && testResult?.agent_id && (
                      <button
                        onClick={addException}
                        className="bg-emerald-500 text-black px-4 py-1.5 rounded-lg text-xs font-bold font-headline tracking-widest shadow-[0_0_15px_rgba(16,185,129,0.3)] hover:bg-emerald-400 transition-all ml-2 animate-bounce"
                      >
                        ADD EXCEPTION
                      </button>
                    )}
                  </div>
                </div>

                {/* Rule code view */}
                <div className="flex-1 flex font-technical text-[13px] overflow-hidden bg-[#0a0a0a]">
                  <div className="w-12 bg-[#111] py-4 text-right pr-4 text-neutral-600 select-none border-r border-white/5">
                    {codeBlocks.map((_, i) => <div key={i}>{String(i + 1).padStart(2, '0')}</div>)}
                  </div>
                  <div className="flex-1 py-4 px-6 overflow-y-auto w-full relative">
                    {codeBlocks.map((line, i) => (
                      <div key={i} className="flex tracking-[0.02em] opacity-90 hover:opacity-100 hover:bg-white/5 -mx-4 px-4" style={{ paddingLeft: `${16 + (line.indent ?? 0) * 16}px` }}>
                        {line.comment ? (
                          <span className="text-neutral-500 italic">{line.comment}</span>
                        ) : (
                          <>
                            <span className="text-primary">{line.t}</span>
                            {line.v && (
                              <span className={line.err ? 'text-error font-bold ml-1' : 'text-secondary ml-1'}>{line.v}</span>
                            )}
                          </>
                        )}
                      </div>
                    ))}

                    {testPhase === 'resolved' && testResult && (
                      <div className="absolute top-[208px] left-[16px] -right-2 bg-emerald-500/10 border border-emerald-500/30 px-3 py-1 animate-pulse flex items-center gap-4">
                        <span className="text-emerald-400 font-bold">&quot;{testResult.agent_name}&quot;,
                          <span className="text-neutral-500 text-[10px] ml-4 font-normal">// Added as exception — {new Date().toLocaleString()}</span>
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Test output terminal */}
                <div
                  className="h-48 bg-[#000] border-t-2 border-white/10 p-4 font-technical text-[11px] overflow-hidden relative transition-colors shadow-inner"
                  style={testPhase === 'blocked' ? { borderTopColor: '#ff5f56' } : testPhase === 'resolved' ? { borderTopColor: '#27c93f' } : {}}
                >
                  <div className="h-full overflow-y-auto space-y-2 pb-6">
                    {terminalLogs.map((log, i) => (
                      <div key={i} className="flex gap-3 items-start">
                        <span className="text-neutral-600 shrink-0">[{log.time}]</span>
                        <span className={`shrink-0 font-bold ${log.sys === 'BLOCKED' || log.sys === 'ERROR' ? 'text-error' : log.sys === 'OK' || log.sys === 'PASS' ? 'text-emerald-500' : log.sys === 'UPDATE' ? 'text-cyan-400' : 'text-orange-500'}`}>{log.sys}:</span>
                        <span className={log.cls ?? 'text-neutral-400'}>{log.msg}</span>
                      </div>
                    ))}
                    {(testPhase === 'testing' || testPhase === 'applying') && (
                      <div className="flex items-center gap-2 mt-2 opacity-50">
                        <span className="w-1.5 h-3 bg-white animate-pulse"></span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom stats */}
          <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className={`backdrop-blur-sm p-6 rounded-2xl border transition-colors ${testPhase === 'resolved' ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-[#1a1a1a]/30 border-white/5'}`}>
              <p className="text-[10px] font-headline font-bold text-neutral-500 tracking-widest uppercase mb-1">Requests Blocked</p>
              <p className="text-3xl font-black font-headline text-on-surface">
                {testPhase === 'resolved' ? '1,203' : '1,204'}
                <span className={`text-sm font-medium ml-2 ${testPhase === 'resolved' ? 'text-emerald-500' : 'text-error'}`}>
                  {testPhase === 'resolved' ? '↓ Resolved' : '↑ Live'}
                </span>
              </p>
              <div className="mt-4 h-1 w-full bg-neutral-800 rounded-full overflow-hidden">
                <div className={`h-full transition-all duration-1000 ${testPhase === 'resolved' ? 'w-[55%] bg-emerald-500' : 'w-[65%] bg-error'}`}></div>
              </div>
            </div>
            <div className="backdrop-blur-sm p-6 rounded-2xl border bg-[#1a1a1a]/30 border-white/5">
              <p className="text-[10px] font-headline font-bold text-neutral-500 tracking-widest uppercase mb-1">Response Time</p>
              <p className="text-3xl font-black font-headline text-on-surface">{testPhase === 'resolved' ? '12' : '114'}<span className="text-xs text-neutral-400 font-technical ml-1">ms</span></p>
              <div className="mt-4 h-1 w-full bg-neutral-800 rounded-full overflow-hidden">
                <div className={`h-full transition-all duration-1000 bg-secondary ${testPhase === 'resolved' ? 'w-[10%]' : 'w-[85%]'}`}></div>
              </div>
            </div>
            <div className={`backdrop-blur-sm p-6 rounded-2xl border transition-colors ${testPhase === 'resolved' ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-[#1a1a1a]/30 border-white/5'}`}>
              <p className="text-[10px] font-headline font-bold text-neutral-500 tracking-widest uppercase mb-1">Policy Health</p>
              <p className={`text-3xl font-black font-headline ${testPhase === 'resolved' ? 'text-emerald-500' : 'text-orange-500'}`}>{testPhase === 'resolved' ? '100%' : '90.2%'}</p>
              <div className="mt-4 h-1 w-full bg-neutral-800 rounded-full overflow-hidden">
                <div className={`h-full transition-all duration-1000 ${testPhase === 'resolved' ? 'w-full bg-emerald-500' : 'w-[90%] bg-orange-500'}`}></div>
              </div>
            </div>
          </div>

        </div>
      </main>

      <div className="fixed inset-0 pointer-events-none overflow-hidden -z-10">
        <div className="absolute top-1/4 -right-20 w-[600px] h-[600px] bg-primary/5 rounded-full blur-[120px]"></div>
        <div className="absolute -bottom-20 -left-20 w-[400px] h-[400px] bg-secondary/5 rounded-full blur-[100px]"></div>
      </div>
    </>
  );
}

function now() {
  return new Date().toLocaleTimeString();
}

export default function SecurityPolicies() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-black flex items-center justify-center text-primary font-technical animate-pulse">Loading...</div>}>
      <SecurityPoliciesCore />
    </Suspense>
  );
}
