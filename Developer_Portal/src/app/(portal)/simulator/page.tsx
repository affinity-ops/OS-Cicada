// © 2026 Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useState } from 'react';
import { useSession } from '../layout';

export default function PolicySimulator() {
  const session = useSession();
  const [evar, setEvar] = useState('');
  const [endpoint, setEndpoint] = useState('/v1/agent/proxy');
  const [targetUrl, setTargetUrl] = useState('https://api.example.com/data');
  const [method, setMethod] = useState('POST');
  const [payload, setPayload] = useState('{\n  "query": "Find the latest financial data",\n  "tools_used": ["search"]\n}');
  const [provider, setProvider] = useState('openai');
  const [model, setModel] = useState('gpt-4o');
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  async function runSimulation() {
    setLoading(true);
    setResponse(null);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${evar}`,
        'X-Cicada-Dry-Run': 'true',
      };

      if (endpoint === '/v1/agent/proxy') {
        headers['X-Cicada-Target-URL'] = targetUrl;
      } else {
        headers['X-Cicada-LLM-Provider'] = provider;
        headers['X-Cicada-LLM-Model'] = model;
      }

      const gatewayUrl = process.env.NEXT_PUBLIC_GATEWAY_URL ?? 'http://localhost:8080';
      const res = await fetch(`${gatewayUrl}${endpoint}`, {
        method,
        headers,
        body: ['GET', 'HEAD'].includes(method) ? undefined : payload,
      });

      const data = await res.json().catch(() => ({ error: 'Failed to parse JSON response' }));
      
      setResponse({
        status: res.status,
        headers: Object.fromEntries(res.headers.entries()),
        data,
      });
    } catch (err: any) {
      setResponse({ error: err.message });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-8 space-y-6 max-w-6xl">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Policy Simulator</h1>
        <p className="text-on-surface-muted text-sm mt-1">Run dry-run tests against your agent's policies without forwarding requests to the target API.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Form */}
        <div className="space-y-5 bg-surface-raised border border-[rgba(255,159,74,0.08)] p-6 rounded-2xl">
          <div>
            <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1.5">Agent EVAR Token</label>
            <input 
              type="password" 
              value={evar} 
              onChange={e => setEvar(e.target.value)} 
              placeholder="evr_..."
              className="w-full bg-[#0a0a0a] border border-[rgba(255,159,74,0.1)] rounded-lg px-4 py-2.5 text-sm font-mono focus:border-primary/50 outline-none"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1.5">Proxy Endpoint</label>
              <select 
                value={endpoint} 
                onChange={e => setEndpoint(e.target.value)}
                className="w-full bg-[#0a0a0a] border border-[rgba(255,159,74,0.1)] rounded-lg px-4 py-2.5 text-sm focus:border-primary/50 outline-none appearance-none"
              >
                <option value="/v1/agent/proxy">Target API Proxy</option>
                <option value="/v1/llm/proxy">LLM Provider Proxy</option>
              </select>
            </div>
            <div>
              <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1.5">HTTP Method</label>
              <select 
                value={method} 
                onChange={e => setMethod(e.target.value)}
                className="w-full bg-[#0a0a0a] border border-[rgba(255,159,74,0.1)] rounded-lg px-4 py-2.5 text-sm focus:border-primary/50 outline-none appearance-none"
              >
                <option>POST</option>
                <option>GET</option>
                <option>PUT</option>
                <option>PATCH</option>
                <option>DELETE</option>
              </select>
            </div>
          </div>

          {endpoint === '/v1/agent/proxy' ? (
            <div>
              <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1.5">Target URL</label>
              <input 
                type="text" 
                value={targetUrl} 
                onChange={e => setTargetUrl(e.target.value)} 
                className="w-full bg-[#0a0a0a] border border-[rgba(255,159,74,0.1)] rounded-lg px-4 py-2.5 text-sm font-mono focus:border-primary/50 outline-none"
              />
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1.5">Provider</label>
                <select 
                  value={provider} 
                  onChange={e => setProvider(e.target.value)}
                  className="w-full bg-[#0a0a0a] border border-[rgba(255,159,74,0.1)] rounded-lg px-4 py-2.5 text-sm focus:border-primary/50 outline-none appearance-none"
                >
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1.5">Model</label>
                <input 
                  type="text" 
                  value={model} 
                  onChange={e => setModel(e.target.value)} 
                  className="w-full bg-[#0a0a0a] border border-[rgba(255,159,74,0.1)] rounded-lg px-4 py-2.5 text-sm font-mono focus:border-primary/50 outline-none"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mb-1.5">JSON Payload</label>
            <textarea 
              value={payload} 
              onChange={e => setPayload(e.target.value)} 
              rows={8}
              className="w-full bg-[#0a0a0a] border border-[rgba(255,159,74,0.1)] rounded-lg px-4 py-3 text-sm font-mono focus:border-primary/50 outline-none resize-y"
            />
          </div>

          <button 
            onClick={runSimulation}
            disabled={loading || !evar}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-lg bg-primary text-black font-headline font-bold hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {loading ? <div className="w-5 h-5 border-2 border-black border-t-transparent rounded-full animate-spin" /> : <span className="material-symbols-outlined text-[20px]">play_arrow</span>}
            {loading ? 'Running...' : 'Run Dry-Run Simulation'}
          </button>
        </div>

        {/* Output Area */}
        <div className="bg-[#0a0a0a] border border-[rgba(255,159,74,0.1)] rounded-2xl flex flex-col overflow-hidden">
          <div className="px-5 py-4 border-b border-[rgba(255,159,74,0.1)] flex items-center justify-between bg-surface-raised">
            <h2 className="text-sm font-headline font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-primary">terminal</span>
              Simulation Output
            </h2>
            {response?.status && (
              <span className={`text-[10px] font-technical px-2.5 py-1 rounded-full ${response.status >= 200 && response.status < 300 ? 'bg-green-400/10 text-green-400' : 'bg-red-400/10 text-red-400'}`}>
                HTTP {response.status}
              </span>
            )}
          </div>
          <div className="p-5 flex-1 overflow-y-auto">
            {!response ? (
              <div className="h-full flex flex-col items-center justify-center text-on-surface-muted/50">
                <span className="material-symbols-outlined text-4xl mb-2">code_blocks</span>
                <p className="text-xs font-technical">Output will appear here</p>
              </div>
            ) : (
              <pre className="text-[11px] font-mono whitespace-pre-wrap break-all text-on-surface">
                {JSON.stringify(response.data, null, 2)}
              </pre>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
