// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import { useSession } from '../layout';

const GW_API = process.env.NEXT_PUBLIC_GATEWAY_API_URL || 'http://localhost:8080';

interface Provider {
  id: string;
  name: string;
  protocol: string;
  enabled: boolean;
  oidc_issuer_url: string;
  oidc_client_id: string;
  default_role: string;
  auto_provision: boolean;
}

interface RoleMapping {
  id: string;
  idp_group: string;
  cicada_role: string;
  priority: number;
  description: string;
}

type Tab = 'providers' | 'mappings' | 'test';

export default function FederationPage() {
  const session = useSession();
  const [tab, setTab] = useState<Tab>('providers');
  const [providers, setProviders] = useState<Provider[]>([]);
  const [mappings, setMappings] = useState<RoleMapping[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [showAddProvider, setShowAddProvider] = useState(false);
  const [showAddMapping, setShowAddMapping] = useState(false);
  const [toast, setToast] = useState('');

  // Test resolve state
  const [testGroups, setTestGroups] = useState('');
  const [testResult, setTestResult] = useState<any>(null);

  // New provider form
  const [newProvider, setNewProvider] = useState({
    name: '', protocol: 'oidc', oidc_issuer_url: '', oidc_client_id: '',
    oidc_client_secret: '', oidc_scopes: 'openid profile email groups',
    default_role: 'viewer', auto_provision: true,
  });

  // New mapping form
  const [newMapping, setNewMapping] = useState({
    idp_group: '', cicada_role: 'viewer', priority: 0, description: '',
  });

  const headers = {
    'Content-Type': 'application/json',
    'X-Cicada-Tenant-ID': session?.tenant.id || '',
  };

  useEffect(() => {
    if (!session) return;
    fetchProviders();
  }, [session]);

  useEffect(() => {
    if (selectedProvider) fetchMappings(selectedProvider);
  }, [selectedProvider]);

  async function fetchProviders() {
    setLoading(true);
    try {
      const res = await fetch(`${GW_API}/v1/federation/providers`, { headers });
      const data = await res.json();
      const list = data.providers || data || [];
      setProviders(Array.isArray(list) ? list : []);
      if (list.length > 0 && !selectedProvider) setSelectedProvider(list[0].id);
    } catch { /* empty */ }
    setLoading(false);
  }

  async function fetchMappings(pid: string) {
    try {
      const res = await fetch(`${GW_API}/v1/federation/providers/${pid}/mappings`, { headers });
      const data = await res.json();
      setMappings(data.mappings || []);
    } catch { setMappings([]); }
  }

  async function addProvider(e: React.FormEvent) {
    e.preventDefault();
    const res = await fetch(`${GW_API}/v1/federation/providers`, {
      method: 'POST', headers, body: JSON.stringify({ ...newProvider, enabled: true }),
    });
    if (res.ok) {
      flash('Provider created');
      setShowAddProvider(false);
      setNewProvider({ name: '', protocol: 'oidc', oidc_issuer_url: '', oidc_client_id: '',
        oidc_client_secret: '', oidc_scopes: 'openid profile email groups',
        default_role: 'viewer', auto_provision: true });
      fetchProviders();
    } else flash('Failed to create provider');
  }

  async function addMapping(e: React.FormEvent) {
    e.preventDefault();
    const res = await fetch(`${GW_API}/v1/federation/providers/${selectedProvider}/mappings`, {
      method: 'POST', headers,
      body: JSON.stringify({ ...newMapping, tenant_id: session?.tenant.id }),
    });
    if (res.ok) {
      flash('Mapping created');
      setShowAddMapping(false);
      setNewMapping({ idp_group: '', cicada_role: 'viewer', priority: 0, description: '' });
      fetchMappings(selectedProvider);
    } else flash('Failed to create mapping');
  }

  async function deleteMapping(id: string) {
    await fetch(`${GW_API}/v1/federation/mappings/${id}`, { method: 'DELETE', headers });
    flash('Mapping deleted');
    fetchMappings(selectedProvider);
  }

  async function testResolve() {
    const groups = testGroups.split(',').map(g => g.trim()).filter(Boolean);
    const res = await fetch(`${GW_API}/v1/federation/providers/${selectedProvider}/resolve-role`, {
      method: 'POST', headers, body: JSON.stringify({ groups }),
    });
    setTestResult(await res.json());
  }

  function flash(msg: string) { setToast(msg); setTimeout(() => setToast(''), 3000); }

  const roleColor: Record<string, string> = {
    super_admin: 'text-red-400 bg-red-500/10 border-red-500/20',
    admin: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    operator: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
    viewer: 'text-green-400 bg-green-500/10 border-green-500/20',
    guest: 'text-neutral-400 bg-neutral-500/10 border-neutral-500/20',
  };

  const tabCls = (t: Tab) =>
    `px-4 py-2 text-xs font-technical uppercase tracking-widest rounded-lg transition-colors ${
      tab === t ? 'bg-primary/15 text-primary border border-primary/30' : 'text-on-surface-muted hover:text-on-surface hover:bg-white/5 border border-transparent'
    }`;

  const inputCls = 'w-full bg-black/40 border border-white/10 rounded-lg p-3 text-sm focus:outline-none focus:border-primary transition-colors';
  const labelCls = 'text-[10px] uppercase font-technical text-on-surface-muted tracking-widest block mb-1';
  const cardCls = 'bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-6';

  if (loading) return (
    <div className="flex items-center justify-center p-20">
      <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
    </div>
  );

  return (
    <div className="p-8 max-w-4xl space-y-6">
      {/* Toast */}
      {toast && (
        <div className="fixed top-6 right-6 z-50 bg-green-500/10 border border-green-500/30 text-green-400 px-4 py-3 rounded-xl text-sm font-technical animate-in slide-in-from-top">
          {toast}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-black font-headline tracking-tighter">Identity Federation</h1>
          <p className="text-on-surface-muted text-sm mt-1">
            Configure enterprise IdP integrations, OIDC/SAML providers, and group-to-role mappings
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 bg-primary/10 border border-primary/20 rounded-lg">
          <span className="material-symbols-outlined text-primary text-[16px]">passkey</span>
          <span className="text-[10px] font-technical text-primary uppercase tracking-widest">S6.5</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        <button onClick={() => setTab('providers')} className={tabCls('providers')}>
          <span className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[16px]">cloud</span> Providers
          </span>
        </button>
        <button onClick={() => setTab('mappings')} className={tabCls('mappings')}>
          <span className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[16px]">account_tree</span> Role Mappings
          </span>
        </button>
        <button onClick={() => setTab('test')} className={tabCls('test')}>
          <span className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[16px]">science</span> Test Resolution
          </span>
        </button>
      </div>

      {/* ── Providers Tab ── */}
      {tab === 'providers' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-headline font-bold text-lg">Configured Providers</h2>
            <button onClick={() => setShowAddProvider(!showAddProvider)}
              className="flex items-center gap-2 px-4 py-2 bg-primary text-black rounded-xl text-sm font-headline font-bold hover:brightness-110 transition-all">
              <span className="material-symbols-outlined text-[18px]">add</span>
              Add Provider
            </button>
          </div>

          {showAddProvider && (
            <form onSubmit={addProvider} className={`${cardCls} space-y-4`}>
              <h3 className="font-headline font-bold flex items-center gap-2">
                <span className="material-symbols-outlined text-primary">add_circle</span>
                New Identity Provider
              </h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className={labelCls}>Provider Name</label>
                  <input className={inputCls} placeholder="Okta Production"
                    value={newProvider.name} onChange={e => setNewProvider(v => ({ ...v, name: e.target.value }))} required />
                </div>
                <div>
                  <label className={labelCls}>Protocol</label>
                  <select className={inputCls} value={newProvider.protocol}
                    onChange={e => setNewProvider(v => ({ ...v, protocol: e.target.value }))}>
                    <option value="oidc">OIDC (OpenID Connect)</option>
                    <option value="saml">SAML 2.0</option>
                  </select>
                </div>
                <div>
                  <label className={labelCls}>OIDC Issuer URL</label>
                  <input className={inputCls} placeholder="https://your-org.okta.com"
                    value={newProvider.oidc_issuer_url} onChange={e => setNewProvider(v => ({ ...v, oidc_issuer_url: e.target.value }))} />
                </div>
                <div>
                  <label className={labelCls}>Client ID</label>
                  <input className={inputCls} placeholder="0oa1b2c3d4..."
                    value={newProvider.oidc_client_id} onChange={e => setNewProvider(v => ({ ...v, oidc_client_id: e.target.value }))} />
                </div>
                <div>
                  <label className={labelCls}>Client Secret</label>
                  <input className={inputCls} type="password" placeholder="••••••••"
                    value={newProvider.oidc_client_secret} onChange={e => setNewProvider(v => ({ ...v, oidc_client_secret: e.target.value }))} />
                </div>
                <div>
                  <label className={labelCls}>Scopes</label>
                  <input className={inputCls} placeholder="openid profile email groups"
                    value={newProvider.oidc_scopes} onChange={e => setNewProvider(v => ({ ...v, oidc_scopes: e.target.value }))} />
                </div>
                <div>
                  <label className={labelCls}>Default Role</label>
                  <select className={inputCls} value={newProvider.default_role}
                    onChange={e => setNewProvider(v => ({ ...v, default_role: e.target.value }))}>
                    <option value="guest">Guest</option>
                    <option value="viewer">Viewer</option>
                    <option value="operator">Operator</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>
                <div className="flex items-end pb-1">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={newProvider.auto_provision}
                      onChange={e => setNewProvider(v => ({ ...v, auto_provision: e.target.checked }))}
                      className="w-4 h-4 accent-primary" />
                    <span className="text-sm">Auto-provision operators</span>
                  </label>
                </div>
              </div>
              <div className="flex gap-3">
                <button type="submit" className="px-6 py-2.5 bg-primary text-black rounded-xl text-sm font-headline font-bold hover:brightness-110 transition-all">
                  Create Provider
                </button>
                <button type="button" onClick={() => setShowAddProvider(false)}
                  className="px-6 py-2.5 border border-white/10 rounded-xl text-sm font-headline text-on-surface-muted hover:text-on-surface transition-colors">
                  Cancel
                </button>
              </div>
            </form>
          )}

          {providers.length === 0 ? (
            <div className={`${cardCls} text-center py-12`}>
              <span className="material-symbols-outlined text-[48px] text-on-surface-muted/30 mb-4 block">cloud_off</span>
              <p className="text-on-surface-muted text-sm">No identity providers configured</p>
              <p className="text-on-surface-muted/60 text-xs mt-1">Add an OIDC or SAML provider to enable enterprise SSO</p>
            </div>
          ) : (
            <div className="grid gap-4">
              {providers.map(p => (
                <div key={p.id} className={`${cardCls} cursor-pointer transition-all ${
                  selectedProvider === p.id ? 'border-primary/40 shadow-lg shadow-primary/5' : 'hover:border-white/15'
                }`} onClick={() => setSelectedProvider(p.id)}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                        p.protocol === 'oidc' ? 'bg-blue-500/10 text-blue-400' : 'bg-purple-500/10 text-purple-400'
                      }`}>
                        <span className="material-symbols-outlined text-xl">
                          {p.protocol === 'oidc' ? 'key' : 'shield'}
                        </span>
                      </div>
                      <div>
                        <h3 className="font-headline font-bold">{p.name}</h3>
                        <p className="text-xs text-on-surface-muted font-technical">
                          {p.protocol.toUpperCase()} · {p.oidc_issuer_url || 'SAML'} · Default: {p.default_role}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`text-[10px] font-technical uppercase tracking-widest px-2 py-1 rounded-md border ${
                        p.enabled ? 'text-green-400 bg-green-500/10 border-green-500/20' : 'text-red-400 bg-red-500/10 border-red-500/20'
                      }`}>{p.enabled ? 'Active' : 'Disabled'}</span>
                      {selectedProvider === p.id && (
                        <span className="material-symbols-outlined text-primary text-lg">check_circle</span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Role Mappings Tab ── */}
      {tab === 'mappings' && (
        <div className="space-y-4">
          {!selectedProvider ? (
            <div className={`${cardCls} text-center py-12`}>
              <p className="text-on-surface-muted text-sm">Select a provider on the Providers tab first</p>
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <h2 className="font-headline font-bold text-lg">
                  Group → Role Mappings
                  <span className="ml-2 text-xs text-on-surface-muted font-technical">({mappings.length} rules)</span>
                </h2>
                <button onClick={() => setShowAddMapping(!showAddMapping)}
                  className="flex items-center gap-2 px-4 py-2 bg-primary text-black rounded-xl text-sm font-headline font-bold hover:brightness-110 transition-all">
                  <span className="material-symbols-outlined text-[18px]">add</span>
                  Add Mapping
                </button>
              </div>

              {showAddMapping && (
                <form onSubmit={addMapping} className={`${cardCls} space-y-4`}>
                  <h3 className="font-headline font-bold flex items-center gap-2">
                    <span className="material-symbols-outlined text-primary">account_tree</span>
                    New Role Mapping
                  </h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className={labelCls}>IdP Group Pattern</label>
                      <input className={inputCls} placeholder='engineering, team-*, *-readonly'
                        value={newMapping.idp_group} onChange={e => setNewMapping(v => ({ ...v, idp_group: e.target.value }))} required />
                      <p className="text-[9px] text-on-surface-muted/60 mt-1">Supports exact, prefix-*, *-suffix, and * wildcard</p>
                    </div>
                    <div>
                      <label className={labelCls}>Cicada Role</label>
                      <select className={inputCls} value={newMapping.cicada_role}
                        onChange={e => setNewMapping(v => ({ ...v, cicada_role: e.target.value }))}>
                        <option value="guest">Guest (0)</option>
                        <option value="viewer">Viewer (1)</option>
                        <option value="operator">Operator (2)</option>
                        <option value="admin">Admin (3)</option>
                        <option value="super_admin">Super Admin (4)</option>
                      </select>
                    </div>
                    <div>
                      <label className={labelCls}>Priority</label>
                      <input className={inputCls} type="number" placeholder="0"
                        value={newMapping.priority} onChange={e => setNewMapping(v => ({ ...v, priority: parseInt(e.target.value) || 0 }))} />
                    </div>
                    <div>
                      <label className={labelCls}>Description</label>
                      <input className={inputCls} placeholder="Maps engineering teams to operator"
                        value={newMapping.description} onChange={e => setNewMapping(v => ({ ...v, description: e.target.value }))} />
                    </div>
                  </div>
                  <div className="flex gap-3">
                    <button type="submit" className="px-6 py-2.5 bg-primary text-black rounded-xl text-sm font-headline font-bold hover:brightness-110 transition-all">
                      Create Mapping
                    </button>
                    <button type="button" onClick={() => setShowAddMapping(false)}
                      className="px-6 py-2.5 border border-white/10 rounded-xl text-sm text-on-surface-muted hover:text-on-surface transition-colors">
                      Cancel
                    </button>
                  </div>
                </form>
              )}

              {mappings.length === 0 ? (
                <div className={`${cardCls} text-center py-12`}>
                  <span className="material-symbols-outlined text-[48px] text-on-surface-muted/30 mb-4 block">account_tree</span>
                  <p className="text-on-surface-muted text-sm">No role mappings configured</p>
                  <p className="text-on-surface-muted/60 text-xs mt-1">Add mappings to translate IdP groups to Cicada roles</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {mappings.map(m => (
                    <div key={m.id} className={`${cardCls} !p-4 flex items-center justify-between`}>
                      <div className="flex items-center gap-4">
                        <code className="text-sm font-mono bg-white/5 px-3 py-1.5 rounded-lg border border-white/10">{m.idp_group}</code>
                        <span className="material-symbols-outlined text-on-surface-muted text-[16px]">arrow_forward</span>
                        <span className={`text-xs font-technical uppercase px-2.5 py-1 rounded-md border ${roleColor[m.cicada_role] || roleColor.guest}`}>
                          {m.cicada_role}
                        </span>
                        {m.description && (
                          <span className="text-xs text-on-surface-muted/60 italic">{m.description}</span>
                        )}
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-[10px] font-technical text-on-surface-muted">P{m.priority}</span>
                        <button onClick={() => deleteMapping(m.id)}
                          className="text-red-400/60 hover:text-red-400 transition-colors">
                          <span className="material-symbols-outlined text-[18px]">delete</span>
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ── Test Resolution Tab ── */}
      {tab === 'test' && (
        <div className="space-y-4">
          {!selectedProvider ? (
            <div className={`${cardCls} text-center py-12`}>
              <p className="text-on-surface-muted text-sm">Select a provider on the Providers tab first</p>
            </div>
          ) : (
            <>
              <div className={`${cardCls} space-y-4`}>
                <h2 className="font-headline font-bold flex items-center gap-2">
                  <span className="material-symbols-outlined text-primary">science</span>
                  Dry-Run Role Resolution
                </h2>
                <p className="text-sm text-on-surface-muted">
                  Simulate how IdP groups would resolve to a Cicada role without creating a session.
                </p>
                <div>
                  <label className={labelCls}>IdP Groups (comma-separated)</label>
                  <input className={inputCls} placeholder="engineering, security-admins, team-backend"
                    value={testGroups} onChange={e => setTestGroups(e.target.value)} />
                </div>
                <button onClick={testResolve}
                  className="px-6 py-2.5 bg-primary text-black rounded-xl text-sm font-headline font-bold hover:brightness-110 transition-all">
                  Resolve Role
                </button>
              </div>

              {testResult && (
                <div className={`${cardCls} space-y-3`}>
                  <h3 className="font-headline font-bold flex items-center gap-2">
                    <span className="material-symbols-outlined text-green-400">check_circle</span>
                    Resolution Result
                  </h3>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <p className={labelCls}>Resolved Role</p>
                      <span className={`text-sm font-technical uppercase px-3 py-1.5 rounded-lg border inline-block ${
                        roleColor[testResult.resolved_role] || roleColor.guest
                      }`}>{testResult.resolved_role}</span>
                    </div>
                    <div>
                      <p className={labelCls}>Default Applied</p>
                      <span className={`text-sm font-mono ${testResult.default_applied ? 'text-yellow-400' : 'text-green-400'}`}>
                        {testResult.default_applied ? 'Yes (no rules matched)' : 'No (rule matched)'}
                      </span>
                    </div>
                    {testResult.matched_groups?.length > 0 && (
                      <div>
                        <p className={labelCls}>Matched Groups</p>
                        <div className="flex gap-2 flex-wrap">
                          {testResult.matched_groups.map((g: string) => (
                            <code key={g} className="text-xs bg-white/5 px-2 py-1 rounded border border-white/10">{g}</code>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Info Card */}
      <div className={`${cardCls} !border-primary/15 space-y-2`}>
        <h3 className="font-headline font-bold text-sm flex items-center gap-2">
          <span className="material-symbols-outlined text-primary text-[16px]">info</span>
          Federation Architecture
        </h3>
        <div className="grid grid-cols-3 gap-4 text-xs text-on-surface-muted">
          <div>
            <p className="font-technical uppercase text-[9px] tracking-widest text-primary/60 mb-1">Auth Flow</p>
            <p>OIDC Authorization Code + PKCE with Vault Transit envelope encryption</p>
          </div>
          <div>
            <p className="font-technical uppercase text-[9px] tracking-widest text-primary/60 mb-1">Role Resolution</p>
            <p>Highest-privilege-wins across 5-tier hierarchy (guest → super_admin)</p>
          </div>
          <div>
            <p className="font-technical uppercase text-[9px] tracking-widest text-primary/60 mb-1">Provisioning</p>
            <p>SCIM 2.0 (RFC 7644) auto-provisioning with soft-delete lifecycle</p>
          </div>
        </div>
      </div>
    </div>
  );
}
