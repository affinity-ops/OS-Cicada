// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

export default function LicenseGenerationPage() {
  return (
    <div className="p-10 font-body">
      <div className="flex justify-between items-end mb-10">
        <div>
          <h1 className="text-3xl font-black font-headline text-white tracking-tight mb-2">License Generation</h1>
          <p className="text-on-surface-muted max-w-2xl">
            Air-gapped enterprise license minting. Generate `.lic` files with PQC dual-signatures for self-hosted gateways.
          </p>
        </div>
      </div>

      <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-2xl p-8 shadow-2xl">
        <div className="flex items-center gap-4 mb-6">
          <div className="w-12 h-12 bg-primary/20 rounded-xl flex items-center justify-center border border-primary/30">
            <span className="material-symbols-outlined text-primary text-2xl">key</span>
          </div>
          <div>
            <h2 className="text-xl font-bold text-white font-headline">Issue New Enterprise License</h2>
            <p className="text-sm text-on-surface-muted">Fill out the tenant constraints below. Keys never leave the local environment.</p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-6 mb-8">
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-technical uppercase tracking-widest text-primary/70 mb-2">Tenant Identifier</label>
              <input type="text" className="w-full bg-black/50 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-primary transition-colors font-body" placeholder="e.g. tenant_prod_001" />
            </div>
            <div>
              <label className="block text-xs font-technical uppercase tracking-widest text-primary/70 mb-2">License Tier</label>
              <select className="w-full bg-black/50 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-primary transition-colors font-body appearance-none">
                <option>Enterprise (Full Feature Set)</option>
                <option>Standard (No PQC)</option>
                <option>Trial (14-Day Limit)</option>
              </select>
            </div>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-technical uppercase tracking-widest text-primary/70 mb-2">Maximum Agents (Concurrency)</label>
              <input type="number" className="w-full bg-black/50 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-primary transition-colors font-body" placeholder="1000" defaultValue={100} />
            </div>
            <div>
              <label className="block text-xs font-technical uppercase tracking-widest text-primary/70 mb-2">Expiration Date</label>
              <input type="date" className="w-full bg-black/50 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-primary transition-colors font-body" />
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4 bg-background/50 border border-border p-4 rounded-xl mb-8">
          <span className="material-symbols-outlined text-green-400">lock</span>
          <div>
            <div className="text-sm font-bold text-white">Hybrid Cryptography Enabled</div>
            <div className="text-xs text-on-surface-muted">License will be signed with Ed25519 + ML-DSA-65 (FIPS 204).</div>
          </div>
        </div>

        <button className="bg-primary hover:bg-primary-hover text-background font-bold py-3 px-6 rounded-xl transition-colors font-headline flex items-center gap-2 shadow-[0_0_15px_rgba(255,159,74,0.3)]">
          <span className="material-symbols-outlined">generating_tokens</span>
          Generate Cryptographic License
        </button>
      </div>
    </div>
  );
}
