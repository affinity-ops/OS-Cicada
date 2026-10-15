// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

export default function BillingPage() {
  return (
    <div className="p-10 font-body">
      <div className="flex justify-between items-end mb-10">
        <div>
          <h1 className="text-3xl font-black font-headline text-white tracking-tight mb-2">Billing (SaaS)</h1>
          <p className="text-on-surface-muted max-w-2xl">
            Consolidated view of SaaS-hosted tenants, automated invoicing, and overage tracking via Stripe integration.
          </p>
        </div>
        <button className="bg-white/5 hover:bg-white/10 text-white font-bold py-2 px-4 rounded-xl border border-white/10 transition-colors text-sm font-headline flex items-center gap-2">
          <span className="material-symbols-outlined text-[18px]">sync</span>
          Sync Stripe
        </button>
      </div>

      <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-2xl overflow-hidden shadow-2xl">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-surface border-b border-border text-[10px] uppercase font-technical tracking-widest text-primary/70">
              <th className="p-4 pl-6 font-medium">Tenant Name</th>
              <th className="p-4 font-medium">Plan</th>
              <th className="p-4 font-medium">MRR</th>
              <th className="p-4 font-medium">Status</th>
              <th className="p-4 pr-6 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {[
              { name: 'Acme Corp', plan: 'Scale', mrr: '$999', status: 'Active' },
              { name: 'Global Finance LLC', plan: 'Enterprise', mrr: '$4,999', status: 'Active' },
              { name: 'TechStart Inc', plan: 'Growth', mrr: '$299', status: 'Past Due' },
              { name: 'Beta Industries', plan: 'Scale', mrr: '$999', status: 'Active' },
            ].map((tenant, idx) => (
              <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                <td className="p-4 pl-6">
                  <div className="font-bold text-white">{tenant.name}</div>
                  <div className="text-xs text-on-surface-muted mt-0.5">tenant_{idx + 1}28x</div>
                </td>
                <td className="p-4">
                  <span className="px-2.5 py-1 bg-white/5 border border-white/10 rounded text-xs font-bold text-white">
                    {tenant.plan}
                  </span>
                </td>
                <td className="p-4 font-mono text-sm text-white">{tenant.mrr}</td>
                <td className="p-4">
                  <span className={`px-2.5 py-1 rounded text-xs font-bold ${
                    tenant.status === 'Active' 
                      ? 'bg-green-500/10 text-green-400 border border-green-500/20' 
                      : 'bg-red-500/10 text-red-400 border border-red-500/20'
                  }`}>
                    {tenant.status}
                  </span>
                </td>
                <td className="p-4 pr-6 text-right">
                  <button className="text-primary hover:text-white transition-colors text-sm font-bold">
                    View Invoice
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
