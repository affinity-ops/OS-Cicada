// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

export default function SupportTunnelsPage() {
  return (
    <div className="p-10 font-body">
      <div className="flex justify-between items-end mb-10">
        <div>
          <h1 className="text-3xl font-black font-headline text-white tracking-tight mb-2">Support Tunnels</h1>
          <p className="text-on-surface-muted max-w-2xl">
            Secure, ephemeral SSH/Diagnostic tunnels into customer-hosted gateways. Customer must explicitly authorise and provide a one-time token.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-8">
        <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-2xl p-8 shadow-2xl h-fit">
          <div className="flex items-center gap-4 mb-6">
            <div className="w-12 h-12 bg-primary/20 rounded-xl flex items-center justify-center border border-primary/30">
              <span className="material-symbols-outlined text-primary text-2xl">connect_without_contact</span>
            </div>
            <div>
              <h2 className="text-xl font-bold text-white font-headline">Initiate Tunnel</h2>
              <p className="text-sm text-on-surface-muted">Enter the 16-character token provided by the customer.</p>
            </div>
          </div>

          <div className="space-y-6 mb-8">
            <div>
              <label className="block text-xs font-technical uppercase tracking-widest text-primary/70 mb-2">Customer Gateway Token</label>
              <input 
                type="text" 
                className="w-full bg-black/50 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-primary transition-colors font-mono tracking-widest text-center text-xl" 
                placeholder="XXXX-XXXX-XXXX-XXXX" 
              />
            </div>
          </div>

          <button className="w-full bg-primary hover:bg-primary-hover text-background font-bold py-4 rounded-xl transition-colors font-headline flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(255,159,74,0.3)]">
            <span className="material-symbols-outlined">key</span>
            Verify & Connect
          </button>
        </div>

        <div className="bg-black/40 border border-white/10 rounded-2xl p-6 font-mono text-sm shadow-inner relative overflow-hidden group">
          {/* Subtle grid background */}
          <div className="absolute inset-0 bg-[linear-gradient(to_right,#ffffff05_1px,transparent_1px),linear-gradient(to_bottom,#ffffff05_1px,transparent_1px)] bg-[size:14px_24px] pointer-events-none" />
          
          <div className="flex items-center justify-between mb-4 border-b border-white/10 pb-4 relative z-10">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
            </div>
            <div className="text-xs text-on-surface-muted">tunnel_log.txt</div>
          </div>
          
          <div className="space-y-2 text-on-surface-muted relative z-10">
            <div className="flex gap-4">
              <span className="text-primary/50">14:02:11</span>
              <span>Waiting for tunnel initiation...</span>
            </div>
            <div className="flex gap-4 opacity-50">
              <span className="text-primary/50">--:--:--</span>
              <span>Handshake pending customer approval...</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
