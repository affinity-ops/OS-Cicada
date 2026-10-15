// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

export default function Root() {
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (localStorage.getItem('cicada_token')) {
      router.replace('/dashboard');
    } else {
      setReady(true);
    }
  }, [router]);

  if (!ready) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="w-10 h-10 border-2 border-primary border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-on-surface">
      {/* Nav */}
      <nav className="fixed top-0 inset-x-0 z-50 border-b border-white/5 bg-background/80 backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-primary/20 flex items-center justify-center">
              <span className="material-symbols-outlined text-primary text-base">bug_report</span>
            </div>
            <span className="font-headline font-black text-lg tracking-tight">Cicada</span>
          </div>
          <div className="hidden md:flex items-center gap-8 text-sm text-on-surface-muted">
            <Link href="/pricing" className="hover:text-on-surface transition-colors">Pricing</Link>
            <Link href="/docs" className="hover:text-on-surface transition-colors">Docs</Link>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/login"
              className="text-sm text-on-surface-muted hover:text-on-surface transition-colors"
            >Sign in</Link>
            <Link href="/login"
              className="px-4 py-2 bg-primary text-black rounded-xl text-sm font-headline font-bold hover:brightness-110 transition-all"
            >Get started</Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="pt-40 pb-24 px-6 text-center relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-primary/5 blur-[120px]" />
        </div>
        <div className="relative max-w-4xl mx-auto space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-xs font-technical text-primary">
            <span className="material-symbols-outlined text-[14px]">verified_user</span>
            Ed25519-signed agent identity
          </div>
          <h1 className="text-5xl md:text-7xl font-black font-headline tracking-tighter leading-none">
            The trust layer<br />
            <span className="text-primary">for AI agents</span>
          </h1>
          <p className="text-xl text-on-surface-muted max-w-2xl mx-auto leading-relaxed">
            Register, certify, and monitor your AI agents on the Cicada network.
            Every agent gets a cryptographically-signed EVAR token — so every company they contact knows exactly who sent them.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
            <Link href="/login"
              className="px-8 py-4 btn-gradient text-black rounded-2xl font-headline font-bold text-lg hover:brightness-110 transition-all shadow-lg shadow-primary/20"
            >
              Register your agent
            </Link>
            <Link href="/pricing"
              className="px-8 py-4 border border-white/10 rounded-2xl font-headline font-bold text-lg hover:border-primary/40 hover:bg-white/5 transition-all"
            >
              View pricing
            </Link>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="py-20 px-6 border-t border-white/5">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <h2 className="text-3xl font-black font-headline tracking-tighter">How it works</h2>
            <p className="text-on-surface-muted mt-2">Three steps from code to certified agent</p>
          </div>
          <div className="grid md:grid-cols-3 gap-6">
            {[
              { step: '01', icon: 'how_to_reg', title: 'Register', desc: 'Create your company account and describe your AI agent — its type, scope, and failure behaviour.' },
              { step: '02', icon: 'key',         title: 'Get your EVAR', desc: 'Cicada mints a tamper-proof Ed25519 JWT bound to your agent. Embed it in every outbound request.' },
              { step: '03', icon: 'route',       title: 'Route traffic', desc: 'Every company running Sentry Gateway will validate your EVAR in milliseconds before admitting your agent.' },
            ].map(({ step, icon, title, desc }) => (
              <div key={step} className="relative p-7 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl glow-hover transition-all">
                <div className="absolute top-5 right-5 font-technical text-xs text-on-surface-muted/30">{step}</div>
                <span className="material-symbols-outlined text-primary text-3xl mb-4 block">{icon}</span>
                <h3 className="font-headline font-bold text-lg mb-2">{title}</h3>
                <p className="text-sm text-on-surface-muted leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Trust chain callout */}
      <section className="py-20 px-6 bg-surface-raised border-y border-white/5">
        <div className="max-w-5xl mx-auto grid md:grid-cols-2 gap-12 items-center">
          <div className="space-y-5">
            <h2 className="text-3xl font-black font-headline tracking-tighter">Full traceability — from agent to human</h2>
            <p className="text-on-surface-muted leading-relaxed">
              Every action your agent takes is logged in Cicada's immutable ledger. The chain runs all the way back:
              agent → tenant → contact → verified GitHub or Google identity. No anonymity, by design.
            </p>
            <ul className="space-y-3 text-sm">
              {[
                'Ed25519-signed EVAR tokens, not random strings',
                'OAuth identity linked to every registered agent',
                'Swarm verification on every inbound call',
                'Cryptographic rollback for failed transactions',
              ].map(item => (
                <li key={item} className="flex items-start gap-2 text-on-surface-muted">
                  <span className="material-symbols-outlined text-primary text-base mt-0.5 flex-shrink-0">check_circle</span>
                  {item}
                </li>
              ))}
            </ul>
          </div>
          <div className="font-technical text-xs space-y-2 p-6 bg-black/40 rounded-2xl border border-white/5">
            <p className="text-on-surface-muted/50">// EVAR token chain</p>
            <p><span className="text-primary">action_ledger</span><span className="text-on-surface-muted"> → agent_id</span></p>
            <p className="pl-4"><span className="text-primary">agents</span><span className="text-on-surface-muted"> → tenant_id</span></p>
            <p className="pl-8"><span className="text-primary">tenants</span><span className="text-on-surface-muted"> → contact_id</span></p>
            <p className="pl-12"><span className="text-primary">contacts</span><span className="text-on-surface-muted"> → oauth_identity</span></p>
            <p className="pl-16"><span className="text-green-400">GitHub / Google</span><span className="text-on-surface-muted"> ✓ verified</span></p>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-24 px-6 text-center">
        <div className="max-w-2xl mx-auto space-y-6">
          <h2 className="text-4xl font-black font-headline tracking-tighter">Ready to certify your agent?</h2>
          <p className="text-on-surface-muted">Start on the Starter plan — free for your first agent.</p>
          <Link href="/login"
            className="inline-flex px-10 py-4 btn-gradient text-black rounded-2xl font-headline font-bold text-lg hover:brightness-110 transition-all shadow-lg shadow-primary/20"
          >
            Sign up with GitHub
          </Link>
          <p className="text-xs text-on-surface-muted/50">No credit card required to start</p>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/5 py-10 px-6">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-on-surface-muted">
          <div className="flex items-center gap-2">
            <span className="font-headline font-bold text-on-surface">Cicada</span>
            <span className="text-on-surface-muted/40">—</span>
            <span>AI Agent Trust Layer</span>
          </div>
          <div className="flex gap-6">
            <Link href="/pricing" className="hover:text-on-surface transition-colors">Pricing</Link>
            <Link href="/docs" className="hover:text-on-surface transition-colors">Docs</Link>
            <Link href="/login"  className="hover:text-on-surface transition-colors">Sign in</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
