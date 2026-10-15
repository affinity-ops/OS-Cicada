// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import Link from 'next/link';

const TIERS = [
  {
    name: 'Starter (Standalone)',
    price: 'Free',
    period: ' / Apache 2.0',
    tag: 'Open Source',
    desc: 'For solo developers and teams self-hosting the standalone Sentry Gateway.',
    features: [
      'Up to 3 registered agents (configurable)',
      'Ed25519 EVAR tokens',
      'Inbound & outbound traffic monitoring',
      'Transaction ledger (30-day retention)',
      'Community support',
    ],
    cta: 'Get started',
    highlight: false,
  },
  {
    name: 'Professional (Mesh)',
    price: 'Self-Hosted',
    period: ' / Connected',
    tag: 'Recommended',
    desc: 'For teams running multiple agents across production workflows with Swarm & Sandbox.',
    features: [
      'Up to 25 registered agents',
      'Verification Swarm confidence scoring',
      'Shadow Sandbox honeypot routing',
      'Policy management controls',
      'Saga rollback for failed transactions',
      '90-day ledger retention',
      'P2P Gossip Mesh telemetry',
    ],
    cta: 'Get started',
    highlight: true,
  },
  {
    name: 'Enterprise (Sovereign)',
    price: 'Cluster',
    period: '',
    tag: null,
    desc: 'For organisations deploying multi-region PQC-attested Sentry Gateway clusters.',
    features: [
      'Unlimited agents',
      'Multi-node Sentry Gateway cluster',
      'Custom BYOK encryption keys',
      'Dedicated swarm nodes',
      'Unlimited ledger retention',
      'Ed25519 + ML-DSA-65 node attestation',
      'Air-gapped deployment support',
    ],
    cta: 'Configure cluster',
    highlight: false,
  },
];

export default function Pricing() {
  return (
    <div className="min-h-screen bg-background text-on-surface">
      {/* Nav */}
      <nav className="fixed top-0 inset-x-0 z-50 border-b border-white/5 bg-background/80 backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-primary/20 flex items-center justify-center">
              <span className="material-symbols-outlined text-primary text-base">bug_report</span>
            </div>
            <span className="font-headline font-black text-lg tracking-tight">Cicada</span>
          </Link>
          <div className="hidden md:flex items-center gap-8 text-sm text-on-surface-muted">
            <Link href="/pricing" className="text-on-surface transition-colors">Pricing</Link>
            <Link href="/docs" className="hover:text-on-surface transition-colors">Docs</Link>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/login" className="text-sm text-on-surface-muted hover:text-on-surface transition-colors">Sign in</Link>
            <Link href="/login" className="px-4 py-2 bg-primary text-black rounded-xl text-sm font-headline font-bold hover:brightness-110 transition-all">Get started</Link>
          </div>
        </div>
      </nav>

      <div className="pt-32 pb-24 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16 space-y-4">
            <h1 className="text-5xl font-black font-headline tracking-tighter">Simple, honest pricing</h1>
            <p className="text-on-surface-muted text-lg max-w-xl mx-auto">
              Start free on the Starter plan. No credit card required for your first agent.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6 items-start">
            {TIERS.map(tier => (
              <div key={tier.name}
                className={`relative rounded-2xl p-7 flex flex-col gap-6 border transition-all ${
                  tier.highlight
                    ? 'bg-primary/5 border-primary/30 shadow-xl shadow-primary/10'
                    : 'bg-surface-raised border-[rgba(255,159,74,0.08)]'
                }`}
              >
                {tier.tag && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                    <span className="px-3 py-1 bg-primary text-black text-xs font-headline font-bold rounded-full whitespace-nowrap">
                      {tier.tag}
                    </span>
                  </div>
                )}

                <div>
                  <p className="font-headline font-bold text-on-surface-muted uppercase tracking-widest text-xs mb-2">{tier.name}</p>
                  <div className="flex items-end gap-1">
                    <span className="text-4xl font-black font-headline">{tier.price}</span>
                    {tier.period && <span className="text-on-surface-muted mb-1">{tier.period}</span>}
                  </div>
                  <p className="text-sm text-on-surface-muted mt-2 leading-relaxed">{tier.desc}</p>
                </div>

                <ul className="space-y-2.5 flex-1">
                  {tier.features.map(f => (
                    <li key={f} className="flex items-start gap-2 text-sm">
                      <span className="material-symbols-outlined text-primary text-base mt-0.5 flex-shrink-0">check</span>
                      <span className="text-on-surface-muted">{f}</span>
                    </li>
                  ))}
                </ul>

                <Link href="/login"
                  className={`block text-center px-5 py-3 rounded-xl font-headline font-bold transition-all ${
                    tier.highlight
                      ? 'btn-gradient text-black hover:brightness-110'
                      : 'border border-white/10 hover:border-primary/30 hover:bg-white/5'
                  }`}
                >
                  {tier.cta}
                </Link>
              </div>
            ))}
          </div>

          <div className="mt-16 p-6 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl flex items-start gap-4">
            <span className="material-symbols-outlined text-primary text-2xl flex-shrink-0 mt-0.5">info</span>
            <div>
              <p className="font-headline font-bold text-sm mb-1">All plans include</p>
              <p className="text-sm text-on-surface-muted">
                OAuth identity verification (GitHub / Google), Ed25519 EVAR token minting,
                immutable action ledger, and access to the Developer Portal.
                Enterprise plans include the self-hosted Sentry Gateway binary.
              </p>
            </div>
          </div>
        </div>
      </div>

      <footer className="border-t border-white/5 py-10 px-6">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-on-surface-muted">
          <div className="flex items-center gap-2">
            <span className="font-headline font-bold text-on-surface">Cicada</span>
            <span className="text-on-surface-muted/40">—</span>
            <span>AI Agent Trust Layer</span>
          </div>
          <div className="flex gap-6">
            <Link href="/"       className="hover:text-on-surface transition-colors">Home</Link>
            <Link href="/docs"   className="hover:text-on-surface transition-colors">Docs</Link>
            <Link href="/login"  className="hover:text-on-surface transition-colors">Sign in</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
