// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState } from 'react';

interface Tier {
  name: string;
  price: string;
  period: string;
  description: string;
  meshTier: string;
  features: string[];
  highlight?: boolean;
  cta: string;
  icon: string;
}

const TIERS: Tier[] = [
  {
    name: 'Standalone',
    price: '$2,500',
    period: '/year',
    description: 'Self-hosted AI gateway with full security inspection. No mesh connectivity.',
    meshTier: 'standalone',
    icon: 'shield',
    cta: 'Get Started',
    features: [
      'Sentry Gateway (full binary)',
      'Prompt injection scanner',
      'Exfiltration detection',
      'Canary token engine',
      'Up to 50 concurrent agents',
      'PQC hybrid licensed (.lic)',
      'Gateway Portal (operator UI)',
      'Community support',
    ],
  },
  {
    name: 'Connected',
    price: '$7,500',
    period: '/year',
    description: 'Everything in Standalone, plus P2P mesh for collective threat intelligence.',
    meshTier: 'connected',
    icon: 'hub',
    highlight: true,
    cta: 'Most Popular',
    features: [
      'Everything in Standalone',
      'P2P gossip mesh access',
      'Anonymised threat intel sharing',
      'Collective attack blocklist',
      'Up to 250 concurrent agents',
      'Ed25519 + ML-DSA-65 mesh auth',
      'Mesh peer discovery',
      'Priority email support',
    ],
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    period: '',
    description: 'Unlimited scale, priority threat feeds, dedicated support, and SLA.',
    meshTier: 'enterprise',
    icon: 'corporate_fare',
    cta: 'Contact Sales',
    features: [
      'Everything in Connected',
      'Unlimited concurrent agents',
      'Priority threat intel feed',
      'Multi-gateway deployment',
      'Root + subsidiary licensing',
      'Custom policy enforcement',
      'Dedicated support engineer',
      '99.9% SLA',
    ],
  },
];

export default function PricingPage() {
  const [selectedTier, setSelectedTier] = useState<string | null>(null);

  return (
    <div className="p-10 font-body">
      <div className="text-center mb-12">
        <h1 className="text-4xl font-black font-headline text-white tracking-tight mb-4">
          Sovereign AI Security
        </h1>
        <p className="text-on-surface-muted max-w-2xl mx-auto text-lg">
          Self-hosted. Zero data egress. Post-quantum authenticated. 
          Choose the tier that fits your organisation.
        </p>
      </div>

      {/* Data Sovereignty Banner */}
      <div className="flex items-center justify-center gap-3 bg-green-500/5 border border-green-500/20 rounded-xl px-6 py-4 mb-10 max-w-3xl mx-auto">
        <span className="material-symbols-outlined text-green-400 text-2xl">lock</span>
        <div className="text-sm text-green-300/80 text-center">
          <strong>Every tier runs on YOUR infrastructure.</strong> We never see your data. 
          The gateway binary, your agents, your policies — all self-hosted. 
          All we receive is anonymous health telemetry.
        </div>
      </div>

      {/* Tier Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl mx-auto mb-16">
        {TIERS.map((tier) => (
          <div
            key={tier.name}
            className={`relative bg-surface/80 backdrop-blur-xl border rounded-2xl p-8 transition-all duration-300 hover:scale-[1.02] ${
              tier.highlight
                ? 'border-primary/50 shadow-[0_0_30px_rgba(255,159,74,0.15)]'
                : 'border-border hover:border-primary/30'
            }`}
          >
            {tier.highlight && (
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-4 py-1 bg-primary text-background text-xs font-bold font-headline rounded-full shadow-[0_0_15px_rgba(255,159,74,0.4)]">
                RECOMMENDED
              </div>
            )}

            <div className="flex items-center gap-3 mb-6">
              <div className={`w-12 h-12 rounded-xl flex items-center justify-center border ${
                tier.highlight 
                  ? 'bg-primary/20 border-primary/30' 
                  : 'bg-white/5 border-white/10'
              }`}>
                <span className={`material-symbols-outlined text-2xl ${tier.highlight ? 'text-primary' : 'text-on-surface-muted'}`}>
                  {tier.icon}
                </span>
              </div>
              <div>
                <h3 className="text-xl font-bold font-headline text-white">{tier.name}</h3>
                <div className="text-xs text-on-surface-muted font-technical uppercase tracking-widest">
                  mesh: {tier.meshTier}
                </div>
              </div>
            </div>

            <div className="mb-6">
              <span className="text-3xl font-black font-headline text-white">{tier.price}</span>
              <span className="text-on-surface-muted text-sm">{tier.period}</span>
            </div>

            <p className="text-sm text-on-surface-muted mb-6 leading-relaxed">{tier.description}</p>

            <ul className="space-y-3 mb-8">
              {tier.features.map((feature, i) => (
                <li key={i} className="flex items-start gap-2 text-sm">
                  <span className="material-symbols-outlined text-green-400 text-[16px] mt-0.5 flex-shrink-0">check_circle</span>
                  <span className="text-gray-300">{feature}</span>
                </li>
              ))}
            </ul>

            <button
              onClick={() => setSelectedTier(tier.meshTier)}
              className={`w-full py-3 px-6 rounded-xl font-bold font-headline transition-all flex items-center justify-center gap-2 ${
                tier.highlight
                  ? 'bg-primary hover:bg-primary-hover text-background shadow-[0_0_15px_rgba(255,159,74,0.3)]'
                  : 'bg-white/5 hover:bg-white/10 text-white border border-white/10 hover:border-primary/30'
              }`}
            >
              <span className="material-symbols-outlined text-[18px]">
                {tier.price === 'Custom' ? 'mail' : 'shopping_cart'}
              </span>
              {tier.cta}
            </button>
          </div>
        ))}
      </div>

      {/* How It Works */}
      <div className="max-w-4xl mx-auto">
        <h2 className="text-2xl font-black font-headline text-white text-center mb-8">How It Works</h2>
        <div className="grid grid-cols-4 gap-6">
          {[
            { step: '1', icon: 'shopping_cart', title: 'Purchase', desc: 'Select your tier and complete payment' },
            { step: '2', icon: 'download', title: 'Download', desc: 'Receive your PQC-signed .lic file and gateway binary' },
            { step: '3', icon: 'terminal', title: 'Deploy', desc: 'Run start_fleet.sh on your infrastructure' },
            { step: '4', icon: 'hub', title: 'Connect', desc: 'Join the mesh for collective threat intelligence' },
          ].map((item) => (
            <div key={item.step} className="text-center">
              <div className="w-12 h-12 bg-primary/10 border border-primary/20 rounded-xl flex items-center justify-center mx-auto mb-3">
                <span className="material-symbols-outlined text-primary">{item.icon}</span>
              </div>
              <div className="text-xs font-technical text-primary mb-1">STEP {item.step}</div>
              <div className="text-sm font-bold text-white font-headline mb-1">{item.title}</div>
              <div className="text-xs text-on-surface-muted">{item.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Purchase Modal Placeholder */}
      {selectedTier && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-surface border border-border rounded-2xl p-8 max-w-md w-full shadow-2xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold font-headline text-white">Request License</h3>
              <button onClick={() => setSelectedTier(null)} className="text-on-surface-muted hover:text-white transition-colors">
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>
            <div className="bg-primary/10 border border-primary/20 rounded-xl p-4 mb-4">
              <div className="text-sm font-bold text-primary font-headline uppercase">{selectedTier} Tier Selected</div>
              <div className="text-xs text-on-surface-muted mt-1">
                {selectedTier === 'enterprise'
                  ? 'Custom pricing — tailored to your organisation\'s scale and requirements.'
                  : `${TIERS.find(t => t.meshTier === selectedTier)?.price}/year — self-hosted on your infrastructure.`}
              </div>
            </div>
            <div className="space-y-3 mb-6">
              <p className="text-sm text-on-surface-muted leading-relaxed">
                Licenses are PQC-signed <code className="text-primary/80 text-xs">.lic</code> files bound to your organisation.
                Contact our sales team to receive your license and gateway binary.
              </p>
              <a
                href={`mailto:sales@affinityops.com?subject=Cicada License Request — ${selectedTier} Tier&body=Organisation:%0ATier: ${selectedTier}%0AEstimated Agent Count:%0A`}
                className="w-full bg-primary hover:bg-primary-hover text-background font-bold py-3 px-6 rounded-xl transition-colors font-headline flex items-center justify-center gap-2"
              >
                <span className="material-symbols-outlined text-[18px]">mail</span>
                Contact sales@affinityops.com
              </a>
            </div>
            <button
              onClick={() => setSelectedTier(null)}
              className="w-full bg-white/5 hover:bg-white/10 text-white border border-white/10 font-bold py-2.5 px-6 rounded-xl transition-colors font-headline text-sm"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
