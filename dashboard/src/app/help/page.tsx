// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import fs from 'fs';
import path from 'path';
import { Sidebar } from '../../components/Sidebar';
import { TopAppBar } from '../../components/TopAppBar';
import { HelpViewer } from '../../components/HelpViewer';

// Structured registry focusing on operational support and client assistance
const DOCUMENTATION_REGISTRY = [
  {
    category: "Platform Overviews",
    docs: [
      { id: "what-is-cicada", title: "What Cicada Actually Is", file: "manuals/platform_overview.md" },
      { id: "operator-manual", title: "Operator Dashboard Guide", file: "manuals/Operator_Dashboard_User_Manual.md" },
      { id: "developer-manual", title: "Developer Portal Guide", file: "manuals/Developer_Portal_User_Manual.md" },
      { id: "gateway-manual", title: "Gateway Portal Guide", file: "manuals/Gateway_Portal_User_Manual.md" }
    ]
  },
  {
    category: "Architecture & Spec",
    docs: [
      { id: "mef", title: "Matthews Enforcement Framework", file: "MATTHEWS_ENFORCEMENT_FRAMEWORK.md" },
      { id: "swarm", title: "Swarm Verification Architecture", file: "cicada_swarm_architecture_spec.md" },
      { id: "gateway", title: "Architecture Deep Dive", file: "ARCHITECTURE_DEEP_DIVE.md" },
      { id: "registry", title: "Verified Agent Registry Spec", file: "verified_agent_registry_spec.md" },
      { id: "boilerplate", title: "Boilerplate Scaffolding Architecture", file: "architecture/Boilerplate_Scaffolding_Architecture.md" }
    ]
  },
  {
    category: "Dashboard Interfaces",
    docs: [
      { id: "ui-home", title: "Global Overview", file: "interfaces/global_overview_ui_guide.md" },
      { id: "ui-nodes", title: "Agent Registry UI", file: "interfaces/agent_registry_ui_guide.md" },
      { id: "ui-pipeline", title: "Execution Pipeline", file: "interfaces/execution_pipeline_ui_guide.md" },
      { id: "ui-pipeline-map", title: "Pipeline Execution Map", file: "interfaces/pipeline_ui_guide.md" },
      { id: "ui-sentry", title: "Sentry Policy Engine", file: "interfaces/security_ui_guide.md" },
      { id: "ui-aegis", title: "Aegis AI Assistant", file: "interfaces/aegis_command_center_guide.md" },
      { id: "ui-vault", title: "Credential Vault", file: "interfaces/credential_vault_guide.md" }
    ]
  },
  {
    category: "Enterprise Features",
    docs: [
      { id: "ui-ghost", title: "Understanding Ghost Mode", file: "interfaces/ghost_mode_ui_guide.md" },
      { id: "ui-kms", title: "Zero-Liability KMS Integration", file: "interfaces/key_provisioning_guide.md" },
      { id: "ui-billing", title: "Metered Billing Guardrails", file: "interfaces/billing_guardrails_guide.md" }
    ]
  }
];

// Quick reference solutions for operators assisting clients
const QUICK_SOLUTIONS = [
  {
    title: "Client agents are all failing with 401 Unauthorized",
    cause: "The client's Ed25519 identity key may have been lost during a redeployment, causing all their EVARs to be rejected.",
    solution: "Instruct the client to restore `sentry_ed25519.key` from backup, or set `ALLOW_KEY_REGEN=true` to force a new key (they will need to re-provision all agents)."
  },
  {
    title: "Agent stuck in 'Shadow Sandbox' loop",
    cause: "The agent is uncertified or violating scope, and Ghost Mode is active but misconfigured upstream.",
    solution: "View the agent in the Rogue Registry. Check if it's hitting undeclared endpoints. You can allow-list the URLs in their biography panel."
  },
  {
    title: "Developer Portal stuck on Loading state",
    cause: "OAuth mismatch or Stripe webhook desync.",
    solution: "Verify their tenant ID in the CRM panel. Ensure their Stripe subscription status is 'active'."
  },
  {
    title: "Gateway Portal showing 'No telemetry received'",
    cause: "The Sentry Gateway cannot connect to their Redis instance, or network routing is blocking WebSocket traffic.",
    solution: "Check the Nodes view to see if the heartbeat is arriving. If heartbeats arrive but telemetry doesn't, it's a Redis routing issue on their end."
  }
];

export default function HelpPage() {
  
  // Read Markdown Files Server-Side
  const docsData = DOCUMENTATION_REGISTRY.map(category => {
    return {
      category: category.category,
      docs: category.docs.map(doc => {
        const rootPath = path.join(process.cwd(), 'public', 'docs');
        const exactFilePath = path.join(rootPath, doc.file);
        
        let markdownContent = "Documentation file not found. Ensure it exists in the `/public/docs/` directory.";
        try {
           if (fs.existsSync(exactFilePath)) {
              markdownContent = fs.readFileSync(exactFilePath, 'utf8');
           }
        } catch (error) {
          console.error(`Failed to read markdown file: ${exactFilePath}`, error);
        }

        return {
          id: doc.id,
          title: doc.title,
          content: markdownContent
        };
      })
    };
  });

  return (
    <>
      <Sidebar />
      <TopAppBar />

      <main className="pt-24 pb-12 px-10 min-h-screen transition-all duration-300" style={{ marginLeft: 'var(--sidebar-width, 18rem)' }}>
        
        {/* Helper Header & Quick Reference */}
        <section className="mb-10">
          <div className="flex items-center gap-4 mb-3">
             <span className="material-symbols-outlined text-4xl text-orange-400 p-3 bg-orange-500/10 rounded-2xl border border-orange-500/20">support_agent</span>
             <div>
                <h1 className="text-4xl font-black font-headline tracking-tighter text-on-surface mb-1">Operator Support Center</h1>
                <p className="text-on-surface-variant font-body w-full max-w-2xl text-sm leading-relaxed">
                  Reference documentation, architecture specs, and troubleshooting guides to assist enterprise clients and platform developers.
                </p>
             </div>
          </div>
          
          <div className="mt-8">
             <h2 className="text-sm font-bold font-headline text-neutral-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                 <span className="material-symbols-outlined text-lg">medical_information</span> Quick Troubleshooting
             </h2>
             <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
               {QUICK_SOLUTIONS.map((solution, idx) => (
                 <div key={idx} className="bg-surface-container-low rounded-xl p-5 border border-white/5 hover:border-orange-500/30 transition-colors shadow-lg group">
                    <h3 className="text-on-surface font-bold text-sm mb-2 group-hover:text-orange-400 transition-colors">{solution.title}</h3>
                    <div className="text-xs text-neutral-400 mb-2 font-body"><strong className="text-neutral-300">Cause:</strong> {solution.cause}</div>
                    <div className="text-xs text-orange-200/70 font-body"><strong className="text-orange-400 font-bold">Fix:</strong> {solution.solution}</div>
                 </div>
               ))}
             </div>
          </div>
        </section>

        {/* Dynamic Help Viewer */}
        <HelpViewer data={docsData} />
      </main>
    </>
  );
}
