// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import Link from 'next/link';

const SECTIONS = [
  {
    id: 'overview',
    title: 'Overview',
    content: `The Cicada Developer Portal is where you register AI agents and receive their cryptographic identity token — the EVAR (Extended Verification & Authorisation Record).

Every EVAR is an Ed25519-signed JWT minted by the Cicada Sentry Gateway. It binds your agent's identity to your verified company account and cannot be forged.`,
  },
  {
    id: 'register',
    title: 'Registering an agent',
    content: `Sign in with GitHub or Google, then navigate to Agents → Register New Agent and follow the 5-step wizard:

1. **Name & description** — human-readable identity
2. **Agent type** — reactive, heartbeat, scheduled, or autonomous
3. **Scopes** — which actions the agent is permitted to perform
4. **Failure scope** — what happens if the agent cannot complete its task (critical for enterprise deployments)
5. **API credentials** — which LLM provider the agent uses`,
  },
  {
    id: 'evar',
    title: 'Using your EVAR token',
    content: `After registration, copy your EVAR from the agent registry. Include it in the \`X-Cicada-EVAR\` header on every outbound request your agent makes:

\`\`\`
X-Cicada-EVAR: eyJhbGciOiJFZERTQSJ9...
\`\`\`

Companies running Sentry Gateway will validate this header before admitting your agent to their systems. An invalid or missing EVAR will result in a 403 rejection.`,
  },
  {
    id: 'verify',
    title: 'Verifying an EVAR (for gateway operators)',
    content: `If you run a Sentry Gateway, it automatically validates all inbound EVARs. You can also query the verification endpoint directly:

\`\`\`bash
curl https://your-gateway:8080/v1/verify/agent/<evar_token>
\`\`\`

A verified response confirms the agent's identity, tenant, registered scopes, and certification date. A 401 response means the token is invalid, revoked, or expired.`,
  },
  {
    id: 'scopes',
    title: 'Scope reference',
    content: `| Scope | Permitted actions |
|---|---|
| \`proxy:read\` | Read data from target systems |
| \`proxy:chat\` | Send conversational messages |
| \`proxy:write\` | Create or update records |
| \`proxy:transact\` | Initiate financial or state-changing actions |
| \`proxy:notify\` | Send notifications (email, webhook) |
| \`proxy:search\` | Query and search external data sources |

Agents will be rejected by Sentry Gateway if they attempt actions outside their registered scopes.`,
  },
];

export default function Docs() {
  return (
    <div className="min-h-screen bg-background text-on-surface">
      <nav className="fixed top-0 inset-x-0 z-50 border-b border-white/5 bg-background/80 backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-primary/20 flex items-center justify-center">
              <span className="material-symbols-outlined text-primary text-base">bug_report</span>
            </div>
            <span className="font-headline font-black text-lg tracking-tight">Cicada</span>
          </Link>
          <div className="hidden md:flex items-center gap-8 text-sm text-on-surface-muted">
            <Link href="/pricing" className="hover:text-on-surface transition-colors">Pricing</Link>
            <Link href="/docs" className="text-on-surface transition-colors">Docs</Link>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/login" className="text-sm text-on-surface-muted hover:text-on-surface transition-colors">Sign in</Link>
            <Link href="/login" className="px-4 py-2 bg-primary text-black rounded-xl text-sm font-headline font-bold hover:brightness-110 transition-all">Get started</Link>
          </div>
        </div>
      </nav>

      <div className="pt-24 pb-20 px-6">
        <div className="max-w-5xl mx-auto flex gap-10">
          {/* Sidebar nav */}
          <aside className="hidden lg:block w-52 flex-shrink-0 pt-8">
            <p className="text-[10px] font-technical uppercase tracking-widest text-on-surface-muted mb-3">Documentation</p>
            <nav className="space-y-1">
              {SECTIONS.map(s => (
                <a key={s.id} href={`#${s.id}`}
                  className="block px-3 py-1.5 rounded-lg text-sm text-on-surface-muted hover:text-on-surface hover:bg-white/5 transition-colors"
                >
                  {s.title}
                </a>
              ))}
            </nav>
          </aside>

          {/* Content */}
          <main className="flex-1 pt-8 space-y-12 max-w-2xl">
            <div>
              <h1 className="text-4xl font-black font-headline tracking-tighter">Documentation</h1>
              <p className="text-on-surface-muted mt-2">Everything you need to register and deploy certified AI agents.</p>
            </div>

            {SECTIONS.map(s => (
              <section key={s.id} id={s.id} className="space-y-4">
                <h2 className="text-xl font-headline font-bold">{s.title}</h2>
                <div className="prose prose-invert prose-sm max-w-none text-on-surface-muted leading-relaxed whitespace-pre-line">
                  {s.content.split('\n').map((line, i) => {
                    if (line.startsWith('```')) return null;
                    if (line.startsWith('|')) {
                      return (
                        <p key={i} className="font-technical text-xs">{line}</p>
                      );
                    }
                    if (line.startsWith('`')) {
                      return (
                        <pre key={i} className="bg-black/40 border border-white/5 rounded-lg p-4 font-technical text-xs text-primary overflow-x-auto">
                          {line.replace(/`/g, '')}
                        </pre>
                      );
                    }
                    if (/^\d+\./.test(line)) {
                      return <p key={i} className="pl-4">{line}</p>;
                    }
                    return line.trim() ? <p key={i}>{line}</p> : null;
                  })}
                </div>
              </section>
            ))}

            <div className="p-6 bg-primary/5 border border-primary/20 rounded-2xl">
              <p className="font-headline font-bold mb-1">Need help?</p>
              <p className="text-sm text-on-surface-muted">
                Sign in to the Developer Portal and open a support ticket, or reach the team at{' '}
                <span className="text-primary">support@cicada.ai</span>.
              </p>
            </div>
          </main>
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
            <Link href="/"        className="hover:text-on-surface transition-colors">Home</Link>
            <Link href="/pricing" className="hover:text-on-surface transition-colors">Pricing</Link>
            <Link href="/login"   className="hover:text-on-surface transition-colors">Sign in</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
