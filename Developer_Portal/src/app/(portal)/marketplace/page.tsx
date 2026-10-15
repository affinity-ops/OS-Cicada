// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useSession } from '../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

interface Template {
  id: string;
  name: string;
  description: string;
  authoring_tenant_id: string;
  is_verified: boolean;
  downloads: number;
  config: any;
}

export default function MarketplacePage() {
  const session = useSession();
  const router = useRouter();
  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading] = useState(true);
  const [importing, setImporting] = useState<string | null>(null);

  useEffect(() => {
    if (!session) return;
    fetch(`${CORE_API}/api/v1/portal/marketplace/templates`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    })
      .then(r => r.json())
      .then(({ data }) => {
        setTemplates(data.templates);
        setLoading(false);
      });
  }, [session]);

  const handleImport = async (templateId: string) => {
    if (!session) return;
    setImporting(templateId);
    try {
      const res = await fetch(`${CORE_API}/api/v1/portal/marketplace/templates/${templateId}/import`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
      });
      const data = await res.json();
      if (res.ok) {
        router.push(`/agents/${data.agent_id}`);
      } else {
        alert(`Import failed: ${data.error}`);
        setImporting(null);
      }
    } catch (e) {
      alert('Network error during import.');
      setImporting(null);
    }
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-black font-headline tracking-tighter">Agent Marketplace</h1>
          <p className="text-on-surface-muted text-sm mt-1">Discover, verify, and 1-click import pre-built agent blueprints.</p>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : templates.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl">
          <span className="material-symbols-outlined text-on-surface-muted text-5xl mb-3">storefront</span>
          <p className="text-on-surface-muted text-sm">No templates available yet.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {templates.map(template => (
            <div key={template.id} className="flex flex-col bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-xl p-5 hover:border-primary/30 transition-all">
              <div className="flex items-start justify-between mb-4">
                <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
                  <span className="material-symbols-outlined text-primary text-xl">extension</span>
                </div>
                {template.is_verified && (
                  <span className="flex items-center gap-1 text-[10px] uppercase tracking-wider font-bold text-green-400 bg-green-400/10 px-2 py-1 rounded-full">
                    <span className="material-symbols-outlined text-[14px]">verified</span>
                    Verified
                  </span>
                )}
              </div>
              
              <h3 className="text-lg font-headline font-bold text-on-surface mb-1">{template.name}</h3>
              <p className="text-xs text-on-surface-muted line-clamp-2 mb-4 flex-grow">{template.description}</p>
              
              <div className="flex items-center justify-between text-xs text-on-surface-muted font-technical border-t border-[rgba(255,159,74,0.10)] pt-4 mt-auto">
                <span className="flex items-center gap-1">
                  <span className="material-symbols-outlined text-[14px]">download</span>
                  {template.downloads} Imports
                </span>
                <button
                  onClick={() => handleImport(template.id)}
                  disabled={importing === template.id}
                  className="px-4 py-1.5 bg-primary/10 text-primary hover:bg-primary hover:text-black font-bold rounded flex items-center gap-2 transition-all disabled:opacity-50"
                >
                  {importing === template.id ? (
                    <div className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <span className="material-symbols-outlined text-[14px]">input</span>
                  )}
                  {importing === template.id ? 'Importing...' : '1-Click Import'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
