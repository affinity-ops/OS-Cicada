// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import React from 'react';

export interface AgentCardProps {
  name: string;
  agentId: string;
  trustTier: 'unverified' | 'nominal' | 'elevated' | 'critical';
  trustScore: number;
  status: string;
  totalActions: number;
  blockedActions: number;
  declaredScopes: string[];
  lastSeen: string;
  onViewDetail?: () => void;
}

const TIER_THEME = {
  critical:   { border: 'hover:border-red-500/40',     iconBg: 'bg-red-500/10 border-red-500/20',     iconText: 'text-red-400',     badge: 'bg-red-500/10 border-red-500/30 text-red-400',     bar: 'bg-red-500'     },
  elevated:   { border: 'hover:border-orange-500/40',  iconBg: 'bg-orange-500/10 border-orange-500/20', iconText: 'text-orange-400', badge: 'bg-orange-500/10 border-orange-500/30 text-orange-400', bar: 'bg-orange-500' },
  nominal:    { border: 'hover:border-emerald-500/40', iconBg: 'bg-emerald-500/10 border-emerald-500/20', iconText: 'text-emerald-400', badge: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400', bar: 'bg-emerald-500' },
  unverified: { border: 'hover:border-neutral-500/40', iconBg: 'bg-neutral-500/10 border-neutral-500/20', iconText: 'text-neutral-400', badge: 'bg-neutral-800 border-neutral-600/30 text-neutral-400', bar: 'bg-neutral-500' },
} as const;

export const AgentCard: React.FC<AgentCardProps> = ({
  name, agentId, trustTier, trustScore, status,
  totalActions, blockedActions, declaredScopes,
  lastSeen, onViewDetail,
}) => {
  const theme = TIER_THEME[trustTier] ?? TIER_THEME.unverified;
  const blockRate = totalActions > 0 ? ((blockedActions / totalActions) * 100).toFixed(1) : '0.0';
  const isRevoked = status === 'Revoked';
  const lastSeenLabel = lastSeen ? new Date(lastSeen).toLocaleDateString() : 'Never';

  return (
    <div className={`group relative overflow-hidden rounded-2xl bg-[#131313] border border-white/5 transition-all duration-300 ${theme.border}`}>
      <div className="p-5 h-full flex flex-col gap-4">

        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center border flex-shrink-0 ${theme.iconBg}`}>
              <span className={`material-symbols-outlined text-[18px] ${theme.iconText}`}>smart_toy</span>
            </div>
            <div className="min-w-0">
              <h3 className="font-headline font-bold text-on-surface truncate">{name}</h3>
              <p className={`font-technical text-[10px] tracking-widest uppercase ${theme.iconText} opacity-70`}>{agentId.substring(0, 12).toUpperCase()}</p>
            </div>
          </div>
          <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
            <span className={`px-2 py-0.5 rounded border font-technical text-[10px] font-bold uppercase ${theme.badge}`}>
              {trustTier}
            </span>
            {isRevoked && (
              <span className="px-2 py-0.5 rounded border font-technical text-[10px] font-bold uppercase bg-red-500/10 border-red-500/30 text-red-400">
                Revoked
              </span>
            )}
          </div>
        </div>

        {/* Trust score bar */}
        <div>
          <div className="flex justify-between mb-1">
            <span className="font-technical text-[10px] text-neutral-500 uppercase tracking-wider">Trust Score</span>
            <span className={`font-technical text-xs font-bold ${theme.iconText}`}>{trustScore}%</span>
          </div>
          <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
            <div className={`h-full rounded-full ${theme.bar}`} style={{ width: `${trustScore}%` }}></div>
          </div>
        </div>

        {/* Call stats */}
        <div className="grid grid-cols-3 gap-2 py-3 border-y border-white/5">
          <div className="text-center">
            <p className="font-technical text-base font-bold text-on-surface">{totalActions.toLocaleString()}</p>
            <p className="font-technical text-[9px] text-neutral-500 uppercase tracking-wider mt-0.5">Total</p>
          </div>
          <div className="text-center">
            <p className="font-technical text-base font-bold text-emerald-400">{(totalActions - blockedActions).toLocaleString()}</p>
            <p className="font-technical text-[9px] text-neutral-500 uppercase tracking-wider mt-0.5">Allowed</p>
          </div>
          <div className="text-center">
            <p className={`font-technical text-base font-bold ${blockedActions > 0 ? 'text-red-400' : 'text-neutral-500'}`}>{blockedActions.toLocaleString()}</p>
            <p className="font-technical text-[9px] text-neutral-500 uppercase tracking-wider mt-0.5">{blockRate}% blocked</p>
          </div>
        </div>

        {/* Scopes */}
        {declaredScopes.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {declaredScopes.slice(0, 3).map(s => (
              <span key={s} className="px-1.5 py-0.5 bg-white/5 border border-white/10 rounded font-technical text-[9px] text-neutral-400">{s}</span>
            ))}
            {declaredScopes.length > 3 && (
              <span className="px-1.5 py-0.5 bg-white/5 border border-white/10 rounded font-technical text-[9px] text-neutral-500">+{declaredScopes.length - 3} more</span>
            )}
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center justify-between mt-auto pt-1">
          <p className="font-technical text-[10px] text-neutral-600">Last seen {lastSeenLabel}</p>
          <button
            onClick={onViewDetail}
            className="px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg font-headline font-bold text-[11px] uppercase tracking-wide text-neutral-400 hover:text-on-surface transition-colors"
          >
            View Detail
          </button>
        </div>
      </div>
    </div>
  );
};
