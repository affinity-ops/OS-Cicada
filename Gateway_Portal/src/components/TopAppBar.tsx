// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React from 'react';

export const TopAppBar: React.FC = () => {
  return (
    <header
      className="fixed top-0 right-0 z-40 flex items-center justify-between px-8 bg-[#000000]/80 backdrop-blur-md h-20 border-b border-white/5 transition-all duration-300"
      style={{ left: 'var(--sidebar-width, 18rem)' }}
    >
      <span className="text-xl font-bold text-neutral-100 font-headline tracking-tight">
        CICADA <span className="text-primary">DEV PORTAL</span>
      </span>

      <div className="flex items-center gap-2">
        <div className="flex items-center gap-2 font-mono text-[10px] text-neutral-400">
          <span className="text-orange-500">DEVELOPER</span>
          <span className="material-symbols-outlined text-[12px]">chevron_right</span>
          <span className="text-neutral-100 border-b border-orange-500">WORKSPACE</span>
        </div>
      </div>
    </header>
  );
};
