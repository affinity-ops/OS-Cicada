// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useState } from 'react';

/**
 * Universal Tooltip Wrapper matching the high-contrast Cicada structural aesthetics.
 * Helps reduce operator cognitive latency by injecting context aggressively.
 */
export const Tooltip: React.FC<{ children: React.ReactNode; content: string; warning?: boolean }> = ({ children, content, warning = false }) => {
  const [show, setShow] = useState(false);

  return (
    <div 
      className="relative flex items-center" 
      onMouseEnter={() => setShow(true)} 
      onMouseLeave={() => setShow(false)}
    >
      {children}
      {show && (
        <div className={`absolute bottom-full mb-2 left-1/2 -translate-x-1/2 w-64 p-3 text-xs font-technical tracking-wide rounded-lg border shadow-xl z-[999] pointer-events-none transition-all ${
            warning 
            ? 'bg-[#2a0800] border-error/50 text-error-container shadow-error/10' 
            : 'bg-[#1a1a1a] border-white/10 text-neutral-300 shadow-black/50'
        }`}>
          {content}
        </div>
      )}
    </div>
  );
};
