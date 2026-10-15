// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import React, { createContext, useContext, useState, useCallback } from 'react';

type ToastContextType = {
  showToast: (msg: string) => void;
};

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export const ToastProvider: React.FC<{children: React.ReactNode}> = ({children}) => {
  const [msg, setMsg] = useState<string | null>(null);
  
  const showToast = useCallback((message: string) => {
    setMsg(message);
    setTimeout(() => setMsg(null), 3000);
  }, []);

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      {msg && (
        <div className="fixed bottom-10 right-10 z-[9999] bg-[#1a1a1a] border border-orange-500/20 px-4 py-3 rounded-xl shadow-[0_0_20px_rgba(255,159,74,0.15)] flex items-center gap-3 animate-[fade-in_0.2s_ease-out]">
            <span className="material-symbols-outlined text-primary text-sm">notifications</span>
            <span className="text-xs font-technical text-neutral-200">{msg}</span>
        </div>
      )}
    </ToastContext.Provider>
  )
};

export const useToast = () => {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
};
