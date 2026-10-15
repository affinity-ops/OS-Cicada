// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';
import React, { createContext, useContext, useState, useCallback } from 'react';

type ToastType = 'info' | 'error';
type ToastContextType = {
  showToast: (msg: string, type?: ToastType) => void;
};

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export const ToastProvider: React.FC<{children: React.ReactNode}> = ({children}) => {
  const [toast, setToast] = useState<{msg: string; type: ToastType} | null>(null);

  const showToast = useCallback((message: string, type: ToastType = 'info') => {
    setToast({ msg: message, type });
    setTimeout(() => setToast(null), 3000);
  }, []);

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      {toast && (
        <div className={`fixed bottom-10 right-10 z-[9999] px-4 py-3 rounded-xl shadow-lg flex items-center gap-3 border ${
          toast.type === 'error'
            ? 'bg-[#1a1a1a] border-red-500/30 shadow-red-500/10'
            : 'bg-[#1a1a1a] border-orange-500/20 shadow-[0_0_20px_rgba(255,159,74,0.15)]'
        }`}>
          <span className={`material-symbols-outlined text-sm ${toast.type === 'error' ? 'text-red-400' : 'text-primary'}`}>
            {toast.type === 'error' ? 'error' : 'notifications'}
          </span>
          <span className="text-xs font-technical text-neutral-200">{toast.msg}</span>
        </div>
      )}
    </ToastContext.Provider>
  );
};

export const useToast = () => {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
};
