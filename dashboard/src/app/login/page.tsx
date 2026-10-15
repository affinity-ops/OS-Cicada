// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useState } from 'react';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

export default function LoginPage() {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';

  const handleLogin = async () => {
    try {
      setLoading(true);
      setError(null);
      const resp = await fetch('/api/webauthn/login/generate');
      if (resp.status === 404) {
          setError("No Operator Key. Must register a YubiKey or Passkey first.");
          setLoading(false);
          return;
      }
      
      const options = await resp.json();
      const asseResp = await startAuthentication(options);
      
      const verificationResp = await fetch('/api/webauthn/login/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(asseResp),
      });

      if (verificationResp.ok) {
        window.location.href = '/';
      } else {
        const { error } = await verificationResp.json();
        setError(error || 'Hardware Key Denied');
      }
    } catch (err: any) {
      setError(err.message || 'Cryptographic Assertion Failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
    try {
      setLoading(true);
      setError(null);
      const resp = await fetch('/api/webauthn/register/generate');
      const options = await resp.json();
      
      const attResp = await startRegistration(options);
      const verificationResp = await fetch('/api/webauthn/register/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(attResp),
      });

      if (verificationResp.ok) {
        window.location.href = '/';
      } else {
        const { error } = await verificationResp.json();
        setError(error || 'Hardware Registration Failed');
      }
    } catch (err: any) {
      setError(err.message || 'Cryptographic Attestation Failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#090909] flex items-center justify-center font-technical p-4">
      <div className="max-w-md w-full bg-[#111] p-8 rounded-2xl border border-white/10 shadow-2xl">
        <div className="text-center mb-10">
          <span className="material-symbols-outlined text-[48px] text-primary mb-4 drop-shadow-[0_0_10px_currentColor] animate-pulse">fingerprint</span>
          <h1 className="text-2xl font-black text-white tracking-widest uppercase">Operator Terminal</h1>
          <p className="text-neutral-500 text-xs mt-2 uppercase tracking-widest">Hardware Biometric Access Required</p>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/50 p-4 rounded-lg mb-6 text-red-500 text-xs text-center uppercase font-bold tracking-wider">
            {error}
          </div>
        )}

        <div className="flex flex-col gap-4">
          <button 
            onClick={handleLogin}
            disabled={loading}
            className="w-full bg-primary text-black font-black uppercase tracking-widest py-4 rounded-xl shadow-[0_0_15px_rgba(0,229,114,0.3)] hover:shadow-[0_0_25px_rgba(0,229,114,0.5)] transition-all flex items-center justify-center gap-2"
          >
            {loading ? 'Interfacing...' : 'Authenticate'}
            <span className="material-symbols-outlined text-[18px]">verified_user</span>
          </button>
          
          <button 
            onClick={handleRegister}
            disabled={loading}
            className="w-full bg-transparent border border-white/20 text-white font-bold uppercase tracking-widest py-3 rounded-xl hover:bg-white/5 transition-all text-sm mt-4"
          >
            Enroll Hardware Key
          </button>
        </div>

        {/* Dev-only bypass — only visible when API points to localhost */}
        {CORE_API.includes('localhost') && (
          <div className="mt-6 pt-6 border-t border-white/5">
            <a
              href={`${CORE_API}/auth/dev-login?portal=operator`}
              className="flex items-center justify-center gap-2 w-full py-3 bg-amber-500/10 border border-amber-500/20 hover:bg-amber-500/20 text-amber-400 rounded-xl font-technical text-sm transition-colors"
            >
              <span className="material-symbols-outlined text-base">developer_mode</span>
              Dev Login (bypass WebAuthn)
            </a>
            <p className="text-center text-[10px] text-neutral-600 font-technical mt-2">
              Local only — seeds dev@cicada.local operator session
            </p>
          </div>
        )}

        <div className="mt-8 text-center border-t border-white/5 pt-6">
          <p className="text-[10px] text-neutral-600 uppercase tracking-widest font-black flex items-center justify-center gap-1.5">
            <span className="material-symbols-outlined text-[12px]">security</span>
            Zero-Trust Aegis Node Boundaries
          </p>
        </div>
      </div>
    </div>
  );
}
