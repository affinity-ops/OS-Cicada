// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState, useEffect } from 'react';
import QRCode from 'react-qr-code';
import { useRouter } from 'next/navigation';

export default function MasterAdminLogin() {
  const [qrData, setQrData] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [status, setStatus] = useState<'loading' | 'pending' | 'success' | 'expired'>('loading');
  const router = useRouter();

  useEffect(() => {
    // 1. Fetch Challenge
    const fetchChallenge = async () => {
      try {
        const res = await fetch('/api/auth/challenge', { method: 'POST' });
        const data = await res.json();
        if (data.session_id && data.challenge_id) {
          setSessionId(data.session_id);
          // Format for Sentinel app — the mobile device needs a routable host to POST the signed response.
          // In production, NEXT_PUBLIC_MASTER_HOST is set to the real domain.
          // In local dev, the QR already contains the browser's current host (which is the LAN IP
          // when accessed via start_fleet.sh).
          const host = process.env.NEXT_PUBLIC_MASTER_HOST
            || (typeof window !== 'undefined' ? window.location.host : 'localhost:3005');
          setQrData(`cicada://master-auth?session=${data.session_id}&challenge=${data.challenge_id}&host=${host}`);
          setStatus('pending');
        } else {
          setStatus('expired');
        }
      } catch (err) {
        console.error('Failed to get auth challenge', err);
        setStatus('expired');
      }
    };

    fetchChallenge();
  }, []);

  useEffect(() => {
    // 2. Poll Status if pending
    if (status !== 'pending' || !sessionId) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/auth/status?session_id=${sessionId}`);
        const data = await res.json();
        
        if (data.status === 'authenticated') {
          setStatus('success');
          clearInterval(interval);
          // Small delay for UX, then redirect
          setTimeout(() => {
            // Ideally set cookie here, or API has already set it
            // Assuming we just use the browser sessionStorage for this dev pass or relying on middleware
            // But since this is a demonstration of the flow, let's redirect to root
            document.cookie = `cicada_master_session=${sessionId}; path=/; max-age=86400; SameSite=Strict`;
            router.push('/');
          }, 1500);
        } else if (data.status === 'expired' || res.status === 404) {
          setStatus('expired');
          clearInterval(interval);
        }
      } catch (err) {
        console.error('Poll failed', err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [status, sessionId, router]);

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center font-body p-6 relative overflow-hidden">
      {/* Background glow */}
      <div className="fixed top-[-20%] right-[-10%] w-[800px] h-[800px] bg-primary/10 rounded-full blur-[150px] pointer-events-none" />
      <div className="fixed bottom-[-20%] left-[-10%] w-[600px] h-[600px] bg-primary/5 rounded-full blur-[150px] pointer-events-none" />

      <div className="z-10 bg-surface/80 backdrop-blur-xl border border-border p-10 rounded-3xl shadow-2xl max-w-md w-full text-center">
        <div className="flex justify-center mb-6">
          <div className="w-16 h-16 bg-gradient-to-br from-primary to-primary-dark rounded-2xl flex items-center justify-center shadow-[0_0_25px_rgba(255,159,74,0.3)]">
            <span className="material-symbols-outlined text-background text-3xl">admin_panel_settings</span>
          </div>
        </div>
        
        <h1 className="text-2xl font-black font-headline text-white tracking-tight uppercase mb-2">Vendor Login</h1>
        <p className="text-sm text-on-surface-muted mb-8 font-technical tracking-widest uppercase">
          Zero-Trust Out-Of-Band Auth
        </p>

        {status === 'loading' && (
          <div className="h-64 flex flex-col items-center justify-center">
            <span className="material-symbols-outlined animate-spin text-primary text-4xl mb-4">autorenew</span>
            <p className="text-on-surface-muted text-sm">Generating Cryptographic Challenge...</p>
          </div>
        )}

        {status === 'pending' && qrData && (
          <div className="flex flex-col items-center animate-fade-in">
            <div className="bg-white p-4 rounded-xl shadow-[0_0_20px_rgba(255,255,255,0.1)] mb-6">
              <QRCode value={qrData} size={200} level="H" />
            </div>
            <p className="text-on-surface text-sm mb-2 font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px] text-primary animate-pulse">qr_code_scanner</span>
              Scan with Sentinel App
            </p>
            <p className="text-on-surface-muted text-xs mb-4">Awaiting Ed25519 + ML-DSA-65 hybrid signature...</p>
            
            <div className="flex items-center gap-2 mb-6 px-3 py-1 bg-red-500/10 border border-red-500/20 rounded-full">
              <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></span>
              <span className="text-xs text-red-400 font-technical">Expires in 30s (Anti-Fixation)</span>
            </div>
            
            <a 
              href={`http://${typeof window !== 'undefined' ? window.location.hostname : '192.168.0.35'}:3004/sentinel-app-v1.apk`}
              className="text-primary hover:text-primary-dark hover:bg-primary/5 transition-colors border border-primary/20 rounded-lg px-4 py-2 text-xs font-bold flex items-center gap-2"
            >
              <span className="material-symbols-outlined text-[14px]">download</span>
              Download Sentinel APK
            </a>
          </div>
        )}

        {status === 'success' && (
          <div className="h-64 flex flex-col items-center justify-center animate-scale-in">
            <div className="w-20 h-20 bg-green-500/20 rounded-full flex items-center justify-center border border-green-500/50 mb-4 shadow-[0_0_30px_rgba(34,197,94,0.3)]">
              <span className="material-symbols-outlined text-green-400 text-4xl">verified_user</span>
            </div>
            <p className="text-white font-bold font-headline text-lg">Cryptographic Signature Verified</p>
            <p className="text-green-400 text-sm mt-1">Establishing secure session...</p>
          </div>
        )}

        {status === 'expired' && (
          <div className="h-64 flex flex-col items-center justify-center">
            <div className="w-16 h-16 bg-red-500/20 rounded-full flex items-center justify-center border border-red-500/50 mb-4">
              <span className="material-symbols-outlined text-red-400 text-3xl">timer_off</span>
            </div>
            <p className="text-white font-bold">Challenge Expired (30s limit)</p>
            <button 
              onClick={() => window.location.reload()}
              className="mt-4 bg-primary text-black font-bold px-4 py-2 rounded-xl text-sm"
            >
              Generate New Challenge
            </button>
          </div>
        )}
      </div>

      <div className="mt-8 text-xs text-on-surface-muted font-technical tracking-widest opacity-50 uppercase z-10 flex items-center gap-2">
        <span className="material-symbols-outlined text-[14px]">lock</span>
        PQC Hybrid Enforcement Active
      </div>
    </div>
  );
}
