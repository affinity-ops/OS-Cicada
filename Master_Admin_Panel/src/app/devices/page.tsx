// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState, useEffect } from 'react';

interface DeviceInfo {
  id: string;
  name: string;
  type: string;
  status: string;
  paired_at: string;
  last_used: string;
  keys: {
    ed25519: string;
    mldsa: string;
  };
}

export default function PairedDevicesPage() {
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [showPairModal, setShowPairModal] = useState(false);

  useEffect(() => {
    const fetchDevices = async () => {
      try {
        const response = await fetch('/api/auth/devices');
        const data = await response.json();
        setDevices(data.devices || []);
      } catch (error) {
        console.error('Failed to fetch paired devices:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchDevices();
  }, []);

  return (
    <div className="p-10 font-body relative">
      {/* Pair New Device Modal Overlay */}
      {showPairModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-2xl p-8 max-w-2xl w-full shadow-2xl relative">
            <button 
              onClick={() => setShowPairModal(false)}
              className="absolute top-4 right-4 text-on-surface-muted hover:text-white transition-colors"
            >
              <span className="material-symbols-outlined">close</span>
            </button>
            <h2 className="text-2xl font-bold font-headline text-white mb-2 flex items-center gap-2">
              <span className="material-symbols-outlined text-primary">add_link</span>
              Pair New Sentinel Device
            </h2>
            <p className="text-on-surface-muted mb-6">
              The Master Admin Panel operates on a strict Zero-Trust architecture. Devices cannot be paired dynamically via an API. They must be hardcoded into the platform&apos;s secure environment.
            </p>
            <div className="space-y-4">
              <div className="bg-black/50 border border-white/5 p-4 rounded-xl">
                <div className="flex items-center gap-3 mb-2">
                  <span className="w-6 h-6 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold text-sm">1</span>
                  <span className="text-white font-bold">Reveal Device Identity</span>
                </div>
                <p className="text-sm text-on-surface-muted ml-9">
                  Open the Sentinel app on your new device and tap the <strong className="text-primary">&ldquo;Reveal Device Identity&rdquo;</strong> button to unlock your hardware-bound cryptographic public keys.
                </p>
              </div>
              <div className="bg-black/50 border border-white/5 p-4 rounded-xl">
                <div className="flex items-center gap-3 mb-2">
                  <span className="w-6 h-6 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold text-sm">2</span>
                  <span className="text-white font-bold">Inject Keys into Master Admin Environment</span>
                </div>
                <p className="text-sm text-on-surface-muted ml-9 mb-3">
                  Open the <code className="text-primary bg-primary/10 px-1 py-0.5 rounded">.env</code> file in the <code>Master_Admin_Panel</code> repository and paste the keys into these exact variables:
                </p>
                <div className="ml-9 bg-black p-3 rounded-lg border border-white/10 overflow-x-auto">
                  <code className="text-xs text-green-400 font-technical whitespace-pre">
                    VENDOR_ADMIN_PUBKEY_ED25519=&quot;your_ed25519_key_here&quot;<br/>
                    VENDOR_ADMIN_PUBKEY_MLDSA=&quot;your_mldsa_key_here&quot;
                  </code>
                </div>
              </div>
              <div className="bg-black/50 border border-white/5 p-4 rounded-xl">
                <div className="flex items-center gap-3 mb-2">
                  <span className="w-6 h-6 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold text-sm">3</span>
                  <span className="text-white font-bold">Restart the Server</span>
                </div>
                <p className="text-sm text-on-surface-muted ml-9">
                  Restart the Node.js server so it securely loads the new keys into memory. The next time that specific phone scans a QR code, it will be recognized and granted access.
                </p>
              </div>
            </div>
            <div className="mt-8 flex justify-end">
              <button 
                onClick={() => setShowPairModal(false)}
                className="bg-primary text-black font-bold px-6 py-2 rounded-xl"
              >
                Understood
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="flex justify-between items-end mb-10">
        <div>
          <h1 className="text-3xl font-black font-headline text-white tracking-tight mb-2">Paired Sentinel Devices</h1>
          <p className="text-on-surface-muted max-w-2xl">
            Manage your Zero-Trust out-of-band authenticators. These hardware-bound devices hold the private cryptographic keys required to authorize Master Admin actions.
          </p>
        </div>
        <button 
          onClick={() => setShowPairModal(true)}
          className="flex items-center gap-2 bg-primary text-black font-bold px-4 py-2 rounded-xl text-sm font-headline hover:bg-primary-dark transition-colors shadow-[0_0_15px_rgba(255,159,74,0.3)]"
        >
          <span className="material-symbols-outlined text-[18px]">add_link</span>
          Pair New Device
        </button>
      </div>

      <div className="bg-surface/80 backdrop-blur-xl border border-border rounded-2xl overflow-hidden shadow-2xl">
        <div className="p-6 border-b border-border bg-surface-raised/50">
          <h2 className="text-lg font-bold font-headline text-white flex items-center gap-2">
            <span className="material-symbols-outlined text-primary drop-shadow-[0_0_8px_rgba(255,159,74,0.5)]">devices</span>
            Hardware Identity Keys
          </h2>
        </div>
        
        {loading ? (
          <div className="p-20 flex flex-col items-center justify-center text-on-surface-muted">
            <span className="material-symbols-outlined animate-spin text-4xl mb-4 text-primary">autorenew</span>
            <p className="font-body">Querying hardware keystore...</p>
          </div>
        ) : devices.length === 0 ? (
          <div className="p-20 text-center text-on-surface-muted">
            <span className="material-symbols-outlined text-5xl mb-4 text-primary opacity-30 drop-shadow-[0_0_8px_rgba(255,159,74,0.3)]">phonelink_erase</span>
            <p className="font-body text-lg">No Sentinel devices are currently paired.</p>
            <p className="font-technical text-xs mt-2 opacity-50">You must configure VENDOR_ADMIN_PUBKEY_ED25519 and VENDOR_ADMIN_PUBKEY_MLDSA.</p>
          </div>
        ) : (
          <div className="p-6 space-y-6">
            {devices.map((device) => (
              <div key={device.id} className="border border-border bg-black/40 rounded-xl p-6 shadow-inner relative overflow-hidden group">
                <div className="absolute top-0 left-0 w-1 h-full bg-primary shadow-[0_0_10px_rgba(255,159,74,1)]"></div>
                
                <div className="flex justify-between items-start mb-6">
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 bg-primary/10 rounded-xl border border-primary/20 flex items-center justify-center">
                      <span className="material-symbols-outlined text-primary text-2xl drop-shadow-[0_0_5px_rgba(255,159,74,0.5)]">smartphone</span>
                    </div>
                    <div>
                      <h3 className="text-xl font-bold text-white font-headline">{device.name}</h3>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-xs font-technical text-on-surface-muted uppercase">{device.type}</span>
                        <span className="w-1 h-1 bg-white/20 rounded-full"></span>
                        <span className="text-xs font-technical text-on-surface-muted">ID: {device.id}</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2 px-3 py-1 bg-green-500/10 border border-green-500/30 rounded-full">
                    <span className="w-2 h-2 bg-green-400 rounded-full shadow-[0_0_5px_rgba(74,222,128,1)]"></span>
                    <span className="text-xs font-bold text-green-400 uppercase tracking-wider">{device.status}</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="bg-surface/50 p-4 rounded-lg border border-white/5">
                    <div className="text-xs text-on-surface-muted uppercase tracking-widest font-technical mb-1">Paired Date</div>
                    <div className="text-sm text-white">{new Date(device.paired_at).toLocaleString()}</div>
                  </div>
                  <div className="bg-surface/50 p-4 rounded-lg border border-white/5">
                    <div className="text-xs text-on-surface-muted uppercase tracking-widest font-technical mb-1">Last Used</div>
                    <div className="text-sm text-white">{new Date(device.last_used).toLocaleString()}</div>
                  </div>
                </div>

                <div className="space-y-4 border-t border-white/5 pt-6">
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="material-symbols-outlined text-primary text-sm">key</span>
                      <span className="text-xs font-bold text-white uppercase tracking-wider font-technical">Ed25519 Public Identity</span>
                    </div>
                    <div className="bg-black/60 p-3 rounded-lg border border-white/10 overflow-x-auto">
                      <code className="text-xs font-technical text-primary/80 whitespace-nowrap">{device.keys.ed25519}</code>
                    </div>
                  </div>
                  
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="material-symbols-outlined text-primary text-sm">enhanced_encryption</span>
                      <span className="text-xs font-bold text-white uppercase tracking-wider font-technical">ML-DSA-65 Hybrid Post-Quantum Key</span>
                    </div>
                    <div className="bg-black/60 p-3 rounded-lg border border-white/10 overflow-x-auto">
                      <code className="text-xs font-technical text-primary/80 whitespace-nowrap">{device.keys.mldsa}</code>
                    </div>
                  </div>
                </div>

                <div className="mt-6 flex justify-end gap-3">
                  <button className="px-4 py-2 border border-white/10 text-white rounded-lg text-sm font-bold hover:bg-white/5 transition-colors">
                    Suspend Device
                  </button>
                  <button className="px-4 py-2 border border-red-500/30 text-red-400 rounded-lg text-sm font-bold hover:bg-red-500/10 hover:border-red-500/50 transition-colors flex items-center gap-2">
                    <span className="material-symbols-outlined text-[16px]">delete_forever</span>
                    Revoke Key
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
