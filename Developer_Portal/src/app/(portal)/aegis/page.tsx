// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import { useState, useEffect } from 'react';
import QRCode from 'react-qr-code';

function formatDistanceToNowNative(dateString: string) {
  const date = new Date(dateString);
  const now = new Date();
  const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (diffInSeconds < 60) return 'Just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} mins ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
  return `${Math.floor(diffInSeconds / 86400)} days ago`;
}

// The pairing challenge and device management endpoints live on the Sentry Gateway,
// not the Core API — the Gateway owns the mobile_pairing_challenges table.
const GATEWAY_API = process.env.NEXT_PUBLIC_GATEWAY_URL || 'http://localhost:8080';

export default function AegisPairingPage() {
  const [qrPayload, setQrPayload] = useState<string | null>(null);
  const [attestationEnforced, setAttestationEnforced] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [devices, setDevices] = useState<any[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<any>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  useEffect(() => {
    const fetchDevices = async () => {
      try {
        const token = localStorage.getItem('cicada_token');
        if (!token) return;
        const res = await fetch(`${GATEWAY_API}/v1/portal/devices`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json',
          },
        });
        if (res.ok) {
          const { data } = await res.json();
          setDevices(data.devices || []);
        }
      } catch (err) {
        console.error("Failed to fetch devices", err);
      }
    };

    fetchDevices();
    const intervalId = setInterval(fetchDevices, 30000);
    return () => clearInterval(intervalId);
  }, []);

  const handleRevoke = async (deviceId: string) => {
    if (!window.confirm('Revoke this device? It will no longer be able to sign HITL decisions.')) return;
    setRevokingId(deviceId);
    try {
      const token = localStorage.getItem('cicada_token');
      const res = await fetch(`${GATEWAY_API}/v1/portal/devices/${deviceId}/revoke`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
        },
      });
      if (res.ok) {
        setDevices(prev => prev.filter(d => d.id !== deviceId));
      } else {
        const body = await res.json().catch(() => ({}));
        alert(`Revoke failed: ${body.error || res.status}`);
      }
    } catch (err: any) {
      alert(`Revoke failed: ${err.message}`);
    } finally {
      setRevokingId(null);
    }
  };

  const generateChallenge = async () => {
    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem('cicada_token');
      if (!token) {
        throw new Error('Not authenticated — please log in');
      }
      const res = await fetch(`${GATEWAY_API}/v1/portal/pair/generate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      });

      if (res.status === 401) {
        throw new Error('Session expired — please log in again');
      }
      if (!res.ok) {
        throw new Error('Failed to generate pairing challenge');
      }

      const { data } = await res.json();
      // data.qr_payload = structured signed JSON: {"v":1,"tid":"...","n":"...","exp":...,"sig":"..."}
      // Rendered directly as QR — the device parses JSON and verifies the signature.
      setQrPayload(data.qr_payload);
      setAttestationEnforced(data.attestation_enforced);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Mobile Aegis Companion</h1>
        <p className="text-on-surface-muted mt-2">
          Pair your mobile device with the Cicada Platform to receive cryptographically secure, out-of-band alerts for Human-In-The-Loop (HITL) actions.
        </p>
      </div>

      <div className="bg-[#121212] border border-[rgba(255,159,74,0.20)] p-8 rounded-xl flex flex-col md:flex-row gap-8 items-start">
        <div className="flex-1 space-y-6">
          <div className="flex items-start gap-4">
            <div className="w-8 h-8 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold">1</div>
            <div>
              <h3 className="font-bold text-lg">Download the Aegis App</h3>
              <p className="text-sm text-on-surface-muted">Install the Cicada Aegis app on your iOS or Android device.</p>
              {/* APK download — served by the APK Server on port 3004
                   (NOT port 8081, which is the Vault service).
                   The filename must match the latest build in apk_server/.
                   Version must match pubspec.yaml version field. */}
              <a href={`http://${typeof window !== 'undefined' ? window.location.hostname : '192.168.0.35'}:3004/aegis-app-v5.apk`} className="text-primary hover:underline text-sm font-bold mt-2 inline-block">Download Android APK (v3.0.0 Release)</a>
            </div>
          </div>

          <div className="flex items-start gap-4">
            <div className="w-8 h-8 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold">2</div>
            <div>
              <h3 className="font-bold text-lg">Generate Pairing Code</h3>
              <p className="text-sm text-on-surface-muted">Generate a unique, single-use cryptographic token to bind your specific mobile device to this tenant.</p>
            </div>
          </div>

          <div className="flex items-start gap-4">
            <div className="w-8 h-8 rounded-full bg-primary/20 text-primary flex items-center justify-center font-bold">3</div>
            <div>
              <h3 className="font-bold text-lg">Scan QR Code</h3>
              <p className="text-sm text-on-surface-muted">Open the Aegis app and tap "Scan QR Code" to complete the hardware binding.</p>
            </div>
          </div>
        </div>

        <div className="w-full md:w-80 bg-[#0a0a0a] rounded-xl p-6 border border-white/5 flex flex-col items-center justify-center min-h-[320px] text-center">
          {qrPayload ? (
            <div className="space-y-4 flex flex-col items-center">
              <div className="bg-white p-4 rounded-xl">
                <QRCode value={qrPayload} size={200} />
              </div>
              <p className="text-xs text-on-surface-muted mt-4 font-technical">Challenge generated. Scan this code with your Aegis app within 5 minutes.</p>
              {attestationEnforced && (
                <p className="text-xs text-green-400 font-technical">✓ Device attestation enforced</p>
              )}
              {!attestationEnforced && (
                <p className="text-xs text-amber-400 font-technical">⚠ Attestation not enforced (dev mode)</p>
              )}
              <button 
                onClick={() => setQrPayload(null)}
                className="text-xs text-on-surface-muted hover:text-white underline"
              >
                Clear Challenge
              </button>
            </div>
          ) : (
            <div className="space-y-6">
              <span className="material-symbols-outlined text-6xl text-primary/40">qr_code_scanner</span>
              <div>
                <button
                  onClick={generateChallenge}
                  disabled={loading}
                  className="px-6 py-3 bg-primary text-black font-bold font-headline rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50"
                >
                  {loading ? 'Generating...' : 'Generate Pairing QR Code'}
                </button>
                {error && <p className="text-red-400 text-xs mt-3">{error}</p>}
              </div>
            </div>
          )}
        </div>
      </div>
      
      <div className="bg-primary/5 border border-primary/20 p-4 rounded-lg flex items-start gap-3">
        <span className="material-symbols-outlined text-primary mt-0.5">security</span>
        <p className="text-sm text-on-surface-muted">
          <strong className="text-white block">Zero-Trust Device Binding</strong>
          By scanning this QR code, your device will generate a private key inside its Secure Enclave. This key never leaves your device and will be used to cryptographically sign all future HITL decisions, establishing an immutable, non-repudiable audit trail.
        </p>
      </div>

      <div className="mt-12">
        <h2 className="text-2xl font-bold mb-4 font-headline tracking-tighter">Enrolled Aegis Devices</h2>
        <div className="bg-[#121212] border border-white/5 rounded-xl overflow-hidden">
          <table className="w-full text-left">
            <thead className="bg-[#1a1a1a] border-b border-white/5">
              <tr>
                <th className="px-6 py-4 text-xs font-bold text-on-surface-muted uppercase tracking-wider">Device</th>
                <th className="px-6 py-4 text-xs font-bold text-on-surface-muted uppercase tracking-wider">Platform</th>
                <th className="px-6 py-4 text-xs font-bold text-on-surface-muted uppercase tracking-wider">Security Posture</th>
                <th className="px-6 py-4 text-xs font-bold text-on-surface-muted uppercase tracking-wider">Paired At</th>
                <th className="px-6 py-4 text-xs font-bold text-on-surface-muted uppercase tracking-wider text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-sm">
              {devices.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-on-surface-muted">
                    No devices enrolled yet. Generate a QR code to bind your mobile device.
                  </td>
                </tr>
              ) : (
                devices.map((device: any) => {
                  const isActive = device.status === 'active';

                  return (
                    <tr key={device.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <span className="material-symbols-outlined text-on-surface-muted">
                            {device.platform === 'ios' ? 'phone_iphone' : 'smartphone'}
                          </span>
                          <div>
                            <p className="font-bold text-white">{device.model || 'Unknown Device'}</p>
                            <p className="text-xs text-on-surface-muted font-mono">
                              {device.device_id ? device.device_id.slice(0, 16) + '…' : '—'}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-on-surface-muted capitalize">
                        {device.platform === 'ios' ? 'iOS' : device.platform === 'android' ? 'Android' : device.platform || '—'}
                      </td>
                      <td className="px-6 py-4">
                        {isActive ? (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-green-500/10 text-green-400 text-xs font-bold border border-green-500/20">
                            <span className="w-1.5 h-1.5 rounded-full bg-green-400"></span>
                            Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/10 text-amber-400 text-xs font-bold border border-amber-500/20">
                            <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                            {device.status || 'Pending'}
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-on-surface-muted">
                        {device.paired_at ? formatDistanceToNowNative(device.paired_at) : 'Just now'}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <button
                          onClick={() => setSelectedDevice(device)}
                          className="text-primary hover:underline text-xs font-bold mr-4">
                          View Details
                        </button>
                        <button
                          onClick={() => handleRevoke(device.id)}
                          disabled={revokingId === device.id || !isActive}
                          className="text-red-400 hover:underline text-xs font-bold disabled:opacity-30">
                          {revokingId === device.id ? 'Revoking…' : 'Revoke'}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Device Details Modal */}
      {selectedDevice && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4">
          <div className="bg-[#121212] border border-white/10 rounded-xl p-8 max-w-2xl w-full max-h-[90vh] overflow-y-auto relative">
            <button 
              onClick={() => setSelectedDevice(null)}
              className="absolute top-4 right-4 text-white/50 hover:text-white"
            >
              <span className="material-symbols-outlined">close</span>
            </button>
            
            <h2 className="text-2xl font-bold mb-6 font-headline tracking-tighter text-primary">Device Telemetry Details</h2>
            
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-bold text-on-surface-muted uppercase tracking-wider mb-2 border-b border-white/10 pb-1">Device</h3>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div><span className="text-white/50">Model:</span> <span className="text-white">{selectedDevice.model || 'Unknown Device'}</span></div>
                  <div><span className="text-white/50">Platform:</span> <span className="text-white capitalize">{selectedDevice.platform || '—'}</span></div>
                  <div><span className="text-white/50">OS Version:</span> <span className="text-white">{selectedDevice.os_version || '—'}</span></div>
                  <div><span className="text-white/50">App Version:</span> <span className="text-white">{selectedDevice.app_version || '—'}</span></div>
                  <div><span className="text-white/50">Operator:</span> <span className="text-white">{selectedDevice.operator || '—'}</span></div>
                  <div><span className="text-white/50">Status:</span> <span className={selectedDevice.status === 'active' ? 'text-green-400' : 'text-amber-400'}>{selectedDevice.status || '—'}</span></div>
                  <div><span className="text-white/50">Biometric:</span> <span className={selectedDevice.biometric_enrolled ? 'text-green-400' : 'text-amber-400'}>{selectedDevice.biometric_enrolled ? 'Enrolled' : 'Not enrolled'}</span></div>
                  <div><span className="text-white/50">Secure Enclave:</span> <span className={selectedDevice.secure_enclave_available ? 'text-green-400' : 'text-amber-400'}>{selectedDevice.secure_enclave_available ? 'Available' : 'Unavailable'}</span></div>
                  <div><span className="text-white/50">Last Seen:</span> <span className="text-white">{selectedDevice.last_seen ? formatDistanceToNowNative(selectedDevice.last_seen) : 'Never'}</span></div>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-bold text-on-surface-muted uppercase tracking-wider mb-2 border-b border-white/10 pb-1">Pairing</h3>
                <div className="grid grid-cols-1 gap-4 text-sm">
                  <div><span className="text-white/50">Paired:</span> <span className="text-white">{selectedDevice.paired_at ? new Date(selectedDevice.paired_at).toLocaleString() : '—'}</span></div>
                  <div><span className="text-white/50">Created:</span> <span className="text-white">{selectedDevice.created_at ? new Date(selectedDevice.created_at).toLocaleString() : '—'}</span></div>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-bold text-on-surface-muted uppercase tracking-wider mb-2 border-b border-white/10 pb-1">Identity</h3>
                <div className="grid grid-cols-1 gap-4 text-sm break-all">
                  <div><span className="text-white/50">Device ID (Ed25519 Public Key):</span></div>
                  <div><span className="text-primary font-mono text-xs">{selectedDevice.device_id || '—'}</span></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
