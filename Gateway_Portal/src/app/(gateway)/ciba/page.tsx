// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useEffect, useState } from 'react';
import { useSession } from '../layout';

const CORE_API = process.env.NEXT_PUBLIC_CORE_API_URL || 'http://localhost:8000';
const GATEWAY_API = process.env.NEXT_PUBLIC_GATEWAY_URL || 'http://localhost:8080';
const DEVELOPER_PORTAL_URL = process.env.NEXT_PUBLIC_DEVELOPER_PORTAL_URL || 'http://localhost:3001';

interface CibaRequest {
  trace_id: string;
  agent_id: string;
  action_summary: string;
  target_url: string;
  payload_preview: string;
  risk_score: number;
  risk_reason: string;
  expires_at: string;
  created_at: string;
}

interface AegisDevice {
  id: string;
  device_id: string;
  model: string;
  platform: string;
  status: string;
  last_seen: string;
  paired_at: string;
  biometric_enrolled: boolean;
  secure_enclave_available: boolean;
}

function formatLastSeen(dateString: string) {
  if (!dateString) return 'Never';
  const date = new Date(dateString);
  const now = new Date();
  const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);
  if (diffInSeconds < 60) return 'Just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} mins ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
  return `${Math.floor(diffInSeconds / 86400)} days ago`;
}

export default function CibaApprovals() {
  const session = useSession();
  const [requests, setRequests] = useState<CibaRequest[]>([]);
  const [devices, setDevices] = useState<AegisDevice[]>([]);
  const [loading, setLoading] = useState(true);

  // Fetch enrolled Aegis devices from the Core API (shared by tenant_id)
  useEffect(() => {
    if (!session) return;
    const fetchDevices = async () => {
      try {
        const res = await fetch(`${GATEWAY_API}/v1/portal/devices`, {
          headers: {
            Authorization: `Bearer ${session.token}`,
            Accept: 'application/json',
          },
        });
        if (res.ok) {
          const body = await res.json();
          // Core API returns { data: { devices: [...] } }
          const list = body?.data?.devices;
          setDevices(Array.isArray(list) ? list : []);
        }
      } catch (err) {
        console.error('Failed to fetch Aegis devices', err);
      }
    };
    fetchDevices();
    const interval = setInterval(fetchDevices, 30000);
    return () => clearInterval(interval);
  }, [session]);

  // Fetch pending CIBA requests from the Core API
  const fetchPending = () => {
    if (!session) return;
    fetch(`${CORE_API}/api/v1/admin/ciba/pending`, {
      headers: { Authorization: `Bearer ${session.token}`, Accept: 'application/json' },
    })
      .then(r => r.json())
      .then(body => {
        // Core API returns { count, data: [...] } — data is the array directly
        const list = body?.data;
        setRequests(Array.isArray(list) ? list : []);
      })
      .catch(e => console.error("Failed to fetch pending CIBA requests", e))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchPending();
    const interval = setInterval(fetchPending, 5000);
    return () => clearInterval(interval);
  }, [session]);

  const respond = async (traceId: string, approved: boolean) => {
    if (!session) return;
    try {
      await fetch(`${CORE_API}/api/v1/admin/ciba/${traceId}/respond`, {
        method: 'POST',
        headers: { 
          Authorization: `Bearer ${session.token}`, 
          Accept: 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ approved })
      });
      // Optimistic UI update
      setRequests(prev => prev.filter(r => r.trace_id !== traceId));
    } catch (e) {
      console.error("Failed to respond to CIBA request", e);
    }
  };

  const activeDevices = devices.filter(d => d.status === 'active');

  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter flex items-center gap-3">
          <span className="material-symbols-outlined text-primary text-4xl">verified_user</span>
          CIBA Authorizations
        </h1>
        <p className="text-on-surface-muted text-sm mt-2 max-w-2xl">
          Client Initiated Backchannel Authentication (CIBA) allows you to authorize or deny high-risk agent operations and context shifts (Drift) in real-time.
        </p>

        {/* Aegis Device Status — paired via Developer Portal, shared by tenant_id */}
        {activeDevices.length > 0 ? (
          <div className="mt-6 bg-green-500/5 border border-green-500/20 rounded-xl p-4 flex items-start gap-4 max-w-3xl">
            <span className="material-symbols-outlined text-green-400 text-3xl">smartphone</span>
            <div className="flex-1">
              <h3 className="text-sm font-bold font-headline text-green-400">Aegis Mobile Companion — Active</h3>
              <div className="mt-2 space-y-1">
                {activeDevices.map(device => (
                  <div key={device.id} className="flex items-center justify-between text-xs">
                    <span className="text-white">
                      {device.model || 'Unknown Device'}
                      <span className="text-on-surface-muted ml-2 capitalize">{device.platform || ''}</span>
                    </span>
                    <span className="text-on-surface-muted">
                      {device.biometric_enrolled && <span className="text-green-400 mr-2">✓ Biometric</span>}
                      {device.secure_enclave_available && <span className="text-green-400 mr-2">✓ Enclave</span>}
                      Last seen: {formatLastSeen(device.last_seen)}
                    </span>
                  </div>
                ))}
              </div>
              <p className="text-xs text-on-surface-muted mt-2">
                CIBA push notifications will be delivered to {activeDevices.length === 1 ? 'this device' : 'these devices'} when high-risk agent actions require authorization.
                {' '}<a href={`${DEVELOPER_PORTAL_URL}/aegis`} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Manage devices →</a>
              </p>
            </div>
          </div>
        ) : (
          <div className="mt-6 bg-primary/10 border border-primary/20 rounded-xl p-4 flex items-start gap-4 max-w-3xl">
            <span className="material-symbols-outlined text-primary text-3xl">smartphone</span>
            <div>
              <h3 className="text-sm font-bold font-headline text-primary">Aegis Mobile Companion — Not Paired</h3>
              <p className="text-xs text-on-surface-muted mt-1 leading-relaxed">
                Pair your mobile device via the Developer Portal to receive instant push notifications for CIBA authorization requests. Once paired, your device will be able to review context shifts, inspect payload previews, and authorize transactions using biometric sign-off (FaceID/TouchID).
              </p>
              <a
                href={`${DEVELOPER_PORTAL_URL}/aegis`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 mt-3 px-4 py-2 bg-primary text-black text-xs font-bold font-headline rounded-lg hover:bg-primary/90 transition-colors"
              >
                <span className="material-symbols-outlined text-sm">qr_code_scanner</span>
                Pair Device via Developer Portal
              </a>
            </div>
          </div>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center p-12">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      ) : requests.length === 0 ? (
        <div className="bg-surface-raised border border-[rgba(255,159,74,0.08)] rounded-2xl p-12 text-center">
          <span className="material-symbols-outlined text-4xl text-on-surface-muted mb-4">task_alt</span>
          <h3 className="text-lg font-headline font-bold">No Pending Authorizations</h3>
          <p className="text-sm text-on-surface-muted mt-2">All high-risk agent actions have been resolved.</p>
        </div>
      ) : (
        <div className="grid gap-6">
          {requests.map(req => (
            <div key={req.trace_id} className="bg-surface-raised border border-red-500/20 rounded-2xl p-6 relative overflow-hidden">
              <div className="absolute top-0 left-0 w-1 h-full bg-red-500" />
              
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-3 mb-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-technical uppercase tracking-widest bg-red-500/10 text-red-400 border border-red-500/20">
                      High Risk Alert
                    </span>
                    <span className="text-xs font-technical text-on-surface-muted">
                      Trace: {req.trace_id}
                    </span>
                  </div>
                  
                  <h3 className="text-xl font-headline font-bold text-white mb-1">
                    Agent: <span className="text-primary">{req.agent_id}</span>
                  </h3>
                  <p className="text-sm text-on-surface-muted mb-4">{req.action_summary}</p>
                </div>
                
                <div className="text-right">
                  <div className="text-3xl font-black font-technical text-red-400">
                    {req.risk_score.toFixed(2)}
                  </div>
                  <div className="text-[10px] font-technical text-on-surface-muted uppercase tracking-widest mt-1">
                    Risk Score
                  </div>
                </div>
              </div>

              <div className="bg-black/30 rounded-xl p-4 mb-6 border border-white/5 space-y-3">
                <div>
                  <span className="text-[10px] font-technical text-primary uppercase tracking-widest block mb-1">Reason for Escalation</span>
                  <p className="text-sm text-white/90 font-medium">{req.risk_reason}</p>
                </div>
                {req.target_url && (
                  <div>
                    <span className="text-[10px] font-technical text-primary uppercase tracking-widest block mb-1">Target URL</span>
                    <p className="text-sm text-white/70 font-mono break-all">{req.target_url}</p>
                  </div>
                )}
                {req.payload_preview && (
                  <div>
                    <span className="text-[10px] font-technical text-primary uppercase tracking-widest block mb-1">Payload Preview</span>
                    <p className="text-xs text-white/70 font-mono bg-black/50 p-2 rounded border border-white/5 whitespace-pre-wrap">{req.payload_preview}</p>
                  </div>
                )}
              </div>

              <div className="flex items-center justify-end gap-3">
                <button
                  onClick={() => respond(req.trace_id, false)}
                  className="px-5 py-2 rounded-lg text-sm font-headline font-bold border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-colors"
                >
                  Deny Action
                </button>
                <button
                  onClick={() => respond(req.trace_id, true)}
                  className="px-5 py-2 rounded-lg text-sm font-headline font-bold bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20 transition-colors"
                >
                  Approve Action
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
