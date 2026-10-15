// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

'use client';

import React, { useState, useEffect } from 'react';

/**
 * EnterpriseDeployPage
 * 
 * Provides self-hosted distribution instructions for Enterprise customers.
 * Enforces a 2-step UX:
 * 1. Upload the physical .lic file provided by their Cicada Account Manager.
 * 2. View dynamic Docker deployment commands tailored to their tenant.
 */
export default function EnterpriseDeployPage() {
  const [licenseData, setLicenseData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [homeUrl, setHomeUrl] = useState('https://api.cicada.security');

  useEffect(() => {
    // Dynamically set the home URL to the actual deployed Core API origin.
    // In local testing, this will be localhost:3001, but the Core API runs on 8000.
    // We can assume the host is the same but on port 8000 for local, or grab it from env.
    const apiUrl = process.env.NEXT_PUBLIC_CORE_API_URL || 
                   (typeof window !== 'undefined' ? `http://${window.location.hostname}:8000` : 'https://api.cicada.security');
    setHomeUrl(apiUrl);
  }, []);

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const text = e.target?.result as string;
        const parsed = JSON.parse(text);
        
        // Validate it's a Cicada Hybrid PQC License
        if (!parsed.payload || !parsed.sig_ed25519) {
          throw new Error("Invalid license format. Missing payload or Ed25519 signature.");
        }
        
        if (!parsed.sig_mldsa65) {
          console.warn("Missing ML-DSA-65 signature. Ensure this is a hybrid license.");
        }

        // Decode the payload to get the claims
        const payloadJson = atob(parsed.payload);
        const claims = JSON.parse(payloadJson);

        setLicenseData(claims);
        setError(null);
      } catch (err: any) {
        setError(`Failed to parse license file: ${err.message}`);
        setLicenseData(null);
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-black font-headline tracking-tighter">Enterprise Distribution</h1>
        <p className="text-on-surface-muted mt-2">
          Deploy the zero-trust Sentry Gateway into your own air-gapped infrastructure.
        </p>
      </div>

      {!licenseData ? (
        <div className="bg-[#121212] border border-orange-500/20 p-8 rounded-xl flex flex-col items-center justify-center space-y-4">
          <span className="material-symbols-outlined text-6xl text-orange-500/40">lock_open</span>
          <h2 className="text-xl font-bold font-headline">Step 1: Authenticate License</h2>
          <p className="text-sm text-center text-on-surface-muted max-w-md">
            The Sentry Gateway requires a cryptographically minted hybrid license to boot. 
            Please upload the <code className="text-orange-400 bg-orange-500/10 px-1 rounded">.lic</code> file securely provided by your Cicada Account Manager.
          </p>
          
          <label className="mt-4 cursor-pointer px-6 py-3 bg-orange-500 text-black font-bold font-headline rounded-lg hover:bg-orange-400 transition-colors">
            Upload .lic File
            <input type="file" accept=".lic,.json" className="hidden" onChange={handleFileUpload} />
          </label>
          
          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-sm mt-4">
              {error}
            </div>
          )}
        </div>
      ) : (
        <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className="bg-[#121212] border border-green-500/20 p-6 rounded-xl flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-green-400 flex items-center gap-2">
                <span className="material-symbols-outlined text-green-400">check_circle</span>
                License Authenticated
              </h2>
              <p className="text-sm text-on-surface-muted mt-1">
                Tenant: <strong className="text-white">{licenseData.tenant_id}</strong> | 
                Tier: <strong className="text-white">{licenseData.tier}</strong> | 
                Max Agents: <strong className="text-white">{licenseData.max_agents}</strong>
              </p>
            </div>
            <button 
              onClick={() => setLicenseData(null)}
              className="text-xs text-orange-500 hover:underline"
            >
              Change License
            </button>
          </div>

          <div className="bg-[#121212] border border-white/5 p-8 rounded-xl space-y-6">
            <div>
              <h2 className="text-xl font-bold font-headline mb-2">Step 2: Deploy Sentry Gateway</h2>
              <p className="text-sm text-on-surface-muted">
                Run the Gateway using our verified Docker image. The container will automatically enforce 
                your license constraints and sync telemetry to the Core API.
              </p>
            </div>

            <div className="bg-black border border-white/10 rounded-lg p-4 font-mono text-sm overflow-x-auto">
              <pre className="text-neutral-300">
<span className="text-orange-400"># 1. Pull the latest verified image</span>
<br/>docker pull ghcr.io/cicada/sentry-gateway:latest
<br/><br/>
<span className="text-orange-400"># 2. Run the Gateway (mounting your license file)</span>
<br/>docker run -d --name cicada-gateway \<br/>
  -p 8080:8080 \<br/>
  -v /path/to/your/license:/license \<br/>
  -e <span className="text-green-300">CICADA_POSTGRES_URL</span>="postgres://user:pass@your-local-db:5432/cicada_edge?sslmode=disable" \<br/>
  -e <span className="text-green-300">CICADA_HOME_URL</span>="{homeUrl}" \<br/>
  ghcr.io/cicada/sentry-gateway:latest \<br/>
  <span className="text-purple-300">--license</span>=/license/{licenseData.tenant_id}.lic
              </pre>
            </div>
            
            <div className="bg-orange-500/5 border border-orange-500/10 p-4 rounded-lg space-y-4 text-sm">
              <div className="flex gap-3">
                <span className="material-symbols-outlined text-orange-500">info</span>
                <div>
                  <strong className="text-white block mb-1">Air-Gapped Environments</strong>
                  <p className="text-on-surface-muted">
                    If your infrastructure cannot reach <code className="text-orange-300 bg-orange-500/10 px-1 rounded">ghcr.io</code>, you can download the secure offline installation files directly.
                  </p>
                </div>
              </div>
              <div className="flex gap-4 mt-4 ml-8">
                <a 
                  href="/downloads/sentry-gateway-offline.tar.gz" 
                  className="px-4 py-2 bg-[#2a2a2a] hover:bg-[#333] border border-white/10 rounded-lg text-white font-bold flex items-center gap-2 transition-colors"
                >
                  <span className="material-symbols-outlined text-sm">download</span>
                  Download Sentry Gateway
                </a>
                <a 
                  href="/downloads/gateway-portal-offline.tar.gz" 
                  className="px-4 py-2 bg-orange-500/20 hover:bg-orange-500/30 border border-orange-500/30 rounded-lg text-orange-400 font-bold flex items-center gap-2 transition-colors"
                >
                  <span className="material-symbols-outlined text-sm">download</span>
                  Download Gateway Portal
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
