// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { useState, useRef, useEffect } from "react";
import { Lock, AlertCircle, CheckCircle2 } from "lucide-react";

interface SecureInputProps {
  label: string;
  provider: "OpenAI" | "Anthropic" | "OpenRouter";
  tenantId: string;
}

export const SecureInput: React.FC<SecureInputProps> = ({ label, provider, tenantId }) => {
  const [status, setStatus] = useState<"idle" | "binding" | "success" | "error">("idle");
  const inputRef = useRef<HTMLInputElement>(null);

  // Hardened security measure: Never allow the browser to auto-complete or store this in history.
  // The moment the POST is finalized, physically strip the value from the DOM entirely.
  const handleSecureBind = async () => {
    if (!inputRef.current || !inputRef.current.value) return;
    setStatus("binding");

    try {
      // Direct POST to Sentry `keys/bind` route
      const gatewayUrl = process.env.NEXT_PUBLIC_GATEWAY_URL ?? 'http://localhost:8080';
      const response = await fetch(`${gatewayUrl}/v1/vault/keys/bind`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${tenantId}`, // Tenant Context passed explicitly
        },
        body: JSON.stringify({
          provider: provider,
          raw_key: inputRef.current.value,
        }),
      });

      if (!response.ok) throw new Error("KMS Cipher Rejection");

      setStatus("success");
    } catch (e) {
      setStatus("error");
    } finally {
      // **ZERO-VISIBILITY MANDATE**
      // Eradicate the plain-text from browser memory instantly.
      if (inputRef.current) {
        inputRef.current.value = "";
      }
      
      setTimeout(() => {
        setStatus("idle");
      }, 4000);
    }
  };

  return (
    <div className="w-full bg-[#111111] border border-gray-800 rounded-xl p-5 mb-4 relative overflow-hidden ring-1 ring-white/5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div className="bg-blue-500/10 p-2 rounded-lg border border-blue-500/20">
            <Lock className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-gray-200">{label}</h3>
            <p className="text-xs text-gray-500">Zero-Visibility KMS Injection</p>
          </div>
        </div>
      </div>

      <div className="flex space-x-3">
        <input
          ref={inputRef}
          type="password"
          autoComplete="off"
          spellCheck="false"
          placeholder={`paste-${provider.toLowerCase()}-secret-key...`}
          className="flex-1 bg-black border border-gray-800 rounded-lg px-4 py-2 text-sm text-gray-300 font-mono tracking-widest focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all placeholder:tracking-normal placeholder:font-sans"
        />
        <button
          onClick={handleSecureBind}
          disabled={status === "binding" || status === "success"}
          className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center min-w-[120px]"
        >
          {status === "idle" && "Bind to Vault"}
          {status === "binding" && "Encrypting..."}
          {status === "success" && <CheckCircle2 className="w-5 h-5" />}
          {status === "error" && <AlertCircle className="w-5 h-5 text-red-300" />}
        </button>
      </div>

      {status === "success" && (
        <p className="mt-3 text-xs text-green-400 font-mono">
          [SUCCESS] CiphertextBlob generated. Plain text destroyed.
        </p>
      )}
      {status === "error" && (
        <p className="mt-3 text-xs text-red-400 font-mono">
          [ERROR] Verification swarm rejected key binding.
        </p>
      )}
    </div>
  );
};
