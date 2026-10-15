// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { useState, useEffect, useRef } from 'react';

export interface Verification {
  instance_id: string;
  customer_name: string;
  agent_role: string;
  status: string;
}

export interface SagaTracker {
  type: string;
  target: string;
  status: string;
  progress: number;
  trace_id: string;
}

export interface LocalAnomaly {
  type: string;
  count: number;
  severity: string;
}

export interface CityMetrics {
  active_instances: number;
  avg_latency_ms: number;
  threat_pulse_score: number;
  total_burn_rate: string;
}

export interface CityTelemetryResponse {
  city_id: string;
  metrics: CityMetrics;
  active_remediations: SagaTracker[];
  local_anomalies: LocalAnomaly[];
  verifications: Verification[];
}

export function useCityTelemetry(cityId: string | null) {
  const [telemetry, setTelemetry] = useState<CityTelemetryResponse | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!cityId) {
      setTelemetry(null);
      setIsConnected(false);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      return;
    }

    let reconnectAttempts = 0;
    let isActive = true;

    const connect = () => {
      if (!isActive) return;
      
      const WS_BASE = process.env.NEXT_PUBLIC_SENTRY_WS_URL || 'ws://localhost:8080';
      const ws = new WebSocket(`${WS_BASE}/v1/telemetry/city/${cityId}`);
      wsRef.current = ws;

      ws.onopen = () => {
        if (isActive) {
          setIsConnected(true);
          setLastError(null);
          reconnectAttempts = 0; // Reset backoff on success
        }
      };

      ws.onmessage = (event) => {
        if (!isActive) return;
        try {
          // Native 5Hz stream ingestion parsing
          const data: CityTelemetryResponse = JSON.parse(event.data);
          setTelemetry(data);
        } catch (e) {
          console.error("Failed to parse telemetry stream", e);
        }
      };

      ws.onerror = () => {
        if (isActive) {
          setLastError("WebSocket connection encountered an active anomaly block.");
          setIsConnected(false);
        }
      };

      ws.onclose = () => {
        if (isActive) {
          setIsConnected(false);
          // Automatic Reconnection loop backoff structure
          const backoff = Math.min(1000 * Math.pow(2, reconnectAttempts), 10000);
          reconnectAttempts++;
          setTimeout(connect, backoff);
        }
      };
    };

    connect();

    return () => {
      isActive = false;
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [cityId]);

  return { telemetry, isConnected, lastError };
}
