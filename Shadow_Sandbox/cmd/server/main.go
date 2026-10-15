// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Shadow Sandbox — Cicada isolation container
//
// This server receives HTTP requests that the Sentry Gateway has diverted from
// ghost-mode agents. The agent never knows it was diverted — it receives
// plausible-looking synthetic responses shaped to match the target API.
//
// Every intercepted request is:
//   1. Recorded to SQLite (append-only, operator-queryable)
//   2. Analysed for behavioural anomalies by the analyzer package
//   3. Reported back to the Sentry Gateway gossip endpoint if anomaly score
//      exceeds the threshold (0.70) — so the operator sees it in real time
//
// The container has no outbound internet access at the network layer.
// This file makes no HTTP calls except the gossip report back to the gateway
// at CICADA_GATEWAY_GOSSIP_URL (an internal address, not the public internet).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/asai/cicada/shadow_sandbox/internal/analyzer"
	"github.com/asai/cicada/shadow_sandbox/internal/store"
)

func main() {
	port := os.Getenv("SANDBOX_PORT")
	if port == "" {
		port = "9090"
	}

	if err := store.OpenDefault(); err != nil {
		log.Fatalf("[SANDBOX] failed to open database: %v", err)
	}
	log.Printf("[SANDBOX] database ready")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/sandbox/proxy", handleProxy)
	mux.HandleFunc("/sandbox/events", handleEvents)

	log.Printf("[SANDBOX] listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("[SANDBOX] server error: %v", err)
	}
}

// handleHealth returns 200 OK so the gateway and start_fleet.sh can confirm
// the sandbox is alive before routing traffic to it.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","service":"shadow_sandbox"}`))
}

// handleProxy is the primary endpoint. The Sentry Gateway forwards every
// ghost-mode agent request here. The sandbox returns a plausible response,
// records the interaction, and reports anomalies to the gateway.
func handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Envelope from the gateway: the agent's original request is nested inside.
	var envelope struct {
		AgentID   string          `json:"agent_id"`
		TenantID  string          `json:"tenant_id"`
		TraceID   string          `json:"trace_id"`
		Method    string          `json:"method"`
		TargetURL string          `json:"target_url"`
		Headers   map[string]string `json:"headers"`
		Body      string          `json:"body"` // base64-encoded original body
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024))
	if err != nil {
		http.Error(w, `{"error":"read error"}`, http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		http.Error(w, `{"error":"invalid envelope"}`, http.StatusBadRequest)
		return
	}

	bodyBytes := []byte(envelope.Body)

	// Analyse the intercepted request for behavioural anomalies.
	result := analyzer.Analyze(envelope.Method, envelope.TargetURL, bodyBytes)

	// Snapshot first 1024 bytes for the database — not the full body to keep
	// storage manageable and avoid logging sensitive data at scale.
	snapshot := envelope.Body
	if len(snapshot) > 1024 {
		snapshot = snapshot[:1024] + "...[truncated]"
	}

	findingsJSON, _ := json.Marshal(result.Findings)

	store.Append(store.Event{
		AgentID:      envelope.AgentID,
		TenantID:     envelope.TenantID,
		TraceID:      envelope.TraceID,
		Method:       envelope.Method,
		TargetURL:    envelope.TargetURL,
		BodySnapshot: snapshot,
		AnomalyScore: result.AnomalyScore,
		Findings:     string(findingsJSON),
		SentToGossip: result.ShouldReport,
	})

	log.Printf("[SANDBOX] intercepted %s %s agent=%s score=%.2f findings=%s",
		envelope.Method, envelope.TargetURL, envelope.AgentID,
		result.AnomalyScore, result.Summary)

	// If the anomaly score is above the report threshold, push a quarantine
	// signal to the gateway's gossip endpoint. This is the feedback loop that
	// makes ghost mode an active defence rather than just passive logging.
	if result.ShouldReport {
		go reportToGossip(envelope.AgentID, envelope.TenantID, envelope.TraceID, result)
	}

	// Return a plausible synthetic response to the agent. The response is shaped
	// to match the target API so the agent cannot detect the diversion by
	// inspecting the response structure.
	respBody, statusCode, contentType := analyzer.PlausibleResponse(
		envelope.Method, envelope.TargetURL, bodyBytes,
	)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Cicada-Sandbox", "true")
	w.Header().Set("X-Cicada-Trace-ID", envelope.TraceID)
	w.WriteHeader(statusCode)
	w.Write(respBody)
}

// handleEvents returns the most recent 100 sandbox events for the operator
// dashboard. This is internal-only — the container does not expose this
// to the public internet.
func handleEvents(w http.ResponseWriter, r *http.Request) {
	events, err := store.Recent(100)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []store.Event{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"events": events,
		"count":  len(events),
	})
}

// reportToGossip sends a quarantine-candidate signal to the Sentry Gateway.
// The gateway logs this as a sandbox anomaly event but does NOT automatically
// quarantine — that decision belongs to the operator via Aegis-0. The signal
// surfaces in the threat dashboard so the operator can act.
func reportToGossip(agentID, tenantID, traceID string, result analyzer.Result) {
	gossipURL := os.Getenv("CICADA_GATEWAY_GOSSIP_URL")
	if gossipURL == "" {
		// Default: gateway is accessible at the Docker bridge gateway address.
		// The gateway's gossip endpoint accepts sandbox reports on /v1/sandbox/report.
		gossipURL = "http://host.docker.internal:8080/v1/sandbox/report"
	}

	payload, _ := json.Marshal(map[string]any{
		"agent_id":      agentID,
		"tenant_id":     tenantID,
		"trace_id":      traceID,
		"anomaly_score": result.AnomalyScore,
		"findings":      result.Findings,
		"summary":       result.Summary,
		"reported_at":   time.Now().UTC().Format(time.RFC3339),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gossipURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("[SANDBOX] gossip report build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[SANDBOX] gossip report failed for agent %s: %v", agentID, err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[SANDBOX] gossip report sent for agent %s score=%.2f → %d", agentID, result.AnomalyScore, resp.StatusCode)
}

