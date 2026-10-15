// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package output — operator alert emission for threat events.
//
// This file implements S1.2: when the Sentry Gateway detects a high-severity
// threat (exfiltration, prompt injection, semantic mismatch, velocity breach),
// it fires an alert to the Core API. The Core API's AlertDispatcherService
// then routes the alert to configured webhook/PagerDuty destinations.
//
// Why this is Gateway → Core API and not direct webhook:
// The Gateway is a stateless reverse proxy. It does not know about:
//   - which alert rules are configured (stored in PostgreSQL)
//   - which webhook destinations are active
//   - which PagerDuty integrations are set up
//   - SSRF validation rules on alert destinations
//
// The Core API already handles all of this via AlertDispatcherService.
// The Gateway's responsibility is to fire a structured event; the Core API's
// responsibility is to route it.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// ThreatAlertPayload is the structured event sent to the Core API when
// a threat event is detected. This maps to the
// AlertDispatcherService's expected payload format.
type ThreatAlertPayload struct {
	// EventType identifies this alert for alert rule matching.
	EventType string `json:"event_type"`

	// TenantID scopes the alert to a specific tenant.
	TenantID string `json:"tenant_id"`

	// AgentID identifies the agent whose request triggered the alert.
	AgentID string `json:"agent_id"`

	// Context carries the investigation details for operator investigation.
	Context ThreatAlertContext `json:"context"`

	// Timestamp is when the alert was generated (RFC 3339).
	Timestamp string `json:"timestamp"`

	// Source identifies the generating service.
	Source string `json:"source"`
}

// ThreatAlertContext carries the investigation details operators need
// to understand and respond to the threat event.
type ThreatAlertContext struct {
	Severity         string `json:"severity"`
	TargetURL        string `json:"target_url,omitempty"`
	DestinationTrust string `json:"destination_trust,omitempty"`
	VaultMatch       bool   `json:"vault_match,omitempty"`
	FindingSummary   string `json:"finding_summary"`
	Action           string `json:"action"`
	TraceID          string `json:"trace_id,omitempty"`
}

// alertEmissionTimeout limits how long the Gateway waits for the Core API to
// accept the alert. Alert emission must not slow the proxy path.
const alertEmissionTimeout = 2 * time.Second

// alertClient is a shared, package-level HTTP client with bounded connection
// pooling. Using a per-call client leaked goroutines under load because each
// client created its own connection pool — at 150 req/s with multiple alerts
// per request, hundreds of goroutines held TCP sockets waiting for the 2s
// timeout against a non-running Core API, exhausting file descriptors.
var alertClient = &http.Client{
	Timeout: alertEmissionTimeout,
	Transport: &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
		MaxConnsPerHost:     10,
	},
}

// ExfiltrationAlertPayload is a backward-compatible alias for ThreatAlertPayload.
// The exfiltration alert test suite uses this type name for deserialization.
type ExfiltrationAlertPayload = ThreatAlertPayload

// EmitThreatAlert sends a structured threat alert to the Core API's
// internal alert endpoint. The Core API routes it to configured destinations
// via AlertDispatcherService.
func EmitThreatAlert(
	eventType string,
	severity string,
	tenantID string,
	agentID string,
	targetURL string,
	findingSummary string,
	action string,
	traceID string,
	extraContext map[string]any,
) {
	coreAPIURL := os.Getenv("CICADA_CORE_API_URL")
	internalKey := os.Getenv("CICADA_INTERNAL_KEY")

	if coreAPIURL == "" {
		log.Printf("[ThreatAlert] ALERT (local only): type=%s tenant=%s agent=%s target=%s",
			eventType, tenantID, agentID, targetURL)
		return
	}

	ctx := ThreatAlertContext{
		Severity:       severity,
		TargetURL:      targetURL,
		FindingSummary: findingSummary,
		Action:         action,
		TraceID:        traceID,
	}

	if val, ok := extraContext["destination_trust"]; ok {
		if dt, ok := val.(DestinationTrust); ok {
			ctx.DestinationTrust = destinationTrustLabel(dt)
		}
	}
	if val, ok := extraContext["vault_match"]; ok {
		if vm, ok := val.(bool); ok {
			ctx.VaultMatch = vm
		}
	}

	payload := ThreatAlertPayload{
		EventType: eventType,
		TenantID:  tenantID,
		AgentID:   agentID,
		Context:   ctx,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Source:    "Sentry-Gateway/threat-scanner",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[ThreatAlert] failed to marshal alert payload: %v", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/internal/threat-alert", coreAPIURL)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[ThreatAlert] failed to build alert request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if internalKey != "" {
		req.Header.Set("X-Gateway-Secret", internalKey)
	}

	resp, err := alertClient.Do(req)
	if err != nil {
		log.Printf("[ThreatAlert] Core API unreachable for alert: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[ThreatAlert] Alert dispatched: type=%s severity=%s tenant=%s agent=%s",
			eventType, severity, tenantID, agentID)
	} else {
		log.Printf("[ThreatAlert] Core API returned %d for alert: type=%s tenant=%s",
			resp.StatusCode, eventType, tenantID)
	}
}

// EmitExfiltrationAlert is a wrapper around EmitThreatAlert for backward compatibility
// and specific exfiltration logic mapping.
func EmitExfiltrationAlert(
	tenantID, agentID, targetURL string,
	vaultMatch bool,
	destinationTrust DestinationTrust,
	findingSummary string,
	traceID string,
) {
	eventType := "pii_exfiltration"
	severity := "high"
	action := "Review agent activity and consider quarantine"

	if vaultMatch {
		eventType = "credential_exfiltration"
		severity = "critical"
		action = "IMMEDIATE: Quarantine agent, rotate affected BYOK key, review all recent agent actions"
	}

	if destinationTrust == TrustExfiltrationSink {
		severity = "critical"
		action = "IMMEDIATE: Agent sent credentials to a known exfiltration sink — quarantine and investigate"
	}

	EmitThreatAlert(
		eventType,
		severity,
		tenantID,
		agentID,
		targetURL,
		findingSummary,
		action,
		traceID,
		map[string]any{
			"destination_trust": destinationTrust,
			"vault_match":       vaultMatch,
		},
	)
}

func destinationTrustLabel(dt DestinationTrust) string {
	switch dt {
	case TrustExfiltrationSink:
		return "exfiltration_sink"
	case TrustNewDomain:
		return "new_domain"
	case TrustKnown:
		return "known_domain"
	case TrustPropagation:
		return "propagation_allowed"
	default:
		return "unknown"
	}
}
