// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package caep implements inbound IETF Shared Signals Framework (SSF) /
// Continuous Access Evaluation Protocol (CAEP) event processing.
//
// When an external IdP (Okta, Microsoft Entra, Google Workspace) detects a
// security event — user session revoked, credential compromised, assurance
// level degraded — it POSTs a CAEP Security Event Token (SET) to
// POST /v1/sso/caep/webhook. This handler:
//
//  1. Validates the event against CICADA_CAEP_TRUSTED_ISSUERS
//  2. Extracts agent/tenant identifiers from the CAEP subject
//  3. Maps CAEP event types to Cicada actions (quarantine, flag, log)
//  4. Triggers gossip mesh propagation for quarantine actions
//  5. Writes an immutable audit record to the evidence chain
//
// Supported CAEP event types:
//
//	session-revoked         → quarantine agent
//	credential-change       → quarantine agent
//	assurance-level-change  → flag agent (operator review)
//	token-claims-change     → log only
//
// Reference: https://openid.net/specs/openid-caep-specification-1_0.html
package caep

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/asai/cicada/sentry/internal/gossip"
	"github.com/asai/cicada/sentry/internal/ledger"
)

// ── CAEP Event URI → Action Mapping ─────────────────────────────────────────

// CaepAction defines the response to a received CAEP event.
type CaepAction string

const (
	ActionQuarantine CaepAction = "quarantine" // Immediate gossip quarantine
	ActionFlag       CaepAction = "flag"       // Log + alert, operator decides
	ActionLog        CaepAction = "log"        // Audit trail only
)

// eventActionMap maps standard CAEP event URIs to Cicada responses.
var eventActionMap = map[string]CaepAction{
	"https://schemas.openid.net/secevent/caep/event-type/session-revoked":        ActionQuarantine,
	"https://schemas.openid.net/secevent/caep/event-type/credential-change":      ActionQuarantine,
	"https://schemas.openid.net/secevent/caep/event-type/assurance-level-change": ActionFlag,
	"https://schemas.openid.net/secevent/caep/event-type/token-claims-change":    ActionLog,
}

// ── Wire Format ─────────────────────────────────────────────────────────────

// SecurityEventToken is the IETF SSF/CAEP wire format.
// https://openid.net/specs/openid-caep-specification-1_0.html#section-3
type SecurityEventToken struct {
	Iss    string                            `json:"iss"`    // IdP issuer URI
	Iat    int64                             `json:"iat"`    // Issued-at timestamp
	Jti    string                            `json:"jti"`    // Unique event ID
	Aud    string                            `json:"aud"`    // Audience (tenant ID or Cicada instance)
	Events map[string]json.RawMessage        `json:"events"` // Keyed by CAEP event URI
}

// CaepEventBody is the inner body of a CAEP event.
type CaepEventBody struct {
	Subject         CaepSubject `json:"subject"`
	EventTimestamp  string      `json:"event_timestamp,omitempty"`
	ReasonAdmin     map[string]string `json:"reason_admin,omitempty"`
	InitiatingEntity string    `json:"initiating_entity,omitempty"`
}

// CaepSubject identifies the entity affected by the event.
type CaepSubject struct {
	SubjectType string `json:"subject_type"` // "user", "session", "agent"
	AgentID     string `json:"agent_id,omitempty"`
	TenantID    string `json:"tenant_id,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	Email       string `json:"email,omitempty"`
	Issuer      string `json:"iss,omitempty"`
	// SSF complex subject format
	Format      string `json:"format,omitempty"`
}

// ── Handler ─────────────────────────────────────────────────────────────────

// Handler returns an http.HandlerFunc that processes inbound CAEP events.
// It requires references to the gossip mesh and edge ledger, injected from main.go.
func Handler(mesh *gossip.Mesh, el *ledger.EdgeLedger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ── Rate limit: cap body size at 256KB ──────────────────────────
		body, err := io.ReadAll(io.LimitReader(r.Body, 256*1024))
		if err != nil {
			writeError(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		// ── Parse the Security Event Token ──────────────────────────────
		var set SecurityEventToken
		if err := json.Unmarshal(body, &set); err != nil {
			writeError(w, "invalid CAEP payload: "+err.Error(), http.StatusBadRequest)
			return
		}

		// ── Validate issuer against trusted list ────────────────────────
		trustedIssuers := parseTrustedIssuers()
		if len(trustedIssuers) > 0 && !trustedIssuers[set.Iss] {
			log.Printf("[CAEP] REJECTED: untrusted issuer %q — not in CICADA_CAEP_TRUSTED_ISSUERS", set.Iss)
			writeError(w, "untrusted issuer", http.StatusForbidden)
			return
		}

		// ── Validate HMAC signature if configured ───────────────────────
		webhookSecret := os.Getenv("CICADA_CAEP_WEBHOOK_SECRET")
		if webhookSecret != "" {
			signature := r.Header.Get("X-Cicada-Signature")
			if signature == "" {
				signature = r.Header.Get("X-SSF-Signature")
			}
			if !validateHMAC(body, signature, webhookSecret) {
				log.Printf("[CAEP] REJECTED: invalid HMAC signature from issuer %q", set.Iss)
				writeError(w, "invalid signature", http.StatusUnauthorized)
				return
			}
		}

		// ── Validate event age (reject stale events > 5 minutes) ────────
		if set.Iat > 0 {
			eventAge := time.Now().Unix() - set.Iat
			if eventAge > 300 {
				log.Printf("[CAEP] REJECTED: stale event from %q — age %ds exceeds 300s limit", set.Iss, eventAge)
				writeError(w, "event too old", http.StatusBadRequest)
				return
			}
			// Reject future-dated events (clock skew tolerance: 30s)
			if eventAge < -30 {
				log.Printf("[CAEP] REJECTED: future-dated event from %q — age %ds", set.Iss, eventAge)
				writeError(w, "event timestamp in future", http.StatusBadRequest)
				return
			}
		}

		// ── Process each event in the SET ───────────────────────────────
		// A single SET can carry multiple events (per SSF spec), though in
		// practice most IdPs send one event per SET.
		processed := 0
		for eventURI, rawBody := range set.Events {
			action, known := eventActionMap[eventURI]
			if !known {
				log.Printf("[CAEP] Ignoring unknown event type: %s from %s", eventURI, set.Iss)
				continue
			}

			var eventBody CaepEventBody
			if err := json.Unmarshal(rawBody, &eventBody); err != nil {
				log.Printf("[CAEP] Failed to parse event body for %s: %v", eventURI, err)
				continue
			}

			// Resolve the agent/tenant from the subject.
			agentID := resolveAgentID(eventBody.Subject)
			tenantID := resolveTenantID(eventBody.Subject, set.Aud)

			if agentID == "" {
				log.Printf("[CAEP] Skipping event %s — no agent_id resolvable from subject", eventURI)
				continue
			}

			reason := "External CAEP event"
			if msg, ok := eventBody.ReasonAdmin["en"]; ok {
				reason = msg
			}

			log.Printf("[CAEP] Processing %s event for agent=%s tenant=%s action=%s issuer=%s reason=%q",
				eventURI, agentID, tenantID, action, set.Iss, reason)

			switch action {
			case ActionQuarantine:
				if mesh != nil {
					mesh.QuarantineAgent(agentID)
				}
				log.Printf("[CAEP] QUARANTINED agent %s via inbound CAEP %s from %s", agentID, eventURI, set.Iss)

			case ActionFlag:
				log.Printf("[CAEP] FLAGGED agent %s for operator review via inbound CAEP %s from %s", agentID, eventURI, set.Iss)

			case ActionLog:
				log.Printf("[CAEP] LOGGED event %s for agent %s from %s", eventURI, agentID, set.Iss)
			}

			// ── Audit ledger entry ──────────────────────────────────────
			if el != nil {
				go el.AppendRecord(ledger.EventRecord{
					EventID:     fmt.Sprintf("caep-%s-%d", set.Jti, time.Now().UnixNano()),
					TraceID:     set.Jti,
					TenantID:    tenantID,
					AgentID:     agentID,
					ActionClass: "caep_inbound_" + string(action),
					Decision:    string(action),
					ReasonCodes: []string{
						"caep_event_received",
						fmt.Sprintf("event_type:%s", eventURI),
						fmt.Sprintf("issuer:%s", set.Iss),
						fmt.Sprintf("reason:%s", reason),
					},
					RiskScore: actionToRiskScore(action),
				})
			}

			processed++
		}

		if processed == 0 {
			writeError(w, "no processable events in SET", http.StatusUnprocessableEntity)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(fmt.Sprintf(`{"status":"accepted","processed":%d,"jti":%q}`, processed, set.Jti)))
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// parseTrustedIssuers reads CICADA_CAEP_TRUSTED_ISSUERS from the environment.
// Format: comma-separated list of issuer URIs.
// Example: "https://login.microsoftonline.com,https://dev-123456.okta.com"
// If empty, all issuers are accepted (development mode).
func parseTrustedIssuers() map[string]bool {
	raw := os.Getenv("CICADA_CAEP_TRUSTED_ISSUERS")
	if raw == "" {
		return nil
	}
	issuers := make(map[string]bool)
	for _, iss := range strings.Split(raw, ",") {
		iss = strings.TrimSpace(iss)
		if iss != "" {
			issuers[iss] = true
		}
	}
	return issuers
}

// validateHMAC verifies a "sha256=<hex>" signature against the raw body.
// Follows the same convention as GitHub webhook signatures.
func validateHMAC(body []byte, signature, secret string) bool {
	if signature == "" {
		return false
	}
	// Strip "sha256=" prefix if present
	hexSig := strings.TrimPrefix(signature, "sha256=")
	expectedMAC, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), expectedMAC)
}

// resolveAgentID extracts the agent identifier from a CAEP subject.
// Supports both Cicada-native subjects (agent_id field) and standard
// SSF subjects (user_id or email used as lookup key).
func resolveAgentID(subject CaepSubject) string {
	if subject.AgentID != "" {
		return subject.AgentID
	}
	// Fallback: some IdPs use user_id as the session identifier.
	// In Cicada's model, agents are the primary entity — but if the
	// CAEP event identifies a user whose session should be revoked,
	// we use the user_id as a proxy for "all agents acting on behalf of this user".
	if subject.UserID != "" {
		return "user:" + subject.UserID
	}
	if subject.Email != "" {
		return "user:" + subject.Email
	}
	return ""
}

// resolveTenantID extracts the tenant identifier from the subject or falls
// back to the SET audience field (which typically carries the tenant ID).
func resolveTenantID(subject CaepSubject, audience string) string {
	if subject.TenantID != "" {
		return subject.TenantID
	}
	return audience
}

// actionToRiskScore maps the CAEP action to a risk score for ledger entries.
func actionToRiskScore(action CaepAction) float64 {
	switch action {
	case ActionQuarantine:
		return 0.95
	case ActionFlag:
		return 0.70
	case ActionLog:
		return 0.30
	default:
		return 0.50
	}
}

func writeError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
