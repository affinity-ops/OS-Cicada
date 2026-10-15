// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package caep

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// ── Issuer Validation ───────────────────────────────────────────────────────

func TestHandler_UntrustedIssuer(t *testing.T) {
	os.Setenv("CICADA_CAEP_TRUSTED_ISSUERS", "https://login.okta.com")
	defer os.Unsetenv("CICADA_CAEP_TRUSTED_ISSUERS")

	set := SecurityEventToken{
		Iss: "https://evil-idp.example.com",
		Iat: time.Now().Unix(),
		Jti: "test-jti-001",
		Events: map[string]json.RawMessage{
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked": json.RawMessage(`{"subject":{"agent_id":"agent-1","tenant_id":"t-1"}}`),
		},
	}
	body, _ := json.Marshal(set)

	req := httptest.NewRequest(http.MethodPost, "/v1/sso/caep/webhook", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler := Handler(nil, nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for untrusted issuer, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandler_TrustedIssuerAccepted(t *testing.T) {
	os.Setenv("CICADA_CAEP_TRUSTED_ISSUERS", "https://login.okta.com,https://login.microsoftonline.com")
	defer os.Unsetenv("CICADA_CAEP_TRUSTED_ISSUERS")

	set := SecurityEventToken{
		Iss: "https://login.okta.com",
		Iat: time.Now().Unix(),
		Jti: "test-jti-002",
		Events: map[string]json.RawMessage{
			"https://schemas.openid.net/secevent/caep/event-type/token-claims-change": json.RawMessage(`{"subject":{"agent_id":"agent-2","tenant_id":"t-2"}}`),
		},
	}
	body, _ := json.Marshal(set)

	req := httptest.NewRequest(http.MethodPost, "/v1/sso/caep/webhook", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	// Pass nil mesh/ledger — ActionLog doesn't touch them
	handler := Handler(nil, nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Errorf("Expected 202 for trusted issuer, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandler_NoTrustedIssuersAllowsAll(t *testing.T) {
	os.Unsetenv("CICADA_CAEP_TRUSTED_ISSUERS")

	set := SecurityEventToken{
		Iss: "https://any-issuer.example.com",
		Iat: time.Now().Unix(),
		Jti: "test-jti-003",
		Events: map[string]json.RawMessage{
			"https://schemas.openid.net/secevent/caep/event-type/token-claims-change": json.RawMessage(`{"subject":{"agent_id":"agent-3","tenant_id":"t-3"}}`),
		},
	}
	body, _ := json.Marshal(set)

	req := httptest.NewRequest(http.MethodPost, "/v1/sso/caep/webhook", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler := Handler(nil, nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Errorf("Expected 202 when no trusted issuers configured, got %d", rr.Code)
	}
}

// ── Stale Event Rejection ───────────────────────────────────────────────────

func TestHandler_StaleEventRejected(t *testing.T) {
	os.Unsetenv("CICADA_CAEP_TRUSTED_ISSUERS")

	set := SecurityEventToken{
		Iss: "https://idp.example.com",
		Iat: time.Now().Unix() - 600, // 10 minutes ago — exceeds 300s limit
		Jti: "test-jti-stale",
		Events: map[string]json.RawMessage{
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked": json.RawMessage(`{"subject":{"agent_id":"agent-4"}}`),
		},
	}
	body, _ := json.Marshal(set)

	req := httptest.NewRequest(http.MethodPost, "/v1/sso/caep/webhook", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler := Handler(nil, nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for stale event, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ── HMAC Validation ─────────────────────────────────────────────────────────

func TestHandler_InvalidHMACRejected(t *testing.T) {
	os.Setenv("CICADA_CAEP_WEBHOOK_SECRET", "my-secret-key")
	defer os.Unsetenv("CICADA_CAEP_WEBHOOK_SECRET")
	os.Unsetenv("CICADA_CAEP_TRUSTED_ISSUERS")

	set := SecurityEventToken{
		Iss: "https://idp.example.com",
		Iat: time.Now().Unix(),
		Jti: "test-jti-hmac",
		Events: map[string]json.RawMessage{
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked": json.RawMessage(`{"subject":{"agent_id":"agent-5"}}`),
		},
	}
	body, _ := json.Marshal(set)

	req := httptest.NewRequest(http.MethodPost, "/v1/sso/caep/webhook", bytes.NewReader(body))
	req.Header.Set("X-Cicada-Signature", "sha256=0000000000000000000000000000000000000000000000000000000000000000")
	rr := httptest.NewRecorder()

	handler := Handler(nil, nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for invalid HMAC, got %d", rr.Code)
	}
}

func TestHandler_ValidHMACAccepted(t *testing.T) {
	secret := "my-secret-key"
	os.Setenv("CICADA_CAEP_WEBHOOK_SECRET", secret)
	defer os.Unsetenv("CICADA_CAEP_WEBHOOK_SECRET")
	os.Unsetenv("CICADA_CAEP_TRUSTED_ISSUERS")

	set := SecurityEventToken{
		Iss: "https://idp.example.com",
		Iat: time.Now().Unix(),
		Jti: "test-jti-hmac-valid",
		Events: map[string]json.RawMessage{
			"https://schemas.openid.net/secevent/caep/event-type/token-claims-change": json.RawMessage(`{"subject":{"agent_id":"agent-6","tenant_id":"t-6"}}`),
		},
	}
	body, _ := json.Marshal(set)

	// Compute valid HMAC
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/v1/sso/caep/webhook", bytes.NewReader(body))
	req.Header.Set("X-Cicada-Signature", sig)
	rr := httptest.NewRecorder()

	handler := Handler(nil, nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Errorf("Expected 202 for valid HMAC, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ── Subject Resolution ──────────────────────────────────────────────────────

func TestResolveAgentID_DirectField(t *testing.T) {
	id := resolveAgentID(CaepSubject{AgentID: "agent-abc"})
	if id != "agent-abc" {
		t.Errorf("Expected agent-abc, got %s", id)
	}
}

func TestResolveAgentID_FallbackToUserID(t *testing.T) {
	id := resolveAgentID(CaepSubject{UserID: "user-123"})
	if id != "user:user-123" {
		t.Errorf("Expected user:user-123, got %s", id)
	}
}

func TestResolveAgentID_FallbackToEmail(t *testing.T) {
	id := resolveAgentID(CaepSubject{Email: "admin@corp.com"})
	if id != "user:admin@corp.com" {
		t.Errorf("Expected user:admin@corp.com, got %s", id)
	}
}

func TestResolveAgentID_Empty(t *testing.T) {
	id := resolveAgentID(CaepSubject{})
	if id != "" {
		t.Errorf("Expected empty string for empty subject, got %s", id)
	}
}

func TestResolveTenantID_SubjectField(t *testing.T) {
	id := resolveTenantID(CaepSubject{TenantID: "tenant-1"}, "aud-fallback")
	if id != "tenant-1" {
		t.Errorf("Expected tenant-1, got %s", id)
	}
}

func TestResolveTenantID_AudienceFallback(t *testing.T) {
	id := resolveTenantID(CaepSubject{}, "aud-fallback")
	if id != "aud-fallback" {
		t.Errorf("Expected aud-fallback, got %s", id)
	}
}

// ── Event Action Mapping ────────────────────────────────────────────────────

func TestEventActionMapping(t *testing.T) {
	tests := []struct {
		eventURI string
		expected CaepAction
	}{
		{"https://schemas.openid.net/secevent/caep/event-type/session-revoked", ActionQuarantine},
		{"https://schemas.openid.net/secevent/caep/event-type/credential-change", ActionQuarantine},
		{"https://schemas.openid.net/secevent/caep/event-type/assurance-level-change", ActionFlag},
		{"https://schemas.openid.net/secevent/caep/event-type/token-claims-change", ActionLog},
	}

	for _, tt := range tests {
		action, ok := eventActionMap[tt.eventURI]
		if !ok {
			t.Errorf("Event URI %s not found in action map", tt.eventURI)
			continue
		}
		if action != tt.expected {
			t.Errorf("Event %s: expected action %s, got %s", tt.eventURI, tt.expected, action)
		}
	}
}

// ── HMAC Helper ─────────────────────────────────────────────────────────────

func TestValidateHMAC_Correct(t *testing.T) {
	body := []byte(`{"test":"payload"}`)
	secret := "test-secret"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if !validateHMAC(body, sig, secret) {
		t.Error("Expected valid HMAC to pass")
	}
}

func TestValidateHMAC_Wrong(t *testing.T) {
	body := []byte(`{"test":"payload"}`)
	if validateHMAC(body, "sha256=deadbeef00000000000000000000000000000000000000000000000000000000", "secret") {
		t.Error("Expected wrong HMAC to fail")
	}
}

func TestValidateHMAC_Empty(t *testing.T) {
	if validateHMAC([]byte("test"), "", "secret") {
		t.Error("Expected empty signature to fail")
	}
}

// ── Invalid Payload ─────────────────────────────────────────────────────────

func TestHandler_InvalidJSON(t *testing.T) {
	os.Unsetenv("CICADA_CAEP_TRUSTED_ISSUERS")

	req := httptest.NewRequest(http.MethodPost, "/v1/sso/caep/webhook", bytes.NewReader([]byte(`not json`)))
	rr := httptest.NewRecorder()

	handler := Handler(nil, nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestHandler_NoProcessableEvents(t *testing.T) {
	os.Unsetenv("CICADA_CAEP_TRUSTED_ISSUERS")

	set := SecurityEventToken{
		Iss:    "https://idp.example.com",
		Iat:    time.Now().Unix(),
		Jti:    "test-jti-noevents",
		Events: map[string]json.RawMessage{},
	}
	body, _ := json.Marshal(set)

	req := httptest.NewRequest(http.MethodPost, "/v1/sso/caep/webhook", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler := Handler(nil, nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected 422 for empty events, got %d", rr.Code)
	}
}

func TestHandler_UnknownEventTypeIgnored(t *testing.T) {
	os.Unsetenv("CICADA_CAEP_TRUSTED_ISSUERS")

	set := SecurityEventToken{
		Iss: "https://idp.example.com",
		Iat: time.Now().Unix(),
		Jti: "test-jti-unknown",
		Events: map[string]json.RawMessage{
			"https://example.com/custom-event": json.RawMessage(`{"subject":{"agent_id":"agent-x"}}`),
		},
	}
	body, _ := json.Marshal(set)

	req := httptest.NewRequest(http.MethodPost, "/v1/sso/caep/webhook", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler := Handler(nil, nil)
	handler.ServeHTTP(rr, req)

	// Unknown events should result in 422 (no processable events)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected 422 for unknown event type only, got %d", rr.Code)
	}
}

// ── Risk Score Mapping ──────────────────────────────────────────────────────

func TestActionToRiskScore(t *testing.T) {
	if s := actionToRiskScore(ActionQuarantine); s != 0.95 {
		t.Errorf("Quarantine risk: expected 0.95, got %f", s)
	}
	if s := actionToRiskScore(ActionFlag); s != 0.70 {
		t.Errorf("Flag risk: expected 0.70, got %f", s)
	}
	if s := actionToRiskScore(ActionLog); s != 0.30 {
		t.Errorf("Log risk: expected 0.30, got %f", s)
	}
}
