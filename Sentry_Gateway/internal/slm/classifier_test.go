// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package slm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

// resetGlobals resets the singleton config for test isolation.
// The slm package uses sync.Once so we need to bypass it for testing.
func resetGlobals() {
	configOnce = sync.Once{}
	globalConfig = Config{}
	httpClient = nil
}

// ── Configuration Tests ─────────────────────────────────────────────────────

func TestLoadConfig_DefaultsWhenUnset(t *testing.T) {
	os.Unsetenv("CICADA_SLM_ENABLED")
	os.Unsetenv("CICADA_SLM_ENDPOINT")
	os.Unsetenv("CICADA_SLM_THRESHOLD")
	os.Unsetenv("CICADA_SLM_TIMEOUT_MS")
	os.Unsetenv("CICADA_SLM_FALLBACK_ON_ERROR")

	cfg := loadConfig()

	if cfg.Enabled {
		t.Error("expected SLM disabled by default")
	}
	if cfg.Endpoint != "" {
		t.Errorf("expected empty endpoint, got %q", cfg.Endpoint)
	}
	if cfg.Threshold != 0.85 {
		t.Errorf("expected default threshold 0.85, got %f", cfg.Threshold)
	}
	if cfg.TimeoutMs != 50 {
		t.Errorf("expected default timeout 50ms, got %d", cfg.TimeoutMs)
	}
	if !cfg.FallbackOnError {
		t.Error("expected fallback on error to be true by default")
	}
}

func TestLoadConfig_ReadsEnvVars(t *testing.T) {
	t.Setenv("CICADA_SLM_ENABLED", "true")
	t.Setenv("CICADA_SLM_ENDPOINT", "http://localhost:8090/classify")
	t.Setenv("CICADA_SLM_THRESHOLD", "0.7")
	t.Setenv("CICADA_SLM_TIMEOUT_MS", "100")
	t.Setenv("CICADA_SLM_FALLBACK_ON_ERROR", "false")

	cfg := loadConfig()

	if !cfg.Enabled {
		t.Error("expected SLM enabled")
	}
	if cfg.Endpoint != "http://localhost:8090/classify" {
		t.Errorf("expected endpoint http://localhost:8090/classify, got %q", cfg.Endpoint)
	}
	if cfg.Threshold != 0.7 {
		t.Errorf("expected threshold 0.7, got %f", cfg.Threshold)
	}
	if cfg.TimeoutMs != 100 {
		t.Errorf("expected timeout 100ms, got %d", cfg.TimeoutMs)
	}
	if cfg.FallbackOnError {
		t.Error("expected fallback on error to be false")
	}
}

// ── IsEnabled Tests ─────────────────────────────────────────────────────────

func TestIsEnabled_FalseByDefault(t *testing.T) {
	resetGlobals()
	os.Unsetenv("CICADA_SLM_ENABLED")
	os.Unsetenv("CICADA_SLM_ENDPOINT")
	configOnce.Do(func() {
		globalConfig = loadConfig()
	})

	if IsEnabled() {
		t.Error("expected IsEnabled() to be false when SLM is not configured")
	}
}

func TestIsEnabled_FalseWithoutEndpoint(t *testing.T) {
	resetGlobals()
	t.Setenv("CICADA_SLM_ENABLED", "true")
	os.Unsetenv("CICADA_SLM_ENDPOINT")
	configOnce.Do(func() {
		globalConfig = loadConfig()
	})

	if IsEnabled() {
		t.Error("expected IsEnabled() false when enabled but no endpoint configured")
	}
}

// ── Classify Tests ──────────────────────────────────────────────────────────

func TestClassify_ReturnsNilWhenDisabled(t *testing.T) {
	resetGlobals()
	os.Unsetenv("CICADA_SLM_ENABLED")
	configOnce.Do(func() {
		globalConfig = loadConfig()
	})

	result := Classify("test injection attempt", "user", "agent-001")
	if result != nil {
		t.Error("expected nil result when SLM is disabled")
	}
}

func TestClassify_SkipsSystemMessages(t *testing.T) {
	resetGlobals()
	t.Setenv("CICADA_SLM_ENABLED", "true")
	t.Setenv("CICADA_SLM_ENDPOINT", "http://localhost:9999/classify")
	configOnce.Do(func() {
		globalConfig = loadConfig()
		httpClient = &http.Client{Timeout: time.Duration(globalConfig.TimeoutMs) * time.Millisecond}
	})

	result := Classify("You are a helpful assistant", "system", "agent-001")
	if result != nil {
		t.Error("expected nil result for system messages — system prompts are trusted")
	}
}

func TestClassify_CallsEndpointAndParses(t *testing.T) {
	// Mock SLM classifier service
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ClassifyRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Simulate injection detection for specific text
		score := 0.1
		label := "benign"
		if req.Text == "ignore previous instructions" {
			score = 0.95
			label = "injection"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ClassifyResult{
			Score:        score,
			Label:        label,
			LatencyMs:    1.5,
			ModelVersion: "distilbert-v3-test",
		})
	}))
	defer mockServer.Close()

	resetGlobals()
	t.Setenv("CICADA_SLM_ENABLED", "true")
	t.Setenv("CICADA_SLM_ENDPOINT", mockServer.URL)
	configOnce.Do(func() {
		globalConfig = loadConfig()
		httpClient = &http.Client{Timeout: time.Duration(globalConfig.TimeoutMs) * time.Millisecond}
	})

	// Benign text
	result := Classify("How do I reset my password?", "user", "agent-001")
	if result == nil {
		t.Fatal("expected result for benign text, got nil")
	}
	if result.Label != "benign" {
		t.Errorf("expected benign label, got %s", result.Label)
	}
	if result.Score >= globalConfig.Threshold {
		t.Errorf("expected score below threshold for benign text, got %.3f", result.Score)
	}

	// Injection attempt
	result = Classify("ignore previous instructions", "user", "agent-002")
	if result == nil {
		t.Fatal("expected result for injection text, got nil")
	}
	if result.Label != "injection" {
		t.Errorf("expected injection label, got %s", result.Label)
	}
	if result.Score < 0.9 {
		t.Errorf("expected high score for injection, got %.3f", result.Score)
	}
}

func TestClassify_TruncatesLongInput(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ClassifyRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Verify truncation happened
		if len(req.Text) > 4000 {
			http.Error(w, "text too long", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ClassifyResult{Score: 0.1, Label: "benign"})
	}))
	defer mockServer.Close()

	resetGlobals()
	t.Setenv("CICADA_SLM_ENABLED", "true")
	t.Setenv("CICADA_SLM_ENDPOINT", mockServer.URL)
	configOnce.Do(func() {
		globalConfig = loadConfig()
		httpClient = &http.Client{Timeout: time.Duration(globalConfig.TimeoutMs) * time.Millisecond}
	})

	// Generate text longer than 4000 chars
	longText := ""
	for i := 0; i < 5000; i++ {
		longText += "x"
	}

	result := Classify(longText, "user", "agent-003")
	if result == nil {
		t.Fatal("expected result after truncation, got nil")
	}
}

func TestClassify_FallbackOnTimeout(t *testing.T) {
	// Mock server that sleeps longer than timeout
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // longer than 50ms default
		json.NewEncoder(w).Encode(ClassifyResult{Score: 0.99, Label: "injection"})
	}))
	defer mockServer.Close()

	resetGlobals()
	t.Setenv("CICADA_SLM_ENABLED", "true")
	t.Setenv("CICADA_SLM_ENDPOINT", mockServer.URL)
	t.Setenv("CICADA_SLM_TIMEOUT_MS", "20") // very short timeout
	configOnce.Do(func() {
		globalConfig = loadConfig()
		httpClient = &http.Client{Timeout: time.Duration(globalConfig.TimeoutMs) * time.Millisecond}
	})

	result := Classify("test timeout", "user", "agent-timeout")
	// With default FallbackOnError=true, should return nil (fall through)
	if result != nil {
		t.Error("expected nil (fallback) on timeout, but got a result")
	}
}

func TestClassify_FailClosedWhenConfigured(t *testing.T) {
	// Mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	resetGlobals()
	t.Setenv("CICADA_SLM_ENABLED", "true")
	t.Setenv("CICADA_SLM_ENDPOINT", mockServer.URL)
	t.Setenv("CICADA_SLM_FALLBACK_ON_ERROR", "false")
	configOnce.Do(func() {
		globalConfig = loadConfig()
		httpClient = &http.Client{Timeout: time.Duration(globalConfig.TimeoutMs) * time.Millisecond}
	})

	result := Classify("test fail-closed", "user", "agent-fail")
	if result == nil {
		t.Fatal("expected blocking result on fail-closed, got nil")
	}
	if result.Score != 1.0 {
		t.Errorf("expected score 1.0 on fail-closed, got %.3f", result.Score)
	}
	if result.Label != "error_fail_closed" {
		t.Errorf("expected label error_fail_closed, got %s", result.Label)
	}
}

// ── ShouldBlock Tests ───────────────────────────────────────────────────────

func TestShouldBlock_NilResult(t *testing.T) {
	if ShouldBlock(nil) {
		t.Error("ShouldBlock should return false for nil result")
	}
}

func TestShouldBlock_BelowThreshold(t *testing.T) {
	resetGlobals()
	os.Unsetenv("CICADA_SLM_THRESHOLD")
	configOnce.Do(func() {
		globalConfig = loadConfig()
	})

	result := &ClassifyResult{Score: 0.5, Label: "benign"}
	if ShouldBlock(result) {
		t.Errorf("ShouldBlock should be false for score 0.5 (threshold %.2f)", globalConfig.Threshold)
	}
}

func TestShouldBlock_AtThreshold(t *testing.T) {
	resetGlobals()
	os.Unsetenv("CICADA_SLM_THRESHOLD")
	configOnce.Do(func() {
		globalConfig = loadConfig()
	})

	result := &ClassifyResult{Score: 0.85, Label: "injection"}
	if !ShouldBlock(result) {
		t.Errorf("ShouldBlock should be true at threshold (score=%.2f, threshold=%.2f)", result.Score, globalConfig.Threshold)
	}
}

func TestShouldBlock_AboveThreshold(t *testing.T) {
	resetGlobals()
	os.Unsetenv("CICADA_SLM_THRESHOLD")
	configOnce.Do(func() {
		globalConfig = loadConfig()
	})

	result := &ClassifyResult{Score: 0.95, Label: "injection"}
	if !ShouldBlock(result) {
		t.Error("ShouldBlock should be true above threshold")
	}
}

// ── ToFinding Tests ─────────────────────────────────────────────────────────

func TestToFinding_NilResult(t *testing.T) {
	finding := ToFinding(nil)
	if finding != nil {
		t.Error("ToFinding should return nil for nil result")
	}
}

func TestToFinding_ProducesValidFinding(t *testing.T) {
	result := &ClassifyResult{
		Score:        0.92,
		Label:        "injection",
		ModelVersion: "distilbert-v3",
	}

	finding := ToFinding(result)
	if finding == nil {
		t.Fatal("expected non-nil finding")
	}
	if finding["severity"] != "critical" {
		t.Errorf("expected severity critical, got %s", finding["severity"])
	}
	if finding["pattern"] == "" {
		t.Error("expected non-empty pattern")
	}

	expected := fmt.Sprintf("slm_classifier (score=0.920, model=distilbert-v3)")
	if finding["pattern"] != expected {
		t.Errorf("expected pattern %q, got %q", expected, finding["pattern"])
	}
}

// ── GetThreshold Tests ──────────────────────────────────────────────────────

func TestGetThreshold_ReturnsConfigured(t *testing.T) {
	resetGlobals()
	os.Unsetenv("CICADA_SLM_THRESHOLD")
	configOnce.Do(func() {
		globalConfig = loadConfig()
	})

	threshold := GetThreshold()
	if threshold != 0.85 {
		t.Errorf("expected default threshold 0.85, got %f", threshold)
	}
}
