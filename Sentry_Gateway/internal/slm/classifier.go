// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package slm implements a distilled small language model (SLM) classifier
// for fast-path prompt injection detection at Layer 1 of the Cicada pipeline.
//
// Architecture:
//
//	                  ┌─────────────────────┐
//	  Inbound text ──→│  SLM Fast Classifier │──→ score ≥ threshold?
//	                  └─────────────────────┘         │
//	                                               Y  │  N
//	                                               ▼  │  ▼
//	                                          [BLOCK] │ [PASS to regex/DOM]
//
// The SLM classifier runs BEFORE the regex/DOM scanner and the expensive
// Verification Swarm evaluation. It is a lightweight HTTP microservice that
// hosts a fine-tuned DistilBERT-class model trained on Cicada's injection +
// semantic mismatch patterns.
//
// Integration point: injection.Scan() calls slm.Classify() first. If the
// SLM returns a score above the configurable threshold, the request is
// blocked immediately without incurring the cost of downstream LLM calls.
//
// Deployment modes:
//   - LOCAL: Model loaded in-process via ONNX Runtime (lowest latency, ~2ms)
//   - HTTP:  External classifier service at CICADA_SLM_ENDPOINT (flexible deployment)
//   - OFF:   SLM disabled — fall through to regex/DOM only (default)
//
// The classifier is designed as a pre-filter, not a replacement. Regex/DOM
// scanning always runs as a second pass to catch structural patterns the SLM
// might miss. The SLM catches novel, natural-language injection attempts that
// evade pattern matching.
package slm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Configuration ───────────────────────────────────────────────────────────

// Config holds the SLM classifier configuration, loaded from env vars at init.
type Config struct {
	// Enabled determines whether the SLM classifier runs.
	// Set via CICADA_SLM_ENABLED. Default: false.
	Enabled bool

	// Endpoint is the HTTP URL of the SLM classifier service.
	// Set via CICADA_SLM_ENDPOINT. Example: "http://localhost:8090/classify"
	Endpoint string

	// Threshold is the minimum score (0.0–1.0) to trigger an immediate block.
	// Set via CICADA_SLM_THRESHOLD. Default: 0.85.
	// High default to minimize false positives — the SLM is a pre-filter,
	// not the sole decision maker.
	Threshold float64

	// TimeoutMs is the maximum time to wait for the SLM service response.
	// Set via CICADA_SLM_TIMEOUT_MS. Default: 50ms.
	// If the SLM doesn't respond in time, we fall through to regex/DOM.
	TimeoutMs int

	// FallbackOnError determines whether to continue to regex/DOM on SLM error.
	// Set via CICADA_SLM_FALLBACK_ON_ERROR. Default: true.
	// If false, SLM errors will block the request (fail-closed).
	FallbackOnError bool
}

// ClassifyResult is the SLM classifier response.
type ClassifyResult struct {
	// Score is the injection probability (0.0–1.0).
	Score float64 `json:"score"`
	// Label is the classifier's predicted label.
	// "injection" or "benign"
	Label string `json:"label"`
	// LatencyMs is the classifier inference time.
	LatencyMs float64 `json:"latency_ms"`
	// ModelVersion identifies which SLM checkpoint produced this result.
	ModelVersion string `json:"model_version,omitempty"`
}

// ClassifyRequest is the payload sent to the SLM classifier service.
type ClassifyRequest struct {
	Text       string `json:"text"`
	Role       string `json:"role,omitempty"`
	Provenance string `json:"provenance,omitempty"`
}

// ── Singleton ───────────────────────────────────────────────────────────────

var (
	globalConfig Config
	configOnce   sync.Once
	httpClient   *http.Client
)

// loadConfig reads SLM configuration from environment variables.
func loadConfig() Config {
	threshold := 0.85
	if v := os.Getenv("CICADA_SLM_THRESHOLD"); v != "" {
		if t, err := strconv.ParseFloat(v, 64); err == nil {
			threshold = t
		}
	}

	timeoutMs := 50
	if v := os.Getenv("CICADA_SLM_TIMEOUT_MS"); v != "" {
		if t, err := strconv.Atoi(v); err == nil {
			timeoutMs = t
		}
	}

	fallback := true
	if v := os.Getenv("CICADA_SLM_FALLBACK_ON_ERROR"); v != "" {
		fallback = strings.ToLower(v) != "false"
	}

	return Config{
		Enabled:         strings.ToLower(os.Getenv("CICADA_SLM_ENABLED")) == "true",
		Endpoint:        os.Getenv("CICADA_SLM_ENDPOINT"),
		Threshold:       threshold,
		TimeoutMs:       timeoutMs,
		FallbackOnError: fallback,
	}
}

func init() {
	configOnce.Do(func() {
		globalConfig = loadConfig()
		httpClient = &http.Client{
			Timeout: time.Duration(globalConfig.TimeoutMs) * time.Millisecond,
		}
		if globalConfig.Enabled {
			log.Printf("[SLM] Distilled classifier ENABLED — endpoint=%s threshold=%.2f timeout=%dms",
				globalConfig.Endpoint, globalConfig.Threshold, globalConfig.TimeoutMs)
		}
	})
}

// IsEnabled returns whether the SLM classifier is active.
func IsEnabled() bool {
	return globalConfig.Enabled && globalConfig.Endpoint != ""
}

// ── Classifier ──────────────────────────────────────────────────────────────

// Classify sends text to the SLM classifier and returns the result.
// If the SLM is disabled, unavailable, or times out, it returns a nil result
// (meaning: fall through to regex/DOM scanning).
//
// This function NEVER blocks the pipeline — it has a hard timeout and always
// returns within TimeoutMs + network overhead.
func Classify(text string, role string, provenance string) *ClassifyResult {
	if !IsEnabled() {
		return nil
	}

	// Don't classify system messages — they're developer-authored and trusted.
	if strings.ToLower(role) == "system" {
		return nil
	}

	// Truncate very long inputs — the SLM has a fixed context window.
	// DistilBERT-class models typically accept 512 tokens (~2000 chars).
	if len(text) > 4000 {
		text = text[:4000]
	}

	reqBody := ClassifyRequest{
		Text:       text,
		Role:       role,
		Provenance: provenance,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		log.Printf("[SLM] Failed to marshal request: %v", err)
		return fallbackResult()
	}

	req, err := http.NewRequest(http.MethodPost, globalConfig.Endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Printf("[SLM] Failed to create request: %v", err)
		return fallbackResult()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Cicada-SLM-Client/1.0")

	start := time.Now()
	resp, err := httpClient.Do(req)
	latency := time.Since(start)

	if err != nil {
		log.Printf("[SLM] Classifier unavailable (%.1fms): %v", float64(latency.Microseconds())/1000, err)
		return fallbackResult()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[SLM] Classifier returned HTTP %d (%.1fms)", resp.StatusCode, float64(latency.Microseconds())/1000)
		return fallbackResult()
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		log.Printf("[SLM] Failed to read response: %v", err)
		return fallbackResult()
	}

	var result ClassifyResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		log.Printf("[SLM] Failed to parse response: %v", err)
		return fallbackResult()
	}

	result.LatencyMs = float64(latency.Microseconds()) / 1000.0

	log.Printf("[SLM] Classified: score=%.3f label=%s latency=%.1fms model=%s",
		result.Score, result.Label, result.LatencyMs, result.ModelVersion)

	return &result
}

// ShouldBlock returns true if the SLM score exceeds the configured threshold.
func ShouldBlock(result *ClassifyResult) bool {
	if result == nil {
		return false
	}
	return result.Score >= globalConfig.Threshold
}

// GetThreshold returns the current SLM block threshold.
func GetThreshold() float64 {
	return globalConfig.Threshold
}

// ToFinding converts a blocking SLM result into a Finding-compatible format
// for inclusion in the injection scanner's output.
func ToFinding(result *ClassifyResult) map[string]string {
	if result == nil {
		return nil
	}
	return map[string]string{
		"pattern":  fmt.Sprintf("slm_classifier (score=%.3f, model=%s)", result.Score, result.ModelVersion),
		"severity": "critical",
		"excerpt":  fmt.Sprintf("SLM distilled classifier detected injection with %.1f%% confidence", result.Score*100),
	}
}

// fallbackResult returns nil (fall through to regex/DOM) or a blocking result
// depending on FallbackOnError config.
func fallbackResult() *ClassifyResult {
	if globalConfig.FallbackOnError {
		return nil // fall through — SLM is optional
	}
	// Fail closed: treat SLM errors as potential injection
	return &ClassifyResult{
		Score:        1.0,
		Label:        "error_fail_closed",
		ModelVersion: "unavailable",
	}
}
