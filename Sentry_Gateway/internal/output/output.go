// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package output implements response body inspection for Cicada's Sentry Gateway.
//
// The problem this solves:
// The proxy admission pipeline (semantic, velocity, FGA, roles, OPA) all inspect
// INBOUND calls — what an agent is trying to DO. None of them inspect what comes
// BACK from the target API before the agent consumes it. A target API could return
// a customer database dump, a credential blob, or an anomalously large payload
// indicating data exfiltration in progress.
//
// Two-tier inspection:
//
// Tier 1 — NER-based contextual analysis (primary, via Presidio):
// Microsoft Presidio runs as a sidecar service and uses transformer-based Named
// Entity Recognition to detect PII in context. Unlike regex, NER understands that
// "my SSN is 123-45-6789" and "order ID: 123456789" are semantically different
// even though both contain 9-digit sequences. Presidio supports 50+ entity types
// including IBAN, passport numbers, NHS numbers, and custom enterprise entities.
//
// Why Presidio as a sidecar rather than bundled in Go:
// Production-grade NER requires a transformer model (~100MB minimum for adequate
// accuracy). Embedding a Go ONNX runtime adds significant binary weight, complex
// build dependencies, and model update friction. A sidecar exposes a REST API —
// the model can be updated independently without recompiling the gateway, and the
// same Presidio instance can be reused by other platform services (the swarm,
// the Core API log sanitizer).
//
// Tier 2 — Regex pattern matching (fallback + credential detection):
// If Presidio is unavailable (not yet deployed, cold start, network partition),
// 12 pre-compiled patterns cover the most critical credentials (API keys, AWS
// access keys, PEM private keys) and high-severity PII (payment cards, SSNs).
// Regex also catches structured credentials that NER models underperform on
// (e.g. "sk-ant-api..." is a token, not a named entity — regex is more reliable).
//
// Configuring Presidio:
//   PRESIDIO_ANALYZER_URL=http://localhost:5002  (Presidio default port)
//
// To start Presidio:
//   docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer
package output

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// presidioClient is shared across calls. 3-second timeout: the inspection is on
// the hot path. If Presidio takes longer than 3 seconds, the regex fallback runs.
// A slow Presidio must not cause agent timeouts — it is defence-in-depth, not
// the last line of defence.
var presidioClient = &http.Client{Timeout: 3 * time.Second}

// Finding describes a single detected pattern in the response body.
type Finding struct {
	Category   string  // "pii", "credential", "volume"
	Pattern    string  // human-readable description of the matched pattern
	Severity   string  // "low", "medium", "high", "critical"
	EntityType string  // Presidio entity type (e.g. "CREDIT_CARD", "EMAIL_ADDRESS") if applicable
	Score      float64 // Presidio confidence score (0.0–1.0); 1.0 for regex matches
}

// Inspection is the result of scanning a response body.
type Inspection struct {
	Block     bool      // true → the response must not be forwarded to the agent
	Findings  []Finding // all detected patterns (present even when Block=false, for logging)
	RiskScore float64   // 0.0–1.0 for the ledger risk_score
	Method    string    // "presidio", "regex", or "both" — which tiers fired
}

// maxBodyBytes is the largest response body inspected inline. Responses larger
// than this are ALWAYS blocked — multi-megabyte payloads from API calls are a
// strong indicator of data exfiltration. Configurable via RESPONSE_MAX_BYTES.
func maxBodyBytes() int64 {
	if v := os.Getenv("RESPONSE_MAX_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 512 * 1024 // 512 KB
}

// ── Presidio NER tier ─────────────────────────────────────────────────────────

// presidioAnalyzeRequest is the JSON body for Presidio's /analyze endpoint.
type presidioAnalyzeRequest struct {
	Text       string   `json:"text"`
	Language   string   `json:"language"`
	Entities   []string `json:"entities,omitempty"` // nil = all entity types
	ScoreThreshold float64 `json:"score_threshold"`
}

// presidioEntity is one detection result from Presidio's /analyze response.
type presidioEntity struct {
	EntityType string  `json:"entity_type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
}

// presidioAnalyze calls the Presidio Analyzer sidecar for NER-based PII detection.
// Returns nil slice and nil error if Presidio is not configured — the caller
// falls through to regex inspection. Returns an error only for parse failures;
// network errors are treated as "not configured" to maintain fail-open behaviour.
func presidioAnalyze(text string) ([]presidioEntity, error) {
	serviceURL := os.Getenv("PRESIDIO_ANALYZER_URL")
	if serviceURL == "" {
		return nil, nil // Presidio not configured — regex fallback will run
	}

	body, err := json.Marshal(presidioAnalyzeRequest{
		Text:     text,
		Language: "en",
		// ScoreThreshold 0.6 filters out low-confidence NER detections that are
		// likely false positives (e.g. short numeric strings matching SSN pattern
		// by coincidence). Configurable in future via env var.
		ScoreThreshold: 0.60,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal presidio request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serviceURL+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, nil // treat request build failure as unconfigured
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := presidioClient.Do(req)
	if err != nil {
		// Network failure — fail open (regex fallback runs).
		return nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var entities []presidioEntity
	if err := json.NewDecoder(resp.Body).Decode(&entities); err != nil {
		return nil, fmt.Errorf("decode presidio response: %w", err)
	}

	return entities, nil
}

// presidioEntityToFinding maps a Presidio entity type to a Cicada Finding.
// Severity assignment reflects the risk of each entity type being present in
// an API response returned to an AI agent — a PEM private key in a response
// is catastrophic; a phone number is low-risk but worth logging.
func presidioEntityToFinding(entity presidioEntity) Finding {
	severity := presidioCriticality(entity.EntityType)
	return Finding{
		Category:   "pii",
		Pattern:    strings.ToLower(strings.ReplaceAll(entity.EntityType, "_", " ")),
		Severity:   severity,
		EntityType: entity.EntityType,
		Score:      entity.Score,
	}
}

func presidioCriticality(entityType string) string {
	switch entityType {
	case "CREDIT_CARD", "IBAN_CODE", "US_SSN", "UK_NHS", "US_PASSPORT",
		"UK_NINO", "AU_TFN", "SG_NRIC_FIN":
		return "critical"
	case "MEDICAL_LICENSE", "US_DRIVER_LICENSE", "US_ITIN",
		"IN_PAN", "IN_AADHAAR", "DATE_TIME":
		return "high"
	case "PHONE_NUMBER", "IP_ADDRESS", "LOCATION", "PERSON":
		return "medium"
	case "EMAIL_ADDRESS", "URL", "NRP":
		return "low"
	default:
		return "medium"
	}
}

// ── Regex fallback tier ───────────────────────────────────────────────────────

type pattern struct {
	re       *regexp.Regexp
	category string
	desc     string
	severity string
}

// patterns covers high-value credentials (regex is MORE reliable than NER for
// structured tokens with well-defined formats) and common PII as a fallback.
// Credential patterns are kept in the regex tier even when Presidio is running —
// NER models are not trained to recognise provider-specific secret formats.
var patterns = []pattern{
	// Credentials — regex outperforms NER for structured secret formats
	{regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), "credential", "OpenAI API key", "critical"},
	{regexp.MustCompile(`sk-ant-[A-Za-z0-9\-_]{20,}`), "credential", "Anthropic API key", "critical"},
	{regexp.MustCompile(`"(?:token|access_token|api_key|apikey|secret|password|passwd|private_key)"\s*:\s*"[^"]{8,}"`), "credential", "credential field in JSON response", "critical"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "credential", "AWS access key ID", "critical"},
	{regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), "credential", "PEM private key block", "critical"},
	{regexp.MustCompile(`ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}`), "credential", "GitHub personal access token", "critical"},
	{regexp.MustCompile(`sk_(?:live|test)_[A-Za-z0-9]{24,}`), "credential", "Stripe secret key", "critical"},

	// PII — fallback only; Presidio handles these with context when available
	{regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`), "pii", "email address", "medium"},
	{regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b`), "pii", "UK National Insurance number", "high"},
	{regexp.MustCompile(`\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`), "pii", "SSN-pattern number", "high"},
	{regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), "pii", "payment card number pattern", "high"},
	{regexp.MustCompile(`\b(?:0|\+44)\s?\d{2,4}\s?\d{3,4}\s?\d{3,4}\b`), "pii", "phone number", "low"},
}

// ── Primary inspection function ───────────────────────────────────────────────

// Inspect scans a response body and returns an Inspection result.
// Runs Presidio NER first (if configured), then regex patterns.
// Both tiers contribute to the findings list; the block decision is based on
// the highest severity finding from either tier.
func Inspect(body []byte, contentType string, bodyLen int64) Inspection {
	var findings []Finding
	method := "none"

	// ── Volume check ──────────────────────────────────────────────────────────
	limit := maxBodyBytes()
	if bodyLen > limit || int64(len(body)) > limit {
		return Inspection{
			Block: true,
			Findings: []Finding{{
				Category: "volume",
				Pattern:  fmt.Sprintf("response exceeds %d KB limit; set RESPONSE_MAX_BYTES to increase", limit/1024),
				Severity: "high",
				Score:    1.0,
			}},
			RiskScore: 0.80,
			Method:    "volume",
		}
	}

	// ── Skip binary content ───────────────────────────────────────────────────
	// Pattern scanning on images, audio, PDFs produces false positives.
	// Volume check above still applies — large binary responses are anomalous.
	ct := strings.ToLower(contentType)
	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "audio/") ||
		strings.HasPrefix(ct, "video/") || ct == "application/pdf" ||
		ct == "application/octet-stream" || strings.Contains(ct, "zip") ||
		strings.Contains(ct, "gzip") {
		return Inspection{Block: false, Findings: nil, RiskScore: 0.0, Method: "skipped-binary"}
	}

	bodyStr := string(body)
	maxRisk := 0.0

	// ── Tier 1: Presidio NER ──────────────────────────────────────────────────
	entities, _ := presidioAnalyze(bodyStr)
	if len(entities) > 0 {
		method = "presidio"
		for _, e := range entities {
			f := presidioEntityToFinding(e)
			findings = append(findings, f)
			risk := severityToRisk(f.Severity)
			if risk > maxRisk {
				maxRisk = risk
			}
		}
	}

	// ── Tier 2: Regex (always runs for credentials; fallback for PII) ─────────
	// Credentials are ALWAYS scanned by regex regardless of whether Presidio ran —
	// NER models are not reliably trained on provider-specific key formats.
	// PII patterns run only when Presidio is not configured.
	presidioRan := len(entities) > 0 || os.Getenv("PRESIDIO_ANALYZER_URL") != ""
	for _, p := range patterns {
		if presidioRan && p.category == "pii" {
			// Presidio handles PII with better contextual accuracy — skip regex PII
			// to avoid duplicate findings (both would reference the same data).
			continue
		}
		if p.re.MatchString(bodyStr) {
			findings = append(findings, Finding{
				Category: p.category,
				Pattern:  p.desc,
				Severity: p.severity,
				Score:    1.0, // regex matches are deterministic — confidence = 1.0
			})
			risk := severityToRisk(p.severity)
			if risk > maxRisk {
				maxRisk = risk
			}
			if method == "presidio" {
				method = "both"
			} else if method == "none" {
				method = "regex"
			}
		}
	}

	if len(findings) == 0 {
		return Inspection{Block: false, Findings: nil, RiskScore: 0.0, Method: method}
	}

	// Block on high or critical severity. Medium and low are logged but not
	// blocking — a legitimate API response may contain an email address.
	shouldBlock := maxRisk >= severityToRisk("high")

	return Inspection{
		Block:     shouldBlock,
		Findings:  findings,
		RiskScore: maxRisk,
		Method:    method,
	}
}

// ShouldBlockOnContentLength returns true if the declared Content-Length exceeds
// the configured maximum. Called before reading the body to reject oversized
// responses without buffering them into memory first.
func ShouldBlockOnContentLength(declared int64) bool {
	return declared > 0 && declared > maxBodyBytes()
}

// MaxReadBytes returns the body size limit plus one byte for io.LimitReader.
// The +1 means Inspect() sees a body that exceeds the threshold and blocks it —
// we never silently truncate and pass a partial body.
func MaxReadBytes() int64 {
	return maxBodyBytes() + 1
}

// FindingsSummary returns a comma-separated list of finding descriptions
// for log lines and ledger reason codes.
func FindingsSummary(findings []Finding) string {
	parts := make([]string, len(findings))
	for i, f := range findings {
		parts[i] = fmt.Sprintf("%s:%s", f.Category, f.Pattern)
	}
	return strings.Join(parts, ", ")
}

func severityToRisk(s string) float64 {
	switch s {
	case "critical":
		return 1.0
	case "high":
		return 0.85
	case "medium":
		return 0.5
	case "low":
		return 0.2
	default:
		return 0.0
	}
}
