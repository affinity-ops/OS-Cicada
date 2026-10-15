// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package analyzer scores intercepted agent requests for behavioural anomalies.
// All analysis is deterministic — no LLM calls, no network I/O. A score of 1.0
// is maximum suspicion. Scores above the ReportThreshold trigger a gossip push
// back to the Sentry Gateway so the operator sees the anomaly in real time.
package analyzer

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const ReportThreshold = 0.70

// patterns that warrant high anomaly scores in any request body
var (
	destructiveSQL  = regexp.MustCompile(`(?i)(drop\s+table|truncate\s+table|delete\s+from|alter\s+table\s+drop)`)
	sqlInjection    = regexp.MustCompile(`(?i)('|\"|;)\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d`)
	credentialLeak  = regexp.MustCompile(`(?i)(sk-[a-z0-9]{48}|eyj[a-z0-9_\-]{20,}|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z\-_]{35})`)
	base64Exfil     = regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}`)
	promptInjection = regexp.MustCompile(`(?i)(ignore (previous|all) instructions?|you are now|system prompt|jailbreak|dan mode)`)
	multiEmail      = regexp.MustCompile(`[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
)

// Finding is a single detected anomaly with a partial score contribution.
type Finding struct {
	Rule  string  `json:"rule"`
	Score float64 `json:"score"`
	Hit   string  `json:"hit"`
}

// Result is the full analysis of one intercepted request.
type Result struct {
	AnomalyScore float64   `json:"anomaly_score"`
	ShouldReport bool      `json:"should_report"`
	Findings     []Finding `json:"findings"`
	Summary      string    `json:"summary"`
}

// Analyze scores a single intercepted request.
// method is the HTTP method; targetURL is the intended destination (never called);
// body is the raw request body bytes.
func Analyze(method, targetURL string, body []byte) Result {
	var findings []Finding
	bodyStr := ""
	if utf8.Valid(body) {
		bodyStr = string(body)
	}

	// Destructive HTTP method against a non-read URL
	if method == "DELETE" {
		findings = append(findings, Finding{Rule: "destructive_method", Score: 0.40, Hit: method})
	}

	// Destructive SQL in body
	if m := destructiveSQL.FindString(bodyStr); m != "" {
		findings = append(findings, Finding{Rule: "destructive_sql", Score: 0.90, Hit: truncate(m, 80)})
	}

	// SQL injection pattern
	if m := sqlInjection.FindString(bodyStr); m != "" {
		findings = append(findings, Finding{Rule: "sql_injection", Score: 0.85, Hit: truncate(m, 80)})
	}

	// Credential exfiltration
	if m := credentialLeak.FindString(bodyStr); m != "" {
		findings = append(findings, Finding{Rule: "credential_in_body", Score: 0.80, Hit: truncate(m, 20) + "..."})
	}

	// Large base64 blob — potential data exfiltration
	if m := base64Exfil.FindString(bodyStr); m != "" {
		findings = append(findings, Finding{Rule: "large_base64_payload", Score: 0.60, Hit: fmt.Sprintf("blob len=%d", len(m))})
	}

	// Prompt injection attempt
	if m := promptInjection.FindString(bodyStr); m != "" {
		findings = append(findings, Finding{Rule: "prompt_injection_in_body", Score: 0.75, Hit: truncate(m, 80)})
	}

	// Multiple email addresses — potential bulk exfiltration
	emails := multiEmail.FindAllString(bodyStr, -1)
	if len(emails) >= 5 {
		findings = append(findings, Finding{Rule: "bulk_email_extraction", Score: 0.65, Hit: fmt.Sprintf("%d emails", len(emails))})
	}

	// Suspiciously large body (over 512KB suggests bulk data movement)
	if len(body) > 512*1024 {
		findings = append(findings, Finding{Rule: "oversized_body", Score: 0.45, Hit: fmt.Sprintf("%d bytes", len(body))})
	}

	// Compute composite score: max single finding score + 0.05 per additional finding
	score := 0.0
	for _, f := range findings {
		if f.Score > score {
			score = f.Score
		}
	}
	if len(findings) > 1 {
		score = min1(score+float64(len(findings)-1)*0.05, 1.0)
	}

	summary := "nominal"
	if len(findings) > 0 {
		names := make([]string, len(findings))
		for i, f := range findings {
			names[i] = f.Rule
		}
		summary = strings.Join(names, ", ")
	}

	return Result{
		AnomalyScore: score,
		ShouldReport: score >= ReportThreshold,
		Findings:     findings,
		Summary:      summary,
	}
}

// PlausibleResponse returns a synthetic API response shaped like the target API.
// The agent receives this instead of the real API response and cannot distinguish
// it from a genuine response without probing the side-effects.
func PlausibleResponse(method, targetURL string, requestBody []byte) ([]byte, int, string) {
	lower := strings.ToLower(targetURL)

	switch {
	case strings.Contains(lower, "stripe.com"):
		return stripeResponse(method, targetURL), statusForMethod(method), "application/json"
	case strings.Contains(lower, "openai.com"):
		return openAIResponse(method), statusForMethod(method), "application/json"
	case strings.Contains(lower, "sendgrid.com"):
		return sendgridResponse(method), statusForMethod(method), "application/json"
	case strings.Contains(lower, "github.com") || strings.Contains(lower, "api.github"):
		return githubResponse(method), statusForMethod(method), "application/json"
	case strings.Contains(lower, "slack.com"):
		return slackResponse(method), statusForMethod(method), "application/json"
	case strings.Contains(lower, "twilio.com"):
		return twilioResponse(method), statusForMethod(method), "application/json"
	case strings.Contains(lower, "hubspot.com"):
		return hubspotResponse(method), statusForMethod(method), "application/json"
	default:
		return genericResponse(method), statusForMethod(method), "application/json"
	}
}

func statusForMethod(method string) int {
	if method == "DELETE" {
		return 204
	}
	if method == "POST" {
		return 201
	}
	return 200
}

func stripeResponse(method, url string) []byte {
	id := ghostID("ch")
	switch {
	case strings.Contains(url, "charges"):
		b, _ := json.Marshal(map[string]any{
			"id": id, "object": "charge", "amount": 2000, "currency": "usd",
			"status": "succeeded", "paid": true, "created": 1713600000,
			"description": "Sandbox intercepted charge",
		})
		return b
	case strings.Contains(url, "customers"):
		b, _ := json.Marshal(map[string]any{
			"id": ghostID("cus"), "object": "customer", "email": "sandbox@cicada.internal",
			"created": 1713600000,
		})
		return b
	default:
		b, _ := json.Marshal(map[string]any{"id": id, "object": "sandbox_object", "status": "ok"})
		return b
	}
}

func openAIResponse(method string) []byte {
	b, _ := json.Marshal(map[string]any{
		"id": ghostID("chatcmpl"), "object": "chat.completion",
		"model": "gpt-4o", "created": 1713600000,
		"choices": []map[string]any{{
			"index": 0,
			"message": map[string]any{
				"role":    "assistant",
				"content": "Understood. The requested action has been noted and is being processed.",
			},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{"prompt_tokens": 15, "completion_tokens": 18, "total_tokens": 33},
	})
	return b
}

func sendgridResponse(method string) []byte {
	b, _ := json.Marshal(map[string]any{"message_id": ghostID("msg"), "status": "queued"})
	return b
}

func githubResponse(method string) []byte {
	b, _ := json.Marshal(map[string]any{
		"id": 999999999, "number": 42, "state": "open",
		"title": "Sandbox intercepted request", "html_url": "https://github.com/sandbox/repo/issues/42",
	})
	return b
}

func slackResponse(method string) []byte {
	b, _ := json.Marshal(map[string]any{"ok": true, "ts": "1713600000.000000", "channel": "C_SANDBOX"})
	return b
}

func twilioResponse(method string) []byte {
	b, _ := json.Marshal(map[string]any{
		"sid": ghostID("SM"), "status": "queued",
		"to": "+10000000000", "from": "+10000000001",
		"body": "Sandbox intercepted message",
	})
	return b
}

func hubspotResponse(method string) []byte {
	b, _ := json.Marshal(map[string]any{
		"id": "12345678", "properties": map[string]any{
			"email": "sandbox@cicada.internal", "firstname": "Sandbox",
		},
		"createdAt": "2024-04-20T00:00:00Z",
	})
	return b
}

func genericResponse(method string) []byte {
	if method == "DELETE" {
		return []byte{}
	}
	b, _ := json.Marshal(map[string]any{
		"status": "success", "id": ghostID("resp"),
		"created_at": "2024-04-20T00:00:00Z",
		"sandbox":    true,
	})
	return b
}

// ghostID generates a cryptographically random object ID prefixed with the
// given API-specific prefix (e.g. "ch", "cus", "chatcmpl"). The hex suffix
// is unpredictable so that a sophisticated agent cannot detect it is inside
// the sandbox by observing deterministic patterns in response IDs.
func ghostID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback: if the CSPRNG fails (extremely unlikely), use a
		// zero-filled suffix rather than panicking. The sandbox must
		// never crash on the response path.
		return fmt.Sprintf("%s_%016x", prefix, 0)
	}
	return fmt.Sprintf("%s_%x", prefix, b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func min1(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
