// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package scrub implements the Deterministic State Sieve — the output
// scrubbing engine that strips secrets, state maps, and private IPs
// from execution output before it reaches the agent's reasoning context.
//
// Source: EPHEMERAL_AGENT_KERNEL_FIREWALL.md §5, lines 188–210.
package scrub

import (
	"regexp"
	"strings"
)

// Result contains the scrubbed output and telemetry about what was redacted.
type Result struct {
	Output      string
	RedactedKeys []string
	RedactedIPs  []string
}

// redactionTag is the replacement string for any detected secret or credential.
const redactionTag = "[REDACTED_BY_EAKF]"

// ── Credential Patterns ──────────────────────────────────────────────────────
// Source: §5, line 195 — "Regex sweep of AKIA / ASCA prefixes."

var credentialPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	// AWS Access Key IDs (AKIA*, ASIA* for temporary STS credentials)
	{"aws_access_key", regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`)},
	// AWS Secret Access Keys (40-char base64)
	{"aws_secret_key", regexp.MustCompile(`(?i)(?:aws_secret_access_key|secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?`)},
	// Generic API keys (Bearer tokens, API key headers)
	{"bearer_token", regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`)},
	// Database connection strings (postgresql://, mysql://, mongodb://)
	{"database_uri", regexp.MustCompile(`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s"']+`)},
	// Generic password assignments
	{"password_assignment", regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*["']?[^\s"']{4,}["']?`)},
	// GitHub/GitLab tokens
	{"github_token", regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`)},
	{"gitlab_token", regexp.MustCompile(`glpat-[A-Za-z0-9\-]{20,}`)},
	// Terraform state file content markers
	{"tfstate_marker", regexp.MustCompile(`(?i)"type"\s*:\s*"(?:aws_|azurerm_|google_)[^"]+"\s*,\s*"primary"`)},
	// Environment variable exports with sensitive values
	{"env_export", regexp.MustCompile(`(?i)export\s+(?:AWS_SECRET|DATABASE_URL|DB_PASSWORD|API_KEY|SECRET_KEY|PRIVATE_KEY)\s*=\s*["']?[^\s"']+["']?`)},
	// SSH private key blocks
	{"ssh_private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	// PEM certificate private keys
	{"pem_private_key", regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`)},
}

// ── Private IP Patterns ──────────────────────────────────────────────────────
// Source: §5, line 196 — "Strip all private IP ranges (10.x.x.x, 172.16.x.x, 192.168.x.x)."

var privateIPPattern = regexp.MustCompile(
	`\b(?:` +
		`10\.\d{1,3}\.\d{1,3}\.\d{1,3}` + // 10.0.0.0/8
		`|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}` + // 172.16.0.0/12
		`|192\.168\.\d{1,3}\.\d{1,3}` + // 192.168.0.0/16
		`|169\.254\.\d{1,3}\.\d{1,3}` + // 169.254.0.0/16 (link-local, AWS IMDS)
		`)\b`,
)

// ── Terraform State Scrubbing ────────────────────────────────────────────────
// Source: §5, line 194 — "Redact entire JSON object structure. Extract only
// resource creation count metrics."

var tfstateBlockPattern = regexp.MustCompile(`(?s)\{[^{}]*"type"\s*:\s*"(?:aws_|azurerm_|google_)[^"]*"[^{}]*\}`)
var tfResourceCountPattern = regexp.MustCompile(`(?i)(\d+)\s+(?:added|created|changed|destroyed)`)

// Scrub applies the Deterministic State Sieve to raw execution output.
// It processes the text in three passes:
//   1. Credential and secret pattern matching → replacement with [REDACTED_BY_EAKF]
//   2. Private IP address stripping → replacement with [PRIVATE_IP_REDACTED]
//   3. Terraform state block scrubbing → replacement with resource count summary
//
// Returns the scrubbed text and telemetry of what was redacted.
func Scrub(raw string) Result {
	result := Result{
		Output:       raw,
		RedactedKeys: []string{},
		RedactedIPs:  []string{},
	}

	// Pass 1: Credentials and secrets
	for _, cp := range credentialPatterns {
		matches := cp.Pattern.FindAllString(result.Output, -1)
		if len(matches) > 0 {
			for _, m := range matches {
				// Truncate match to first 8 chars for telemetry (don't log the full secret)
				truncated := m
				if len(truncated) > 8 {
					truncated = truncated[:8] + "***"
				}
				result.RedactedKeys = append(result.RedactedKeys, cp.Name+":"+truncated)
			}
			result.Output = cp.Pattern.ReplaceAllString(result.Output, redactionTag)
		}
	}

	// Pass 2: Private IPs
	ips := privateIPPattern.FindAllString(result.Output, -1)
	if len(ips) > 0 {
		// Deduplicate
		seen := make(map[string]bool)
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				result.RedactedIPs = append(result.RedactedIPs, ip)
			}
		}
		result.Output = privateIPPattern.ReplaceAllString(result.Output, "[PRIVATE_IP_REDACTED]")
	}

	// Pass 3: Terraform state blocks
	if tfstateBlockPattern.MatchString(result.Output) {
		// Extract resource counts before scrubbing
		counts := tfResourceCountPattern.FindAllString(result.Output, -1)
		summary := "terraform state redacted"
		if len(counts) > 0 {
			summary = "terraform state redacted (metrics: " + strings.Join(counts, ", ") + ")"
		}
		result.Output = tfstateBlockPattern.ReplaceAllString(result.Output, "[TFSTATE_REDACTED: "+summary+"]")
		result.RedactedKeys = append(result.RedactedKeys, "tfstate_block")
	}

	return result
}
