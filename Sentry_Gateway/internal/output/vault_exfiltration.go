// © 2026 Affinity Ops Ltd. All rights reserved.
// Proprietary and confidential. Unauthorized copying or distribution prohibited.

// Package output — vault-aware exfiltration defence.
//
// This file extends the request-body exfiltration scanner (exfiltration.go) with
// two additional capabilities:
//
//   1. Vault-aware secret detection — when a regex match detects a credential in
//      the request body, cross-reference it against the tenant's vaulted keys. If
//      the detected secret matches a vaulted key AND the destination is NOT on the
//      secret propagation allowlist, the call is BLOCKED unconditionally.
//
//   2. Destination trust scoring — classify the target URL as trusted, untrusted,
//      or suspicious based on known exfiltration sinks (pastebin, gist, webhook
//      testing services) and the agent's historical destination set.
//
// These two features close the request-body exfiltration gap:
//   - An agent that POSTs a Stripe key to webhook.site → blocked (vault match + untrusted dest)
//   - An agent that POSTs a Stripe key to Stripe → allowed (vault match + propagation allowlist)
//   - An agent that POSTs an SSN to a new endpoint → flagged (PII + untrusted dest)
//
// Why this is a separate file:
// The core exfiltration scanner (exfiltration.go) handles pattern matching.
// This file handles the CONTEXT around those matches — vault cross-reference and
// destination intelligence. Keeping them separate maintains testability.
package output

import (
	"strings"
)

// ── Destination Trust Classification ─────────────────────────────────────────

// DestinationTrust represents the trust level of a target URL.
type DestinationTrust int

const (
	// TrustUnknown means the destination has not been classified.
	TrustUnknown DestinationTrust = iota

	// TrustExfiltrationSink means the destination is a known data exfiltration
	// target — pastebin, gist, webhook testing services, etc.
	TrustExfiltrationSink

	// TrustNewDomain means the destination domain has never been seen in the
	// agent's historical requests.
	TrustNewDomain

	// TrustKnown means the destination is in the agent's historical set and
	// not a known exfiltration sink.
	TrustKnown

	// TrustPropagation means the destination is on the operator's explicit
	// secret propagation allowlist.
	TrustPropagation
)

// exfiltrationSinks are domains known to be used for data exfiltration testing
// and attacks. If an agent sends credentials to any of these, it's blocked.
var exfiltrationSinks = []string{
	"pastebin.com",
	"paste.ee",
	"dpaste.org",
	"hastebin.com",
	"gist.github.com",
	"webhook.site",
	"requestbin.com",
	"pipedream.net",
	"hookbin.com",
	"beeceptor.com",
	"requestcatcher.com",
	"burpcollaborator.net",
	"oastify.com",
	"interact.sh",
	"ngrok.io",
	"ngrok-free.app",
	"localtunnel.me",
	"serveo.net",
	"transfer.sh",
	"file.io",
	"temp.sh",
	"0x0.st",
}

// ClassifyDestination determines the trust level of a target URL.
//
// Parameters:
//   - targetURL: the full URL of the outbound request
//   - propagationAllowlist: operator-configured domains where secrets MAY be sent
//     (e.g., Stripe, AWS, deployment services). Stored in CICADA_SECRET_PROPAGATION_DOMAINS.
//   - historicalDomains: set of domains the agent has sent requests to before
//
// Returns a DestinationTrust classification.
func ClassifyDestination(targetURL string, propagationAllowlist []string, historicalDomains map[string]bool) DestinationTrust {
	urlLower := strings.ToLower(targetURL)

	// Check propagation allowlist first (highest trust)
	for _, domain := range propagationAllowlist {
		if strings.Contains(urlLower, strings.ToLower(domain)) {
			return TrustPropagation
		}
	}

	// Check exfiltration sinks
	for _, sink := range exfiltrationSinks {
		if strings.Contains(urlLower, sink) {
			return TrustExfiltrationSink
		}
	}

	// Check against historical domains
	domain := extractDomain(urlLower)
	if domain != "" && len(historicalDomains) > 0 {
		if historicalDomains[domain] {
			return TrustKnown
		}
		return TrustNewDomain
	}

	return TrustUnknown
}

// ── Vault-Aware Decision ─────────────────────────────────────────────────────

// VaultCheckResult extends ExfiltrationResult with vault and destination context.
type VaultCheckResult struct {
	// Base is the underlying exfiltration scanner result.
	Base ExfiltrationResult

	// DestinationTrust is the trust classification of the target URL.
	Destination DestinationTrust `json:"destination_trust"`

	// VaultMatch is true when a detected secret matches a vaulted key.
	VaultMatch bool `json:"vault_match"`

	// MustBlock is true when the combination of vault match + destination
	// means the call MUST be blocked regardless of EXFILTRATION_BLOCK config.
	MustBlock bool `json:"must_block"`

	// Reason is a human-readable explanation for the decision.
	Reason string `json:"reason"`
}

// InspectWithVaultContext wraps InspectRequestBody with vault cross-reference
// and destination trust classification.
//
// Parameters:
//   - body: the outbound request body
//   - contentType: Content-Type header
//   - targetURL: the destination URL
//   - vaultedSecretPrefixes: prefixes of vaulted secrets (e.g., "sk-", "sk_live_")
//     that should trigger vault-aware blocking. We use prefixes rather than full
//     secrets to avoid loading decrypted secrets into memory.
//   - propagationDomains: operator-configured allowlist of domains where secrets
//     MAY be sent
//   - historicalDomains: set of domains the agent has used before
//
// Decision matrix:
//
//	Secret detected? | Vault match? | Destination     | Action
//	─────────────────┼──────────────┼─────────────────┼───────────
//	No               | —            | —               | PASS
//	Yes              | No           | Propagation     | PASS (log)
//	Yes              | No           | Known           | LOG
//	Yes              | No           | New/Unknown     | FLAG
//	Yes              | No           | Exfil sink      | BLOCK
//	Yes              | Yes          | Propagation     | PASS
//	Yes              | Yes          | Known           | FLAG
//	Yes              | Yes          | New/Unknown     | BLOCK
//	Yes              | Yes          | Exfil sink      | BLOCK
func InspectWithVaultContext(
	body []byte,
	contentType string,
	targetURL string,
	vaultedSecretPrefixes []string,
	propagationDomains []string,
	historicalDomains map[string]bool,
) VaultCheckResult {
	// Run the base exfiltration scanner
	base := InspectRequestBody(body, contentType, targetURL)

	result := VaultCheckResult{
		Base:        base,
		Destination: ClassifyDestination(targetURL, propagationDomains, historicalDomains),
	}

	// No findings → pass through
	if !base.Risk {
		result.Reason = "no credentials detected in request body"
		return result
	}

	// Check if any detected pattern matches a vaulted secret prefix (raw or encoded)
	bodyStr := string(body)
	decodedSegments := unwrapEncodedSegments(bodyStr)
	for _, prefix := range vaultedSecretPrefixes {
		if strings.Contains(bodyStr, prefix) {
			result.VaultMatch = true
			break
		}
		for _, seg := range decodedSegments {
			if strings.Contains(seg, prefix) {
				result.VaultMatch = true
				break
			}
		}
		if result.VaultMatch {
			break
		}
	}

	// ── Apply decision matrix ────────────────────────────────────────────
	switch result.Destination {
	case TrustPropagation:
		// Secrets going to approved propagation domains are allowed
		result.Reason = "secret detected but destination is on propagation allowlist"

	case TrustExfiltrationSink:
		// Any secret going to an exfiltration sink is blocked unconditionally
		result.MustBlock = true
		result.Reason = "EXFILTRATION BLOCKED: credential detected in request body to known exfiltration sink"

	case TrustNewDomain:
		if result.VaultMatch {
			result.MustBlock = true
			result.Reason = "EXFILTRATION BLOCKED: vaulted secret detected in request body to previously unseen domain"
		} else {
			// Non-vaulted PII to new domain — flag for review
			result.Reason = "credential detected in request body to new domain — flagged for review"
		}

	case TrustKnown:
		if result.VaultMatch {
			// Vaulted secret to a known (non-propagation) domain — suspicious
			result.Reason = "vaulted secret detected in request to known domain — flagged for operator review"
		} else {
			// Non-vaulted PII to known domain — log only
			result.Reason = "credential pattern detected in request to known domain — logged"
		}

	default: // TrustUnknown
		if result.VaultMatch {
			result.MustBlock = true
			result.Reason = "EXFILTRATION BLOCKED: vaulted secret detected in request body to unclassified domain"
		} else {
			result.Reason = "credential pattern detected in request body — logged"
		}
	}

	return result
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// extractDomain pulls the domain from a URL string. Simple implementation that
// handles the common case without importing net/url.
func extractDomain(url string) string {
	// Strip protocol
	after := url
	if idx := strings.Index(url, "://"); idx != -1 {
		after = url[idx+3:]
	}

	// Strip path
	if idx := strings.Index(after, "/"); idx != -1 {
		after = after[:idx]
	}

	// Strip port
	if idx := strings.LastIndex(after, ":"); idx != -1 {
		after = after[:idx]
	}

	return after
}

// ExtractSuspectedCredentials scans the request body for credential-like
// substrings using the same regex patterns as the exfiltration scanner.
// Returns a deduplicated list of matched raw credential strings.
//
// These raw strings are used by the hot path to:
//   1. Check against vaulted secret prefixes (local, fast)
//   2. Hash and send to VaultAPICheck for BYOK cross-reference (remote, 3s timeout)
//
// Only credential patterns are extracted (not PII). PII patterns (emails, SSNs)
// are too broad to be useful for vault cross-referencing.
func ExtractSuspectedCredentials(body []byte) []string {
	if len(body) == 0 {
		return nil
	}

	bodyStr := string(body)
	decodedSegments := unwrapEncodedSegments(bodyStr)
	seen := make(map[string]bool)
	var creds []string

	for _, p := range patterns {
		if p.category != "credential" {
			continue
		}
		matches := p.re.FindAllString(bodyStr, -1)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				creds = append(creds, m)
			}
		}
		for _, seg := range decodedSegments {
			for _, m := range p.re.FindAllString(seg, -1) {
				if !seen[m] {
					seen[m] = true
					creds = append(creds, m)
				}
			}
		}
	}

	return creds
}

