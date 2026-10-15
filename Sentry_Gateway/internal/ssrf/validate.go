// © 2026 Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package ssrf provides a shared outbound-URL validation function used by
// every Gateway component that fires HTTP requests to operator-configured or
// agent-declared destinations.
//
// Call sites:
//   - rotation.sendWebhook()         — EVAR rotation notification webhooks
//   - handleAgentRollback()          — saga compensating transaction revert routes
//   - saga worker                    — automated compensating DELETE on CIBA deny
//
// The validator enforces:
//   1. HTTPS scheme required (HTTP rejected)
//   2. Loopback addresses blocked (localhost, 127.0.0.1, ::1, 0.0.0.0)
//   3. DNS resolution — all resolved IPs checked against private/link-local ranges
//   4. Domain allowlist — if provided, the host must also appear in the allowlist
//
// The domain allowlist is an ADDITIONAL restriction, not a bypass. A URL must
// pass BOTH the allowlist check (if an allowlist is provided) AND the
// private-IP/loopback check. This prevents the "allowlist evil.com, point DNS
// at 169.254.169.254" attack.
package ssrf

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateOutboundURL checks whether a URL is safe for the Gateway to issue
// an outbound HTTP request to. Returns nil if the URL passes all checks,
// or a descriptive error explaining which check failed.
//
// Parameters:
//   - rawURL:         the destination URL to validate
//   - allowedDomains: optional domain allowlist. If non-empty, the URL's host
//     must match at least one entry (suffix match). Pass nil
//     to skip the allowlist check (used when the destination
//     is already operator-controlled, e.g., saga_revert_route
//     stored in the agents table).
func ValidateOutboundURL(rawURL string, allowedDomains []string) error {
	// ── 1. Parse URL ────────────────────────────────────────────────────
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}

	// ── 2. Scheme check — HTTPS only ────────────────────────────────────
	if parsed.Scheme != "https" {
		return fmt.Errorf("non-HTTPS scheme %q in URL %q — only HTTPS is permitted for outbound requests", parsed.Scheme, rawURL)
	}

	// ── 3. Domain allowlist (additional restriction, not a bypass) ──────
	if len(allowedDomains) > 0 {
		host := parsed.Hostname()
		domainAllowed := false
		for _, domain := range allowedDomains {
			if strings.HasSuffix(host, domain) {
				domainAllowed = true
				break
			}
		}
		if !domainAllowed {
			return fmt.Errorf("host %q not in domain allowlist", host)
		}
	}

	// ── 4. Loopback hostname & IP literal check ─────────────────────────
	host := parsed.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
		return fmt.Errorf("loopback address %q blocked — outbound requests to loopback are not permitted", host)
	}
	if literalIP := net.ParseIP(host); literalIP != nil {
		if literalIP.IsLoopback() || literalIP.IsPrivate() || literalIP.IsLinkLocalUnicast() || literalIP.IsLinkLocalMulticast() || literalIP.IsUnspecified() {
			return fmt.Errorf("host %q resolves to private/loopback IP %s — blocked", host, host)
		}
		return nil
	}

	// ── 5. DNS resolution + private IP check ────────────────────────────
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("DNS resolution failed for %q: %w", host, err)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("host %q resolves to private/loopback IP %s — blocked", host, ipStr)
		}
	}

	return nil
}
