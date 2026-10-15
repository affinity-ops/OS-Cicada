// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package ssrf

import (
	"strings"
	"testing"
)

func TestValidateOutboundURL_RejectsHTTP(t *testing.T) {
	err := ValidateOutboundURL("http://example.com/webhook", nil)
	if err == nil {
		t.Fatal("expected error for HTTP URL, got nil")
	}
	if !strings.Contains(err.Error(), "non-HTTPS") {
		t.Fatalf("expected non-HTTPS error, got: %v", err)
	}
}

func TestValidateOutboundURL_RejectsLocalhost(t *testing.T) {
	// IPv6 addresses in URLs must be bracketed: https://[::1]/path
	testCases := map[string]string{
		"localhost": "https://localhost/revert",
		"127.0.0.1": "https://127.0.0.1/revert",
		"::1":       "https://[::1]/revert",
		"0.0.0.0":   "https://0.0.0.0/revert",
	}
	for host, url := range testCases {
		err := ValidateOutboundURL(url, nil)
		if err == nil {
			t.Fatalf("expected error for loopback %q, got nil", host)
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("expected loopback error for %q, got: %v", host, err)
		}
	}
}

func TestValidateOutboundURL_RejectsPrivateIP(t *testing.T) {
	// 192.168.x.x resolves to private — if the host IS a private IP literal
	// in the URL, DNS resolution will return that IP and IsPrivate() catches it.
	err := ValidateOutboundURL("https://192.168.1.1/revert", nil)
	if err == nil {
		t.Fatal("expected error for private IP, got nil")
	}
	if !strings.Contains(err.Error(), "private") {
		t.Fatalf("expected private IP error, got: %v", err)
	}
}

func TestValidateOutboundURL_RejectsDomainNotInAllowlist(t *testing.T) {
	err := ValidateOutboundURL("https://evil.com/revert", []string{"enterprise.internal"})
	if err == nil {
		t.Fatal("expected error for domain not in allowlist, got nil")
	}
	if !strings.Contains(err.Error(), "not in domain allowlist") {
		t.Fatalf("expected allowlist error, got: %v", err)
	}
}

func TestValidateOutboundURL_AcceptsDomainInAllowlist(t *testing.T) {
	// This will likely fail DNS resolution for a fake domain, which is the
	// expected behavior — the allowlist is not a bypass for DNS/IP checks.
	err := ValidateOutboundURL("https://api.enterprise.internal/revert", []string{"enterprise.internal"})
	// The domain IS in the allowlist, but DNS resolution will fail because
	// enterprise.internal doesn't exist. This is correct — both checks must pass.
	if err == nil {
		// If no error, the domain both resolved AND was in the allowlist — fine.
		return
	}
	// Expected: DNS resolution fails for fake domain
	if !strings.Contains(err.Error(), "DNS resolution failed") {
		t.Fatalf("expected DNS resolution error, got: %v", err)
	}
}

func TestValidateOutboundURL_NoAllowlistSkipsCheck(t *testing.T) {
	// With nil allowlist, any domain is accepted (allowlist check skipped).
	// The URL still needs to pass HTTPS + DNS + private-IP checks.
	err := ValidateOutboundURL("https://example.com/webhook", nil)
	// example.com resolves to 93.184.216.34 — a public IP. Should pass.
	if err != nil {
		t.Fatalf("expected nil error for valid public HTTPS URL with no allowlist, got: %v", err)
	}
}

func TestValidateOutboundURL_RejectsInvalidURL(t *testing.T) {
	err := ValidateOutboundURL("://not-a-url", nil)
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}
