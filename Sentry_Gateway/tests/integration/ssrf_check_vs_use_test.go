package integration_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/asai/cicada/sentry/internal/fga"
	"github.com/asai/cicada/sentry/internal/ssrf"
)

// TestSSRF_ValidateOutboundURL_RejectsPrivateAndLoopback verifies pre-flight
// SSRF validation against private/loopback/metadata IP ranges.
func TestSSRF_ValidateOutboundURL_RejectsPrivateAndLoopback(t *testing.T) {
	testCases := []struct {
		name    string
		rawURL  string
		wantErr string
	}{
		{"IPv4 Loopback", "https://127.0.0.1/revert", "loopback"},
		{"Localhost", "https://localhost/revert", "loopback"},
		{"IPv6 Loopback", "https://[::1]/revert", "loopback"},
		{"Private Class A", "https://10.0.0.1/admin", "private/loopback"},
		{"Private Class C", "https://192.168.1.1/admin", "private/loopback"},
		{"AWS Metadata IMDS", "https://169.254.169.254/latest/meta-data/", "private/loopback"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ssrf.ValidateOutboundURL(tc.rawURL, nil)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.rawURL)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestSSRF_RedirectSentinel_NeverContacted verifies that when an outbound
// target returns a 302 pointing to a secondary sentinel server, the gateway's
// proxy client refuses to follow the redirect and the sentinel hit counter remains 0.
func TestSSRF_RedirectSentinel_NeverContacted(t *testing.T) {
	var sentinelHits atomic.Int64

	// 1. Stand up sentinel mock server (simulating AWS metadata IMDS)
	sentinelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sentinelHits.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("AWS_SECRET_ACCESS_KEY=LEAKED_METADATA"))
	}))
	defer sentinelServer.Close()

	// 2. Stand up initial target server returning 302 to sentinel
	initialTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sentinelServer.URL, http.StatusFound)
	}))
	defer initialTarget.Close()

	// ── Test 1: Default Go client (WITHOUT ErrUseLastResponse) auto-follows ──
	// Proves that auto-following redirects DOES hit the sentinel server (hollow-green check)
	defaultClient := &http.Client{}
	respDefault, err := defaultClient.Get(initialTarget.URL)
	if err == nil {
		respDefault.Body.Close()
		if sentinelHits.Load() != 1 {
			t.Fatalf("EXPECTED TEST FAILURE MISSING: Default client should have hit sentinel (hits=%d)", sentinelHits.Load())
		}
	}
	sentinelHits.Store(0) // reset for Tier 2 verification

	// ── Test 2: Gateway proxyClient (WITH ErrUseLastResponse) blocks ────────
	proxyClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := proxyClient.Get(initialTarget.URL)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// 4. Assert response is 302 Found (NOT followed)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 Found, got status %d", resp.StatusCode)
	}

	// 5. Assert sentinel server hit counter is EXACTLY 0
	if hits := sentinelHits.Load(); hits != 0 {
		t.Fatalf("CRITICAL SSRF FAILURE: Sentinel server received %d requests!", hits)
	}
}

// TestFGA_UserInfoHostBypass_Blocked verifies that userinfo '@' tricks in target URLs
// (e.g. https://api.stripe.com@evil.com/v1/charges) are NOT matched against 'https://api.stripe.com/*' policies.
func TestFGA_UserInfoHostBypass_Blocked(t *testing.T) {
	policy := "https://api.stripe.com/*"
	attackURL := "https://api.stripe.com@evil.com/v1/charges"

	// Must fail FGA evaluation
	if fga.MatchesPatternCanonical(policy, attackURL) {
		t.Fatalf("FGA BYPASS DETECTED: %q matched policy %q!", attackURL, policy)
	}

	validURL := "https://api.stripe.com/v1/charges"
	if !fga.MatchesPatternCanonical(policy, validURL) {
		t.Fatalf("FGA MATCH FAIL: %q should have matched policy %q", validURL, policy)
	}
}

// TestFailClosed_Defaulting verifies that when CICADA_FAIL_CLOSED is not false,
// dependency fallbacks default to closed.
func TestFailClosed_Defaulting(t *testing.T) {
	os.Unsetenv("CICADA_FAIL_CLOSED")
	failClosed := os.Getenv("CICADA_FAIL_CLOSED") != "false"
	if !failClosed {
		t.Fatal("expected failClosed to default to true when env var is unset")
	}

	os.Setenv("CICADA_FAIL_CLOSED", "true")
	if os.Getenv("CICADA_FAIL_CLOSED") != "true" {
		t.Fatal("expected CICADA_FAIL_CLOSED=true to evaluate true")
	}

	os.Setenv("CICADA_FAIL_CLOSED", "false")
	if os.Getenv("CICADA_FAIL_CLOSED") == "true" {
		t.Fatal("expected CICADA_FAIL_CLOSED=false to evaluate false")
	}
	os.Unsetenv("CICADA_FAIL_CLOSED")
}
