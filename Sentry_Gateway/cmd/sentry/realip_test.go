// Copyright 2026 Patrick Matthews and Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedRealIP(t *testing.T) {
	seen := ""
	h := func(w http.ResponseWriter, r *http.Request) { seen = r.RemoteAddr }

	cases := []struct {
		name, trusted, peer, xri, xff, want string
	}{
		{"untrusted peer cannot spoof loopback via X-Real-IP", "", "203.0.113.9:5555", "127.0.0.1", "", "203.0.113.9:5555"},
		{"untrusted peer cannot spoof via X-Forwarded-For", "", "203.0.113.9:5555", "", "127.0.0.1", "203.0.113.9:5555"},
		{"peer not in trusted list is ignored", "10.0.0.0/8", "203.0.113.9:5555", "127.0.0.1", "", "203.0.113.9:5555"},
		{"trusted proxy forwards real client", "10.0.0.0/8", "10.1.2.3:443", "", "198.51.100.7", "198.51.100.7:0"},
		{"client-injected XFF hop left of proxy is skipped correctly", "10.0.0.0/8", "10.1.2.3:443", "", "127.0.0.1, 198.51.100.7", "198.51.100.7:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CICADA_TRUSTED_PROXIES", tc.trusted)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.peer
			if tc.xri != "" {
				req.Header.Set("X-Real-IP", tc.xri)
			}
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			trustedRealIP(http.HandlerFunc(h)).ServeHTTP(httptest.NewRecorder(), req)
			if seen != tc.want {
				t.Fatalf("RemoteAddr = %q, want %q", seen, tc.want)
			}
		})
	}
}
