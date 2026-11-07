// Copyright 2026 Patrick Matthews and Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// trustedRealIP replaces chi's middleware.RealIP, which rewrote r.RemoteAddr
// from X-Real-IP / X-Forwarded-For for EVERY request. That let any client send
// "X-Real-IP: 127.0.0.1" and pass the loopback-only checks on /v1/gossip/receive,
// /v1/mcp and /v1/aegis/mcp/execute.
//
// Forwarding headers are now honoured only when the direct TCP peer is listed
// in CICADA_TRUSTED_PROXIES (comma-separated IPs or CIDRs, e.g.
// "10.0.0.0/8,192.168.1.10"). With the variable unset, headers are ignored and
// RemoteAddr is always the real socket peer.
func trustedRealIP(next http.Handler) http.Handler {
	trusted := parseTrustedProxies(os.Getenv("CICADA_TRUSTED_PROXIES"))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(trusted) > 0 {
			peer, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				peer = r.RemoteAddr
			}
			if ip := net.ParseIP(peer); ip != nil && ipInNets(ip, trusted) {
				if fwd := clientIPFromHeaders(r, trusted); fwd != "" {
					r.RemoteAddr = net.JoinHostPort(fwd, "0")
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func parseTrustedProxies(raw string) []*net.IPNet {
	var out []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				part = part + "/" + itoa(bits)
			}
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 128 {
		return "128"
	}
	return "32"
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIPFromHeaders walks X-Forwarded-For from the right, skipping trusted
// proxies, and returns the first untrusted hop (the real client). Falls back to
// X-Real-IP.
func clientIPFromHeaders(r *http.Request, trusted []*net.IPNet) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		hops := strings.Split(xff, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			h := strings.TrimSpace(hops[i])
			ip := net.ParseIP(h)
			if ip == nil {
				return ""
			}
			if !ipInNets(ip, trusted) {
				return ip.String()
			}
		}
	}
	if xr := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); xr != nil {
		return xr.String()
	}
	return ""
}
