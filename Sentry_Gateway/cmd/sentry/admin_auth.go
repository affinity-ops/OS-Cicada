// Copyright 2026 Patrick Matthews and Patrick Matthews (Affinity Ops / Affinity Smart AI)
// SPDX-License-Identifier: Apache-2.0

package main

// Authentication for gateway admin / operator routes.
//
// An unauthenticated sweep of every route (scripts/route_probe in the audit)
// found these doing real work for anonymous callers: federation identity
// providers and role mappings (could grant admin via SSO), credential
// rotation, saga rollback, shadow-agent status changes, device inventory,
// sandbox anomaly reports, and test push notifications.

import (
	"crypto/subtle"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/asai/cicada/sentry/internal/mobile"
)

func internalKeyOK(r *http.Request) bool {
	want := os.Getenv("CICADA_INTERNAL_KEY")
	got := r.Header.Get("X-Gateway-Secret")
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func operatorKeyOK(r *http.Request) bool {
	want := os.Getenv("CICADA_OPERATOR_KEY")
	got := r.Header.Get("X-Operator-Secret")
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// devLoopbackOK allows a single local developer setup to work with no secrets
// configured. RemoteAddr is trustworthy here because trustedRealIP no longer
// lets clients rewrite it.
func devLoopbackOK(r *http.Request) bool {
	if os.Getenv("CICADA_DEV_MODE") != "true" || os.Getenv("CICADA_INTERNAL_KEY") != "" || os.Getenv("CICADA_OPERATOR_KEY") != "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func deny(w http.ResponseWriter, r *http.Request, why string) {
	log.Printf("[ADMIN-AUTH] denied %s %s from %s: %s", r.Method, r.URL.Path, r.RemoteAddr, why)
	writeError(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
}

// requireService admits only service-to-service or operator callers (Core API,
// Shadow Sandbox, or dedicated operator credential) presenting
// X-Gateway-Secret == CICADA_INTERNAL_KEY or X-Operator-Secret == CICADA_OPERATOR_KEY.
func requireService(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if internalKeyOK(r) || operatorKeyOK(r) || devLoopbackOK(r) {
			next.ServeHTTP(w, r)
			return
		}
		deny(w, r, "no valid X-Gateway-Secret or X-Operator-Secret")
	})
}

// requireServiceOrPortal admits service/operator callers, or portal users with a
// valid session token. For portal users the tenant is pinned to the session:
// X-Cicada-Tenant-ID is overwritten so a user cannot act on another tenant.
func requireServiceOrPortal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if internalKeyOK(r) || operatorKeyOK(r) || devLoopbackOK(r) {
			next.ServeHTTP(w, r)
			return
		}
		tenantID, err := mobile.AuthenticatePortalRequest(r)
		if err != nil || tenantID == "" {
			deny(w, r, "no valid service/operator key or portal session")
			return
		}
		r.Header.Set("X-Cicada-Tenant-ID", tenantID)
		next.ServeHTTP(w, r)
	})
}
