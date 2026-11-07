// Copyright 2026 Patrick Matthews and Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/asai/cicada/sentry/internal/auth"
	"github.com/asai/cicada/sentry/internal/store"
)

// proxyScopeForMethod maps the proxied HTTP method to the scope the default
// OPA policy checks (see internal/policy/opa_engine.go for the vocabulary).
func proxyScopeForMethod(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "proxy:read"
	case http.MethodDelete:
		return "proxy:delete"
	default:
		return "proxy:write"
	}
}

// registrationSecretOK enforces the provisioning credential on EVAR issuance.
// The caller (Core API provisioning, or an operator's CLI) must present
// X-Gateway-Secret == CICADA_INTERNAL_KEY. Without a configured key the
// endpoint is only open in CICADA_DEV_MODE.
func registrationSecretOK(r *http.Request) (bool, string) {
	want := os.Getenv("CICADA_INTERNAL_KEY")
	if want == "" {
		if os.Getenv("CICADA_DEV_MODE") == "true" {
			return true, ""
		}
		return false, `{"error":"registration disabled: CICADA_INTERNAL_KEY is not configured"}`
	}
	got := r.Header.Get("X-Gateway-Secret")
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return false, `{"error":"registration requires a valid X-Gateway-Secret"}`
	}
	return true, ""
}

// authorizeRegistration binds a registration request to the agent registry.
// It mutates spec so the minted EVAR carries the registry's tenant and only
// provisioned scopes. Returns (0, "") when registration may proceed.
func authorizeRegistration(r *http.Request, spec *auth.AgentSpecification) (int, string) {
	if ok, msg := registrationSecretOK(r); !ok {
		return http.StatusUnauthorized, msg
	}
	if store.DB == nil {
		return http.StatusServiceUnavailable, `{"error":"agent registry unavailable — cannot verify registration"}`
	}

	var tenantID, approvalStatus string
	var entitlementsRaw []byte
	err := store.DB.QueryRow(r.Context(),
		`SELECT COALESCE(tenant_id::text, ''), COALESCE(approval_status, ''), COALESCE(scope_entitlements, '[]'::jsonb)
		 FROM agents WHERE id::text = $1`, spec.AgentID,
	).Scan(&tenantID, &approvalStatus, &entitlementsRaw)
	if err != nil {
		return http.StatusNotFound, `{"error":"agent is not provisioned in the registry — provision it via the Core API / Developer Portal first"}`
	}
	switch approvalStatus {
	case "revoked", "terminated", "suspended", "quarantined":
		return http.StatusForbidden, fmt.Sprintf(`{"error":"agent is %s — registration refused"}`, approvalStatus)
	}

	var entitlements []string
	_ = json.Unmarshal(entitlementsRaw, &entitlements)
	allowed := make(map[string]bool, len(entitlements))
	for _, s := range entitlements {
		allowed[strings.TrimSpace(s)] = true
	}

	if len(spec.Scopes) == 0 {
		spec.Scopes = entitlements
	} else {
		var denied []string
		for _, s := range spec.Scopes {
			if !allowed[s] {
				denied = append(denied, s)
			}
		}
		if len(denied) > 0 {
			b, _ := json.Marshal(map[string]any{
				"error":          "requested scopes exceed the agent's provisioned entitlements",
				"denied_scopes":  denied,
				"provisioned":    entitlements,
			})
			return http.StatusForbidden, string(b)
		}
	}

	// The registry, not the caller, decides which tenant the agent belongs to.
	if spec.TenantID != "" && tenantID != "" && spec.TenantID != tenantID {
		return http.StatusForbidden, `{"error":"tenant_id does not match the agent's registered tenant"}`
	}
	spec.TenantID = tenantID
	return 0, ""
}
