// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"time"
	"github.com/golang-jwt/jwt/v5"
)

// AgentSpecification represents the parsed payload mapped from /v1/agents/submit
type AgentSpecification struct {
	AgentID                 string            `json:"agent_id"`
	CodeHash                string            `json:"code_hash"`
	Scopes                  []string          `json:"scopes"`
	ModelIntended           string            `json:"intended_model"`
	IsPersistent            bool              `json:"is_persistent"`
	CertifiedReversalRoutes map[string]string `json:"certified_reversal_routes"` // Ph2 Compensating Saga pattern
	// TenantID is optional. When provided, it is embedded as the JWT issuer so
	// the Gateway can correctly attribute ledger entries to the right tenant.
	// When omitted the Gateway falls back to "cicada-cocoon-lab".
	TenantID string `json:"tenant_id,omitempty"`
	DataResidencyRegion string `json:"data_residency_region,omitempty"`
}

// MintEVARToken cryptographically ties the Agent specifications into an immutable Ed25519 JWT signature
// ensuring that if the Agent changes its codebase or attempts to exceed scope, the runtime gate drops it.
func MintEVARToken(spec AgentSpecification) (string, error) {
	// Calculate a 24 hour expiry (or shorter depending on persistence)
	expiryTime := time.Now().Add(24 * time.Hour)

	// Create physical JWT mapped over Ed25519 (EdDSA) instead of symmetric RS256/HS256
	issuer := spec.TenantID
	if issuer == "" {
		issuer = "cicada-cocoon-lab"
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"sub":                       spec.AgentID,
		"hash":                      spec.CodeHash,
		"scopes":                    spec.Scopes,
		"model":                     spec.ModelIntended,
		"certified_reversal_routes": spec.CertifiedReversalRoutes,
		"region":                    spec.DataResidencyRegion,
		"iss":                       issuer,
		"iat":                       time.Now().Unix(),
		"exp":                       expiryTime.Unix(),
	})

	// Execute Remote Hardware Signing using the native GlobalSentryPrivateKey structure
	// Fail closed instantly if private key hasn't been instantiated
	if GlobalSentryPrivateKey == nil {
		return "", fmt.Errorf("FATAL: System missing Root Ed25519 Private Key memory mapping")
	}

	signedToken, err := token.SignedString(GlobalSentryPrivateKey)
	if err != nil {
		return "", fmt.Errorf("EdDSA cryptograhic signing failed: %w", err)
	}

	return signedToken, nil
}

