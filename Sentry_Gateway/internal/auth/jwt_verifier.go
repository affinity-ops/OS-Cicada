// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
)

// EVARPayload maps directly to the exact JSON struct issued by Cicada
type EVARPayload struct {
	AgentID                 string            `json:"sub"`
	CodeHash                string            `json:"hash"`
	Scopes                  []interface{}     `json:"scopes"` // Generic array unmarshaling from JWT
	ModelIntended           string            `json:"model"`
	CertifiedReversalRoutes map[string]interface{} `json:"certified_reversal_routes"` 
	DataResidencyRegion     string            `json:"region,omitempty"`
	
	// Phase H2.2 - Enterprise Identity Federation
	// Currently, Sentry relies on the X-Cicada-User-Context header for human mapping.
	// Future: SAML 2.0 assertions will inject the enterprise `human_uid` natively
	// into the EVAR if an IdP (Okta/AzureAD) trusts the session, preventing header spoofing.
	// HumanOwnerID string `json:"human_owner_oidc,omitempty"`

	jwt.RegisteredClaims
}

// VerifyEVARToken organically parses the EdDSA JWT string and validates timing and signature
// against the Sentry's root Ed25519 Public Key.
func VerifyEVARToken(tokenString string) (*EVARPayload, error) {
	if GlobalSentryPublicKey == nil {
		return nil, fmt.Errorf("FATAL: System missing Root Ed25519 Public Key memory mapping")
	}

	token, err := jwt.ParseWithClaims(tokenString, &EVARPayload{}, func(token *jwt.Token) (interface{}, error) {
		// Strictly enforce EdDSA as the asymmetric signing mechanism
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing algorithm: %v", token.Header["alg"])
		}
		return GlobalSentryPublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("cryptographic verification failed: %w", err)
	}

	if claims, ok := token.Claims.(*EVARPayload); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token mapping")
}
