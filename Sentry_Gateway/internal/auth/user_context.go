// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package auth — User-Context Propagation (H2.1).
//
// Parses and optionally validates the X-Cicada-User-Context header.
//
// The header carries the identity of the end-user on whose behalf the agent
// is acting. This closes the attribution gap: "Agent X performed this action
// on behalf of Customer Y" — critical for SOX, HIPAA, and PCI-DSS auditing
// in regulated industries.
//
// Supported formats:
//
//  1. Signed JWT (recommended): The agent SDK passes a JWT issued by the
//     customer's IdP. Cicada validates the signature against a configured
//     JWKS endpoint, extracts the `sub`, `email`, and `name` claims, and
//     persists them in the action ledger. This provides non-repudiable
//     user attribution.
//
//  2. Plain identifier (fallback): If no JWKS is configured, the raw header
//     value is stored as-is. This is cooperative (the agent asserts the user
//     identity without cryptographic proof) but still provides audit signal
//     for non-regulated workloads.
//
// Configuration:
//
//	CICADA_USER_CONTEXT_JWKS_URL — HTTPS URL of the JWKS endpoint to validate
//	  user-context JWTs. If empty, validation is skipped (plain identifier mode).
//	CICADA_USER_CONTEXT_REQUIRED — If "true", requests without a valid
//	  X-Cicada-User-Context header are rejected (403). Default: false.
//	CICADA_USER_CONTEXT_ISSUERS — Comma-separated list of accepted `iss` values.
//	  If empty, any issuer is accepted.
package auth

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// UserContext represents the validated identity of the end-user on whose
// behalf an agent is acting. Extracted from X-Cicada-User-Context.
type UserContext struct {
	// Subject is the unique user identifier (JWT `sub` claim or raw header value).
	Subject string `json:"sub"`

	// Email is the user's email address (JWT `email` claim, if present).
	Email string `json:"email,omitempty"`

	// Name is the user's display name (JWT `name` claim, if present).
	Name string `json:"name,omitempty"`

	// Issuer is the IdP that issued the user-context token (JWT `iss` claim).
	Issuer string `json:"iss,omitempty"`

	// Verified indicates whether the user-context was cryptographically verified
	// against a JWKS endpoint (true) or accepted as a plain identifier (false).
	Verified bool `json:"verified"`

	// Raw is the original header value, preserved for audit logging.
	Raw string `json:"raw"`

	// ── OAuth 2.0 Token Exchange (RFC 8693) fields ─────────────────────────

	// ClientID is the OAuth client_id claim — identifies the application that
	// requested the token exchange. Present only in token-exchange JWTs.
	ClientID string `json:"client_id,omitempty"`

	// Scope contains the delegated scope string from the token exchange.
	// Example: "read:profile write:orders" — this is the subset of permissions
	// the end-user delegated to the agent for this session.
	Scope string `json:"scope,omitempty"`

	// ActorChain represents the delegation chain from the `act` claim (RFC 8693 §4.1).
	// Each entry is an actor in the chain, outermost first.
	// Example: [{"sub":"agent-service"}, {"sub":"orchestrator-api"}]
	// means the request was delegated: User → orchestrator-api → agent-service → Gateway.
	ActorChain []ActorClaim `json:"actor_chain,omitempty"`
}

// ActorClaim represents a single actor in the RFC 8693 `act` delegation chain.
// The `act` claim is recursive: {"act": {"sub": "A", "act": {"sub": "B"}}}.
// We flatten this into an ordered slice for storage and display.
type ActorClaim struct {
	Subject  string `json:"sub"`
	ClientID string `json:"client_id,omitempty"`
}

// String returns a human-readable representation for log lines and dashboard display.
// Format: "user@example.com (John Doe) [verified]" or "user_12345 [unverified]".
// If an actor chain is present, it is appended: "via agent-service → orchestrator-api".
func (uc UserContext) String() string {
	var parts []string
	if uc.Email != "" {
		parts = append(parts, uc.Email)
	} else if uc.Subject != "" {
		parts = append(parts, uc.Subject)
	}
	if uc.Name != "" {
		parts = append(parts, fmt.Sprintf("(%s)", uc.Name))
	}
	if uc.Verified {
		parts = append(parts, "[verified]")
	} else {
		parts = append(parts, "[unverified]")
	}
	if len(uc.ActorChain) > 0 {
		var actors []string
		for _, a := range uc.ActorChain {
			actors = append(actors, a.Subject)
		}
		parts = append(parts, fmt.Sprintf("via %s", strings.Join(actors, " → ")))
	}
	return strings.Join(parts, " ")
}

// ToJSON serialises the UserContext for storage in the action_ledger
// human_user_context JSONB column. Returns empty string if no user context.
func (uc UserContext) ToJSON() string {
	if uc.Subject == "" && uc.Raw == "" {
		return ""
	}
	b, err := json.Marshal(uc)
	if err != nil {
		return uc.Raw // fallback to raw string on marshal error
	}
	return string(b)
}

// ── JWKS cache ───────────────────────────────────────────────────────────────

// jwksCache stores fetched JWKS keys with a TTL to avoid hitting the IdP
// on every request. Keys are refreshed every 5 minutes.
var (
	jwksCacheMu   sync.RWMutex
	jwksCacheKeys map[string]crypto.PublicKey
	jwksCacheTime time.Time
	jwksCacheTTL  = 5 * time.Minute
)

// JWKSKey represents a single key in a JWKS response.
type JWKSKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	Crv string `json:"crv"` // EC curve
	X   string `json:"x"`   // EC x coordinate
	Y   string `json:"y"`   // EC y coordinate
}

// JWKSResponse is the top-level JWKS JSON structure.
type JWKSResponse struct {
	Keys []JWKSKey `json:"keys"`
}

// ── Public API ───────────────────────────────────────────────────────────────

// ParseUserContext extracts and validates the X-Cicada-User-Context header.
//
// If CICADA_USER_CONTEXT_JWKS_URL is configured, the header value is treated
// as a JWT and validated against the JWKS endpoint. If the JWT is valid, a
// verified UserContext is returned with structured claims.
//
// If no JWKS URL is configured, the header value is accepted as a plain
// identifier (cooperative mode) and returned as an unverified UserContext.
//
// Returns nil if the header is empty or missing.
func ParseUserContext(headerValue string) *UserContext {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return nil
	}

	jwksURL := os.Getenv("CICADA_USER_CONTEXT_JWKS_URL")

	// If JWKS is configured, attempt JWT validation first.
	if jwksURL != "" {
		uc, err := validateUserContextJWT(headerValue, jwksURL)
		if err != nil {
			log.Printf("[USER-CONTEXT] JWT validation failed (falling back to plain): %v", err)
			// Fall through to plain identifier mode.
		} else {
			return uc
		}
	}

	// Plain identifier mode: accept the raw value without cryptographic proof.
	// The value could be an email, user ID, or any string the agent SDK provides.
	return &UserContext{
		Subject:  headerValue,
		Verified: false,
		Raw:      headerValue,
	}
}

// IsUserContextRequired returns true if CICADA_USER_CONTEXT_REQUIRED is set to "true".
// When true, requests without a valid X-Cicada-User-Context are rejected.
func IsUserContextRequired() bool {
	return strings.EqualFold(os.Getenv("CICADA_USER_CONTEXT_REQUIRED"), "true")
}

// ── JWT validation ───────────────────────────────────────────────────────────

// userContextClaims maps the JWT claims we extract from user-context tokens.
// Includes standard OIDC claims and RFC 8693 token exchange claims.
type userContextClaims struct {
	Email    string                 `json:"email"`
	Name     string                 `json:"name"`
	ClientID string                 `json:"client_id"`
	Scope    string                 `json:"scope"`
	Act      map[string]interface{} `json:"act"`
	jwt.RegisteredClaims
}

// validateUserContextJWT parses and validates a JWT user-context token against
// the configured JWKS endpoint. Returns a verified UserContext on success.
func validateUserContextJWT(tokenString, jwksURL string) (*UserContext, error) {
	// Fetch (or use cached) JWKS keys.
	keys, err := fetchJWKS(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("JWKS fetch failed: %w", err)
	}

	// Parse the token — the key function selects the correct key by kid.
	token, err := jwt.ParseWithClaims(tokenString, &userContextClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			// No kid — try the first available key.
			for _, k := range keys {
				return k, nil
			}
			return nil, fmt.Errorf("no keys available in JWKS")
		}
		key, found := keys[kid]
		if !found {
			return nil, fmt.Errorf("kid %q not found in JWKS", kid)
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("JWT parse/verify failed: %w", err)
	}

	claims, ok := token.Claims.(*userContextClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Issuer validation: if CICADA_USER_CONTEXT_ISSUERS is configured,
	// the token's iss must be in the allowed list.
	if allowedIssuers := os.Getenv("CICADA_USER_CONTEXT_ISSUERS"); allowedIssuers != "" {
		issuer, _ := claims.GetIssuer()
		allowed := false
		for _, iss := range strings.Split(allowedIssuers, ",") {
			if strings.TrimSpace(iss) == issuer {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("issuer %q not in allowed list", issuer)
		}
	}

	// Audience validation: if CICADA_USER_CONTEXT_AUDIENCES is configured,
	// the token's aud must contain at least one of the allowed audiences.
	// This prevents token misuse — a token intended for Service A cannot be
	// replayed against Service B through the Cicada Gateway.
	if allowedAudiences := os.Getenv("CICADA_USER_CONTEXT_AUDIENCES"); allowedAudiences != "" {
		audiences, _ := claims.GetAudience()
		allowed := false
		for _, configAud := range strings.Split(allowedAudiences, ",") {
			configAud = strings.TrimSpace(configAud)
			for _, tokenAud := range audiences {
				if tokenAud == configAud {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("audience %v not in allowed list", audiences)
		}
	}

	sub, _ := claims.GetSubject()
	iss, _ := claims.GetIssuer()

	// Extract the RFC 8693 actor chain from the recursive `act` claim.
	// The act claim is nested: {"act": {"sub": "A", "act": {"sub": "B"}}}.
	// We flatten this into an ordered slice for storage and display.
	actorChain := flattenActClaim(claims.Act)

	return &UserContext{
		Subject:    sub,
		Email:      claims.Email,
		Name:       claims.Name,
		Issuer:     iss,
		Verified:   true,
		Raw:        tokenString,
		ClientID:   claims.ClientID,
		Scope:      claims.Scope,
		ActorChain: actorChain,
	}, nil
}

// fetchJWKS retrieves the JWKS key set from the configured URL, using a local
// cache with a 5-minute TTL. This prevents hammering the IdP on every request.
func fetchJWKS(jwksURL string) (map[string]crypto.PublicKey, error) {
	jwksCacheMu.RLock()
	if jwksCacheKeys != nil && time.Since(jwksCacheTime) < jwksCacheTTL {
		keys := jwksCacheKeys
		jwksCacheMu.RUnlock()
		return keys, nil
	}
	jwksCacheMu.RUnlock()

	// Cache miss or expired — fetch fresh keys.
	jwksCacheMu.Lock()
	defer jwksCacheMu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have refreshed).
	if jwksCacheKeys != nil && time.Since(jwksCacheTime) < jwksCacheTTL {
		return jwksCacheKeys, nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		// On network error, return stale cache if available.
		if jwksCacheKeys != nil {
			log.Printf("[USER-CONTEXT] JWKS fetch failed, using stale cache: %v", err)
			return jwksCacheKeys, nil
		}
		return nil, fmt.Errorf("JWKS endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512KB limit
	if err != nil {
		return nil, fmt.Errorf("JWKS read failed: %w", err)
	}

	var jwksResp JWKSResponse
	if err := json.Unmarshal(body, &jwksResp); err != nil {
		return nil, fmt.Errorf("JWKS parse failed: %w", err)
	}

	keys := make(map[string]crypto.PublicKey)
	for _, k := range jwksResp.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue // skip encryption keys
		}
		pubKey, err := jwksKeyToPublicKey(k)
		if err != nil {
			log.Printf("[USER-CONTEXT] Skipping JWKS key kid=%s: %v", k.Kid, err)
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = "__default__"
		}
		keys[kid] = pubKey
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no usable signing keys in JWKS response")
	}

	jwksCacheKeys = keys
	jwksCacheTime = time.Now()
	log.Printf("[USER-CONTEXT] JWKS cache refreshed: %d keys from %s", len(keys), jwksURL)

	return keys, nil
}

// jwksKeyToPublicKey converts a JWK key to a Go crypto.PublicKey.
// Supports RSA (kty=RSA) keys — the most common in enterprise IdPs
// (Okta, Azure AD, Auth0, Google).
func jwksKeyToPublicKey(k JWKSKey) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		return rsaJWKToPublicKey(k)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.Kty)
	}
}

// rsaJWKToPublicKey constructs an *rsa.PublicKey from JWK n and e values.
func rsaJWKToPublicKey(k JWKSKey) (crypto.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if !e.IsInt64() {
		return nil, fmt.Errorf("RSA exponent too large")
	}

	return &struct {
		N *big.Int
		E int
	}{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// ── RFC 8693 Token Exchange helpers ──────────────────────────────────────────

// flattenActClaim recursively extracts the actor delegation chain from the
// RFC 8693 `act` claim. The claim is nested:
//
//	{"sub": "agent-service", "client_id": "abc", "act": {"sub": "orchestrator"}}
//
// We flatten this into an ordered slice: [{sub: "agent-service"}, {sub: "orchestrator"}].
// Depth is limited to 10 to prevent malicious unbounded recursion.
func flattenActClaim(act map[string]interface{}) []ActorClaim {
	if act == nil {
		return nil
	}

	var chain []ActorClaim
	current := act
	const maxDepth = 10

	for i := 0; i < maxDepth; i++ {
		sub, _ := current["sub"].(string)
		clientID, _ := current["client_id"].(string)
		if sub == "" && clientID == "" {
			break // no identifiable actor at this level
		}
		chain = append(chain, ActorClaim{
			Subject:  sub,
			ClientID: clientID,
		})

		// Descend into the nested act claim.
		nested, ok := current["act"].(map[string]interface{})
		if !ok {
			break
		}
		current = nested
	}

	return chain
}
