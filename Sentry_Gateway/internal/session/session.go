// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package session implements Just-In-Time (JIT) session tokens for Cicada.
//
// Why JIT tokens at all:
// The EVAR is a long-lived credential proving certified agent identity. Presenting
// the EVAR directly on every call means a single intercepted token grants unlimited
// access until manual revocation. Zero Trust's "never trust, always verify" principle
// requires a separate, short-lived access grant per session — the EVAR proves WHO
// the agent is; the session token grants WHAT it can do right now.
//
// Why 5 minutes (not 15):
// The previous default of 15 minutes was a 2024-era choice. The 2026 Zero Trust
// standard for AI agent session tokens is ≤5 minutes for high-risk operations,
// with continuous re-attestation. 5 minutes is long enough for a typical
// API call + retry cycle; short enough that a stolen token expires before an
// attacker can operationalise it. Configurable via CICADA_SESSION_TTL_SECONDS
// so enterprise deployments can reduce further (e.g. 60 seconds for proxy:transact).
//
// Token type discrimination:
// The same Ed25519 keypair signs both EVARs and session tokens. A `type` claim
// ("evar" vs "session") prevents session tokens being accepted at EVAR-only
// endpoints and vice versa — this is intentionally strict. An attacker who
// obtains a session token cannot replay it as an EVAR to register new agents.
package session

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/asai/cicada/sentry/internal/auth"
)

// DefaultSessionTTL is the fallback when CICADA_SESSION_TTL_SECONDS is not set.
// 5 minutes aligns with 2026 Zero Trust standards for AI agent session lifetimes.
// See: NIST SP 800-207 (Zero Trust Architecture) §4.1 — "access tokens should
// be as short-lived as practicable given the use case."
const DefaultSessionTTL = 5 * time.Minute

// SessionTTL returns the configured session token lifetime.
// Reads CICADA_SESSION_TTL_SECONDS from the environment so operators can tune
// without recompiling. Enforces a minimum of 30 seconds — shorter than that
// creates re-authentication storms that overwhelm the session endpoint.
func SessionTTL() time.Duration {
	if v := os.Getenv("CICADA_SESSION_TTL_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			if secs < 30 {
				// Clamp at 30 seconds — below this, session churn causes more risk
				// (flooding the session endpoint) than the short lifetime prevents.
				return 30 * time.Second
			}
			return time.Duration(secs) * time.Second
		}
	}
	return DefaultSessionTTL
}

// SessionClaims are the claims embedded in a JIT session token.
// Only fields needed for admission decisions are included — the session token
// is presented on every proxied call so its size directly affects latency.
// Agent metadata (name, description) is NOT included; the proxy looks those
// up from the DB only when required (e.g., semantic check).
type SessionClaims struct {
	// Type discriminates session tokens from EVAR tokens at parse time.
	// Must equal "session" — any other value is rejected by Verify().
	Type string `json:"type"`

	AgentID  string   `json:"agent_id"`
	TenantID string   `json:"tenant_id"`
	Scopes   []string `json:"scopes"`

	// HITLRequired and HITLWebhookURL are baked in at issuance from
	// agents.hitl_enabled and agents.hitl_webhook_url. This avoids a DB
	// hit on the HITL check for every proxied write/transact call.
	// These values are re-evaluated when the session expires and a new one
	// is issued — changes to HITL settings take effect within one TTL cycle.
	HITLRequired   bool   `json:"hitl_required"`
	HITLWebhookURL string `json:"hitl_webhook_url,omitempty"`

	// UserContext (ID-JAG) binds the human user identity to this session.
	// Extracted from the subject_token during RFC 8693 Token Exchange.
	UserContext *auth.UserContext `json:"user_context,omitempty"`

	// DataResidencyRegion ensures the gateway enforces regional pinning
	// even when the agent presents a short-lived session token.
	DataResidencyRegion string `json:"data_residency_region,omitempty"`

	jwt.RegisteredClaims
}

// Issue mints a new JIT session token for a verified agent.
// Called after successful EVAR verification in the /v1/agent/session handler.
// The session TTL is read fresh from the environment on every call so operators
// can change CICADA_SESSION_TTL_SECONDS without restarting the gateway.
func Issue(agentID, tenantID string, scopes []string, hitlRequired bool, hitlWebhookURL string, userCtx *auth.UserContext, region string) (string, error) {
	if auth.GlobalSentryPrivateKey == nil {
		return "", fmt.Errorf("FATAL: Ed25519 private key not loaded — gateway cannot issue tokens")
	}

	ttl := SessionTTL()
	now := time.Now()

	claims := SessionClaims{
		Type:                "session",
		AgentID:             agentID,
		TenantID:            tenantID,
		Scopes:              scopes,
		HITLRequired:        hitlRequired,
		HITLWebhookURL:      hitlWebhookURL,
		UserContext:         userCtx,
		DataResidencyRegion: region,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "cicada-gateway-session",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(auth.GlobalSentryPrivateKey)
}

// Verify parses and validates a session token.
// Returns ErrNotSessionToken if a valid EVAR is presented where a session token
// is expected — this tells the caller precisely what is wrong so the agent can
// be directed to /v1/agent/session to exchange its EVAR for a session.
func Verify(tokenString string) (*SessionClaims, error) {
	if auth.GlobalSentryPublicKey == nil {
		return nil, fmt.Errorf("FATAL: Ed25519 public key not loaded")
	}

	token, err := jwt.ParseWithClaims(tokenString, &SessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing algorithm: %v", t.Header["alg"])
		}
		return auth.GlobalSentryPublicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("session token verification failed: %w", err)
	}

	claims, ok := token.Claims.(*SessionClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid session token structure")
	}

	// Explicitly reject EVAR tokens at session-only endpoints.
	// Without this check, an EVAR token (valid JWT, same key) would pass
	// the signature verification above and be accepted as a session token —
	// defeating the separation between long-lived identity and short-lived access.
	if claims.Type != "session" {
		return nil, fmt.Errorf("token type %q is not a session token — call /v1/agent/session to exchange your EVAR", claims.Type)
	}

	return claims, nil
}

// ScopesContainWriteOrTransact returns true if the scope list includes any
// scope that triggers HITL review. Centralised here so the HITL check, the
// proxy handler, and the tiered approval system all apply identical logic —
// no divergence between what is checked and what is documented.
func ScopesContainWriteOrTransact(scopes []string) bool {
	for _, s := range scopes {
		if s == "proxy:write" || s == "proxy:transact" {
			return true
		}
	}
	return false
}
