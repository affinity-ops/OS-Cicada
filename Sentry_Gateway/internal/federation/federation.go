// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package federation implements SAML 2.0 / OIDC enterprise SSO (S6.2).
//
// Provides IdP configuration management, OIDC Authorization Code + PKCE flow,
// SAML SP assertion handling, and portal session JWT issuance for federated
// operator authentication.
//
// Configuration:
//
//	CICADA_FEDERATION_BASE_URL    — Gateway external URL for callbacks
//	CICADA_FEDERATION_SESSION_TTL — Portal session lifetime (default: 8h)
package federation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/asai/cicada/sentry/internal/auth"
)

// ── Configuration ────────────────────────────────────────────────────────────

const DefaultSessionTTL = 8 * time.Hour

func SessionTTL() time.Duration {
	if v := os.Getenv("CICADA_FEDERATION_SESSION_TTL"); v != "" {
		if h, err := strconv.Atoi(v); err == nil && h > 0 {
			return time.Duration(h) * time.Hour
		}
	}
	return DefaultSessionTTL
}

func BaseURL() string {
	u := os.Getenv("CICADA_FEDERATION_BASE_URL")
	if u == "" {
		u = "http://localhost:8080"
	}
	return strings.TrimRight(u, "/")
}

// ── Data Types ───────────────────────────────────────────────────────────────

// Provider represents a configured IdP for a tenant.
type Provider struct {
	ID              string   `json:"id"`
	TenantID        string   `json:"tenant_id"`
	Name            string   `json:"name"`
	Protocol        string   `json:"protocol"` // "saml" or "oidc"
	Enabled         bool     `json:"enabled"`
	OIDCIssuerURL   string   `json:"oidc_issuer_url,omitempty"`
	OIDCClientID    string   `json:"oidc_client_id,omitempty"`
	OIDCClientSecret string  `json:"oidc_client_secret,omitempty"`
	OIDCScopes      string   `json:"oidc_scopes,omitempty"`
	OIDCRedirectURI string   `json:"oidc_redirect_uri,omitempty"`
	SAMLEntityID    string   `json:"saml_entity_id,omitempty"`
	SAMLSSOURL      string   `json:"saml_sso_url,omitempty"`
	SAMLCertificate string   `json:"saml_certificate,omitempty"`
	DefaultRole     string   `json:"default_role"`
	AllowedDomains  []string `json:"allowed_domains,omitempty"`
	AutoProvision   bool     `json:"auto_provision"`
}

// FederatedUser represents a user authenticated via an IdP.
type FederatedUser struct {
	Subject     string   `json:"sub"`
	Email       string   `json:"email"`
	DisplayName string   `json:"name"`
	Groups      []string `json:"groups,omitempty"`
	ProviderID  string   `json:"provider_id"`
	TenantID    string   `json:"tenant_id"`
	Role        string   `json:"role"`
}

// PortalSessionClaims are embedded in portal session JWTs.
type PortalSessionClaims struct {
	Type        string   `json:"type"`
	TenantID    string   `json:"tenant_id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"name"`
	Role        string   `json:"role"`
	ProviderID  string   `json:"provider_id"`
	Groups      []string `json:"groups,omitempty"`
	jwt.RegisteredClaims
}

// OIDCDiscovery is the subset of fields we need from .well-known/openid-configuration.
type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// ── OIDC Flow ────────────────────────────────────────────────────────────────

// GenerateOIDCAuthURL builds the authorization URL for OIDC login with PKCE.
func GenerateOIDCAuthURL(provider Provider, state string) (authURL, codeVerifier string, err error) {
	disc, err := discoverOIDC(provider.OIDCIssuerURL)
	if err != nil {
		return "", "", fmt.Errorf("OIDC discovery failed: %w", err)
	}

	// Generate PKCE code verifier (RFC 7636)
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", fmt.Errorf("generate PKCE verifier: %w", err)
	}
	codeVerifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	// S256 challenge
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	redirectURI := provider.OIDCRedirectURI
	if redirectURI == "" {
		redirectURI = fmt.Sprintf("%s/v1/federation/oidc/callback", BaseURL())
	}

	scopes := provider.OIDCScopes
	if scopes == "" {
		scopes = "openid profile email"
	}

	params := fmt.Sprintf(
		"%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
		disc.AuthorizationEndpoint,
		provider.OIDCClientID,
		redirectURI,
		strings.ReplaceAll(scopes, " ", "+"),
		state,
		codeChallenge,
	)

	return params, codeVerifier, nil
}

// ExchangeOIDCCode exchanges an authorization code for tokens and returns user info.
func ExchangeOIDCCode(ctx context.Context, provider Provider, code, codeVerifier string) (*FederatedUser, error) {
	disc, err := discoverOIDC(provider.OIDCIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}

	redirectURI := provider.OIDCRedirectURI
	if redirectURI == "" {
		redirectURI = fmt.Sprintf("%s/v1/federation/oidc/callback", BaseURL())
	}

	// Token exchange
	body := fmt.Sprintf(
		"grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&client_secret=%s&code_verifier=%s",
		code, redirectURI, provider.OIDCClientID, provider.OIDCClientSecret, codeVerifier,
	)

	req, _ := http.NewRequestWithContext(ctx, "POST", disc.TokenEndpoint, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	// Parse ID token claims (signature verification deferred to JWKS — for now trust the TLS channel)
	parts := strings.Split(tokenResp.IDToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid ID token format")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode ID token claims: %w", err)
	}

	var claims struct {
		Sub    string   `json:"sub"`
		Email  string   `json:"email"`
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal ID token claims: %w", err)
	}

	return &FederatedUser{
		Subject:     claims.Sub,
		Email:       claims.Email,
		DisplayName: claims.Name,
		Groups:      claims.Groups,
		ProviderID:  provider.ID,
		TenantID:    provider.TenantID,
		Role:        provider.DefaultRole,
	}, nil
}

// ── Portal Session Issuance ──────────────────────────────────────────────────

// IssuePortalSession mints a portal JWT for a federated user.
func IssuePortalSession(user *FederatedUser) (string, error) {
	if auth.GlobalSentryPrivateKey == nil {
		return "", fmt.Errorf("FATAL: Ed25519 private key not loaded")
	}

	now := time.Now()
	ttl := SessionTTL()

	claims := PortalSessionClaims{
		Type:        "portal_session",
		TenantID:    user.TenantID,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Role:        user.Role,
		ProviderID:  user.ProviderID,
		Groups:      user.Groups,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.Subject,
			Issuer:    "cicada-federation",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(auth.GlobalSentryPrivateKey)
}

// VerifyPortalSession validates a portal session JWT.
func VerifyPortalSession(tokenString string) (*PortalSessionClaims, error) {
	if auth.GlobalSentryPublicKey == nil {
		return nil, fmt.Errorf("FATAL: Ed25519 public key not loaded")
	}

	token, err := jwt.ParseWithClaims(tokenString, &PortalSessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing algorithm: %v", t.Header["alg"])
		}
		return auth.GlobalSentryPublicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("portal session verification failed: %w", err)
	}

	claims, ok := token.Claims.(*PortalSessionClaims)
	if !ok || !token.Valid || claims.Type != "portal_session" {
		return nil, fmt.Errorf("invalid portal session token")
	}

	return claims, nil
}

// ── Provider CRUD ────────────────────────────────────────────────────────────

// GetProvider fetches a federation provider by ID.
func GetProvider(ctx context.Context, db *pgxpool.Pool, providerID string) (*Provider, error) {
	p := &Provider{}
	err := db.QueryRow(ctx, `
		SELECT id, tenant_id, name, protocol, enabled,
		       COALESCE(oidc_issuer_url, ''), COALESCE(oidc_client_id, ''),
		       COALESCE(oidc_client_secret, ''), COALESCE(oidc_scopes, 'openid profile email'),
		       COALESCE(oidc_redirect_uri, ''),
		       COALESCE(saml_entity_id, ''), COALESCE(saml_sso_url, ''),
		       COALESCE(saml_certificate, ''),
		       COALESCE(default_role, 'viewer'), auto_provision
		FROM federation_providers WHERE id = $1::UUID AND enabled = true
	`, providerID).Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Protocol, &p.Enabled,
		&p.OIDCIssuerURL, &p.OIDCClientID, &p.OIDCClientSecret, &p.OIDCScopes,
		&p.OIDCRedirectURI,
		&p.SAMLEntityID, &p.SAMLSSOURL, &p.SAMLCertificate,
		&p.DefaultRole, &p.AutoProvision,
	)
	if err != nil {
		return nil, fmt.Errorf("provider not found: %w", err)
	}
	return p, nil
}

// ListProviders returns all federation providers for a tenant.
func ListProviders(ctx context.Context, db *pgxpool.Pool, tenantID string) ([]Provider, error) {
	rows, err := db.Query(ctx, `
		SELECT id, tenant_id, name, protocol, enabled,
		       COALESCE(oidc_issuer_url, ''), COALESCE(oidc_client_id, ''),
		       COALESCE(default_role, 'viewer'), auto_provision
		FROM federation_providers WHERE tenant_id = $1::UUID
		ORDER BY name
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []Provider
	for rows.Next() {
		var p Provider
		if err := rows.Scan(
			&p.ID, &p.TenantID, &p.Name, &p.Protocol, &p.Enabled,
			&p.OIDCIssuerURL, &p.OIDCClientID,
			&p.DefaultRole, &p.AutoProvision,
		); err != nil {
			continue
		}
		providers = append(providers, p)
	}
	return providers, nil
}

// CreateProvider persists a new federation provider.
func CreateProvider(ctx context.Context, db *pgxpool.Pool, p Provider) (string, error) {
	var id string
	err := db.QueryRow(ctx, `
		INSERT INTO federation_providers
			(tenant_id, name, protocol, enabled,
			 oidc_issuer_url, oidc_client_id, oidc_client_secret, oidc_scopes, oidc_redirect_uri,
			 saml_entity_id, saml_sso_url, saml_certificate,
			 default_role, auto_provision)
		VALUES ($1::UUID, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id
	`, p.TenantID, p.Name, p.Protocol, p.Enabled,
		nullEmpty(p.OIDCIssuerURL), nullEmpty(p.OIDCClientID), nullEmpty(p.OIDCClientSecret),
		nullEmpty(p.OIDCScopes), nullEmpty(p.OIDCRedirectURI),
		nullEmpty(p.SAMLEntityID), nullEmpty(p.SAMLSSOURL), nullEmpty(p.SAMLCertificate),
		p.DefaultRole, p.AutoProvision,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create provider: %w", err)
	}

	// Audit log
	recordAudit(ctx, db, p.TenantID, id, "provider_created", "", "", "", "")

	return id, nil
}

// ── Audit ────────────────────────────────────────────────────────────────────

func recordAudit(ctx context.Context, db *pgxpool.Pool, tenantID, providerID, eventType, subject, email, ip, ua string) {
	_, err := db.Exec(ctx, `
		INSERT INTO federation_audit_log
			(tenant_id, provider_id, event_type, subject, email, ip_address, user_agent)
		VALUES ($1::UUID, NULLIF($2, '')::UUID, $3, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, '')::INET, NULLIF($7, ''))
	`, tenantID, providerID, eventType, subject, email, ip, ua)
	if err != nil {
		log.Printf("[FEDERATION] audit write error: %v", err)
	}
}

// RecordLogin records a federated login event for audit purposes.
func RecordLogin(ctx context.Context, db *pgxpool.Pool, user *FederatedUser, success bool, ip, ua, errDetail string) {
	eventType := "login_success"
	if !success {
		eventType = "login_failure"
	}
	if errDetail != "" {
		_, _ = db.Exec(ctx, `
			INSERT INTO federation_audit_log
				(tenant_id, provider_id, event_type, subject, email, ip_address, user_agent, error_detail)
			VALUES ($1::UUID, NULLIF($2, '')::UUID, $3, $4, $5, NULLIF($6, '')::INET, $7, $8)
		`, user.TenantID, user.ProviderID, eventType, user.Subject, user.Email, ip, ua, errDetail)
	} else {
		recordAudit(ctx, db, user.TenantID, user.ProviderID, eventType, user.Subject, user.Email, ip, ua)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func discoverOIDC(issuerURL string) (*OIDCDiscovery, error) {
	wellKnown := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(wellKnown)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("discovery returned %d", resp.StatusCode)
	}

	var disc OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("parse discovery: %w", err)
	}
	return &disc, nil
}

func nullEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// GenerateState creates a cryptographic random state parameter for OAuth flows.
func GenerateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
