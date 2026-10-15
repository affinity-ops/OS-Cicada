// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package secrets provides a unified interface for external secret management (S6.8).
//
// Abstracts secret storage/retrieval behind a pluggable Backend interface.
// Supported backends:
//   - "env"   — local AES-256-GCM envelope encryption (existing KeyVault, default)
//   - "vault" — HashiCorp Vault Transit secrets engine
//
// Configuration:
//
//	CICADA_SECRET_BACKEND     — "env" or "vault" (default: "env")
//	CICADA_VAULT_ADDR         — Vault server URL (e.g., "https://vault.example.com:8200")
//	CICADA_VAULT_TOKEN        — Vault authentication token
//	CICADA_VAULT_TRANSIT_KEY  — Vault Transit key name (default: "cicada-sentry")
//	CICADA_VAULT_MOUNT_PATH   — Vault secrets mount (default: "transit")
package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/asai/cicada/sentry/internal/auth"
)

// ── Backend Interface ────────────────────────────────────────────────────────

// Backend defines the contract for secret storage providers.
type Backend interface {
	// Name returns the backend identifier (e.g., "vault", "aws", "env").
	Name() string

	// Encrypt encrypts a plaintext secret, binding it to the given tenant context.
	Encrypt(ctx context.Context, plaintext, tenantID string) (string, error)

	// Decrypt decrypts a ciphertext blob, verifying tenant binding.
	Decrypt(ctx context.Context, ciphertext, tenantID string) (string, error)

	// StoreSecret stores a named secret (for backends that support key-value storage).
	StoreSecret(ctx context.Context, path, value string) error

	// GetSecret retrieves a named secret.
	GetSecret(ctx context.Context, path string) (string, error)

	// Health returns nil if the backend is operational.
	Health(ctx context.Context) error
}

// ── Backend Factory ──────────────────────────────────────────────────────────

// NewBackend creates a Backend based on CICADA_SECRET_BACKEND.
func NewBackend() (Backend, error) {
	backend := os.Getenv("CICADA_SECRET_BACKEND")
	if backend == "" {
		backend = "env"
	}

	switch strings.ToLower(backend) {
	case "env":
		return NewEnvBackend()
	case "vault":
		return NewVaultBackend()
	default:
		return nil, fmt.Errorf("unknown secret backend: %q (supported: env, vault)", backend)
	}
}

// ── Env Backend (existing KeyVault wrapper) ──────────────────────────────────

// EnvBackend wraps the existing AES-256-GCM KeyVault for local deployments.
type EnvBackend struct {
	vault *auth.KeyVault
}

// NewEnvBackend creates an EnvBackend using CICADA_AES_MASTER_KEY.
func NewEnvBackend() (*EnvBackend, error) {
	v, err := auth.NewVaultFromEnv()
	if err != nil {
		return nil, fmt.Errorf("env backend: %w", err)
	}
	return &EnvBackend{vault: v}, nil
}

func (e *EnvBackend) Name() string { return "env" }

func (e *EnvBackend) Encrypt(ctx context.Context, plaintext, tenantID string) (string, error) {
	return e.vault.EncryptUserKey(ctx, plaintext, tenantID)
}

func (e *EnvBackend) Decrypt(ctx context.Context, ciphertext, tenantID string) (string, error) {
	return e.vault.DecryptForSentry(ctx, ciphertext, tenantID)
}

func (e *EnvBackend) StoreSecret(_ context.Context, path, value string) error {
	// Env backend has no key-value store — secrets are stored in the database
	log.Printf("[SECRETS/ENV] StoreSecret called for %q — no-op (secrets stored in DB)", path)
	return nil
}

func (e *EnvBackend) GetSecret(_ context.Context, path string) (string, error) {
	// Check environment variables as a fallback
	envKey := strings.ReplaceAll(strings.ToUpper(path), "/", "_")
	if v := os.Getenv(envKey); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("secret %q not found in environment", path)
}

func (e *EnvBackend) Health(_ context.Context) error { return nil }

// ── HashiCorp Vault Backend ──────────────────────────────────────────────────

// VaultBackend integrates with HashiCorp Vault's Transit secrets engine
// for encryption/decryption and KV v2 for secret storage.
type VaultBackend struct {
	addr       string
	token      string
	transitKey string
	mountPath  string
	client     *http.Client
}

// NewVaultBackend creates a VaultBackend from environment variables.
func NewVaultBackend() (*VaultBackend, error) {
	addr := os.Getenv("CICADA_VAULT_ADDR")
	if addr == "" {
		return nil, fmt.Errorf("CICADA_VAULT_ADDR is required for vault backend")
	}
	token := os.Getenv("CICADA_VAULT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("CICADA_VAULT_TOKEN is required for vault backend")
	}

	transitKey := os.Getenv("CICADA_VAULT_TRANSIT_KEY")
	if transitKey == "" {
		transitKey = "cicada-sentry"
	}
	mountPath := os.Getenv("CICADA_VAULT_MOUNT_PATH")
	if mountPath == "" {
		mountPath = "transit"
	}

	return &VaultBackend{
		addr:       strings.TrimRight(addr, "/"),
		token:      token,
		transitKey: transitKey,
		mountPath:  mountPath,
		client:     &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (v *VaultBackend) Name() string { return "vault" }

// Encrypt uses Vault Transit to encrypt data, with tenant context in the AAD.
func (v *VaultBackend) Encrypt(ctx context.Context, plaintext, tenantID string) (string, error) {
	body := fmt.Sprintf(`{"plaintext":"%s","context":"%s"}`,
		encodeB64(plaintext), encodeB64(tenantID))

	resp, err := v.vaultRequest(ctx, "POST",
		fmt.Sprintf("/v1/%s/encrypt/%s", v.mountPath, v.transitKey),
		body)
	if err != nil {
		return "", fmt.Errorf("vault encrypt: %w", err)
	}

	ciphertext, ok := extractVaultField(resp, "ciphertext")
	if !ok {
		return "", fmt.Errorf("vault encrypt: missing ciphertext in response")
	}
	return ciphertext, nil
}

// Decrypt uses Vault Transit to decrypt data, verifying tenant context.
func (v *VaultBackend) Decrypt(ctx context.Context, ciphertext, tenantID string) (string, error) {
	body := fmt.Sprintf(`{"ciphertext":"%s","context":"%s"}`,
		ciphertext, encodeB64(tenantID))

	resp, err := v.vaultRequest(ctx, "POST",
		fmt.Sprintf("/v1/%s/decrypt/%s", v.mountPath, v.transitKey),
		body)
	if err != nil {
		return "", fmt.Errorf("vault decrypt: %w", err)
	}

	b64Plain, ok := extractVaultField(resp, "plaintext")
	if !ok {
		return "", fmt.Errorf("vault decrypt: missing plaintext in response")
	}
	return decodeB64(b64Plain)
}

// StoreSecret writes a secret to Vault KV v2.
func (v *VaultBackend) StoreSecret(ctx context.Context, path, value string) error {
	payload, err := json.Marshal(map[string]interface{}{
		"data": map[string]interface{}{"value": value},
	})
	if err != nil {
		return fmt.Errorf("vault store marshal: %w", err)
	}
	_, err = v.vaultRequest(ctx, "POST",
		fmt.Sprintf("/v1/secret/data/%s", path), string(payload))
	return err
}

// GetSecret reads a secret from Vault KV v2.
func (v *VaultBackend) GetSecret(ctx context.Context, path string) (string, error) {
	resp, err := v.vaultRequest(ctx, "GET",
		fmt.Sprintf("/v1/secret/data/%s", path), "")
	if err != nil {
		return "", err
	}

	// KV v2 nests under data.data.value
	if data, ok := resp["data"].(map[string]interface{}); ok {
		if inner, ok := data["data"].(map[string]interface{}); ok {
			if val, ok := inner["value"].(string); ok {
				return val, nil
			}
		}
	}
	return "", fmt.Errorf("secret %q not found in vault response", path)
}

// Health checks Vault server availability.
func (v *VaultBackend) Health(ctx context.Context) error {
	_, err := v.vaultRequest(ctx, "GET", "/v1/sys/health", "")
	return err
}

func (v *VaultBackend) vaultRequest(ctx context.Context, method, path, body string) (map[string]interface{}, error) {
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, v.addr+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("vault returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]interface{}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, fmt.Errorf("parse vault response: %w", err)
		}
	}
	return result, nil
}

// ── Utility Functions ────────────────────────────────────────────────────────

// encodeB64 encodes a string to standard base64 for Vault Transit API payloads.
func encodeB64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// decodeB64 decodes a standard base64 string returned by Vault Transit.
func decodeB64(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	return string(b), nil
}

func extractVaultField(resp map[string]interface{}, field string) (string, bool) {
	if resp == nil {
		return "", false
	}
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", false
	}
	val, ok := data[field].(string)
	return val, ok
}
