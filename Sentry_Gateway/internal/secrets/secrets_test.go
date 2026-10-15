// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"os"
	"testing"
)

// ── Backend Factory Tests ────────────────────────────────────────────────────

func TestNewBackend_DefaultsToEnv(t *testing.T) {
	os.Unsetenv("CICADA_SECRET_BACKEND")
	t.Setenv("CICADA_AES_MASTER_KEY", "12345678901234567890123456789012")
	b, err := NewBackend()
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	if b.Name() != "env" {
		t.Errorf("Name() = %q, want env", b.Name())
	}
}

func TestNewBackend_ExplicitEnv(t *testing.T) {
	t.Setenv("CICADA_SECRET_BACKEND", "env")
	t.Setenv("CICADA_AES_MASTER_KEY", "12345678901234567890123456789012")
	b, err := NewBackend()
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	if b.Name() != "env" {
		t.Errorf("Name() = %q", b.Name())
	}
}

func TestNewBackend_VaultMissingAddr(t *testing.T) {
	t.Setenv("CICADA_SECRET_BACKEND", "vault")
	os.Unsetenv("CICADA_VAULT_ADDR")
	_, err := NewBackend()
	if err == nil {
		t.Error("expected error when CICADA_VAULT_ADDR is missing")
	}
}

func TestNewBackend_VaultMissingToken(t *testing.T) {
	t.Setenv("CICADA_SECRET_BACKEND", "vault")
	t.Setenv("CICADA_VAULT_ADDR", "https://vault.example.com:8200")
	os.Unsetenv("CICADA_VAULT_TOKEN")
	_, err := NewBackend()
	if err == nil {
		t.Error("expected error when CICADA_VAULT_TOKEN is missing")
	}
}

func TestNewBackend_VaultSuccess(t *testing.T) {
	t.Setenv("CICADA_SECRET_BACKEND", "vault")
	t.Setenv("CICADA_VAULT_ADDR", "https://vault.example.com:8200")
	t.Setenv("CICADA_VAULT_TOKEN", "s.test-token-123")
	b, err := NewBackend()
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	if b.Name() != "vault" {
		t.Errorf("Name() = %q, want vault", b.Name())
	}
}

func TestNewBackend_AWSRejected(t *testing.T) {
	t.Setenv("CICADA_SECRET_BACKEND", "aws")
	_, err := NewBackend()
	if err == nil {
		t.Error("expected error for removed aws backend")
	}
}

func TestNewBackend_UnknownBackend(t *testing.T) {
	t.Setenv("CICADA_SECRET_BACKEND", "gcp")
	_, err := NewBackend()
	if err == nil {
		t.Error("expected error for unknown backend")
	}
}

// ── EnvBackend Tests ─────────────────────────────────────────────────────────

func TestEnvBackend_EncryptDecryptRoundtrip(t *testing.T) {
	t.Setenv("CICADA_AES_MASTER_KEY", "12345678901234567890123456789012")
	b, err := NewEnvBackend()
	if err != nil {
		t.Fatalf("NewEnvBackend: %v", err)
	}

	ctx := context.Background()
	plaintext := "sk_live_testkey123456789"
	tenantID := "tenant-abc"

	cipher, err := b.Encrypt(ctx, plaintext, tenantID)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if cipher == "" || cipher == plaintext {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := b.Decrypt(ctx, cipher, tenantID)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Decrypt = %q, want %q", decrypted, plaintext)
	}
}

func TestEnvBackend_CrossTenantDecryptFails(t *testing.T) {
	t.Setenv("CICADA_AES_MASTER_KEY", "12345678901234567890123456789012")
	b, _ := NewEnvBackend()
	ctx := context.Background()

	cipher, _ := b.Encrypt(ctx, "secret", "tenant-A")
	_, err := b.Decrypt(ctx, cipher, "tenant-B")
	if err == nil {
		t.Error("cross-tenant decrypt should fail")
	}
}

func TestEnvBackend_Health(t *testing.T) {
	t.Setenv("CICADA_AES_MASTER_KEY", "12345678901234567890123456789012")
	b, _ := NewEnvBackend()
	if err := b.Health(context.Background()); err != nil {
		t.Errorf("Health: %v", err)
	}
}

func TestEnvBackend_GetSecretFromEnv(t *testing.T) {
	t.Setenv("CICADA_AES_MASTER_KEY", "12345678901234567890123456789012")
	t.Setenv("CICADA_TEST_SECRET", "hello-world")
	b, _ := NewEnvBackend()

	val, err := b.GetSecret(context.Background(), "CICADA_TEST_SECRET")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if val != "hello-world" {
		t.Errorf("got %q", val)
	}
}

func TestEnvBackend_GetSecretNotFound(t *testing.T) {
	t.Setenv("CICADA_AES_MASTER_KEY", "12345678901234567890123456789012")
	b, _ := NewEnvBackend()
	_, err := b.GetSecret(context.Background(), "NONEXISTENT_SECRET")
	if err == nil {
		t.Error("expected error for missing secret")
	}
}

// ── VaultBackend Tests ───────────────────────────────────────────────────────

func TestVaultBackend_Defaults(t *testing.T) {
	t.Setenv("CICADA_VAULT_ADDR", "https://vault.example.com")
	t.Setenv("CICADA_VAULT_TOKEN", "s.testtoken")
	os.Unsetenv("CICADA_VAULT_TRANSIT_KEY")
	os.Unsetenv("CICADA_VAULT_MOUNT_PATH")

	b, err := NewVaultBackend()
	if err != nil {
		t.Fatalf("NewVaultBackend: %v", err)
	}
	if b.transitKey != "cicada-sentry" {
		t.Errorf("transitKey = %q, want cicada-sentry", b.transitKey)
	}
	if b.mountPath != "transit" {
		t.Errorf("mountPath = %q, want transit", b.mountPath)
	}
}

func TestVaultBackend_CustomConfig(t *testing.T) {
	t.Setenv("CICADA_VAULT_ADDR", "https://vault.prod.internal")
	t.Setenv("CICADA_VAULT_TOKEN", "s.prodtoken")
	t.Setenv("CICADA_VAULT_TRANSIT_KEY", "prod-key")
	t.Setenv("CICADA_VAULT_MOUNT_PATH", "pki")

	b, _ := NewVaultBackend()
	if b.transitKey != "prod-key" {
		t.Errorf("transitKey = %q", b.transitKey)
	}
	if b.mountPath != "pki" {
		t.Errorf("mountPath = %q", b.mountPath)
	}
}

// ── Utility Tests ────────────────────────────────────────────────────────────

func TestExtractVaultField_Found(t *testing.T) {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"ciphertext": "vault:v1:abc123",
		},
	}
	val, ok := extractVaultField(resp, "ciphertext")
	if !ok || val != "vault:v1:abc123" {
		t.Errorf("got %q, ok=%v", val, ok)
	}
}

func TestExtractVaultField_Missing(t *testing.T) {
	resp := map[string]interface{}{
		"data": map[string]interface{}{},
	}
	_, ok := extractVaultField(resp, "ciphertext")
	if ok {
		t.Error("should not find missing field")
	}
}

func TestExtractVaultField_NilResponse(t *testing.T) {
	_, ok := extractVaultField(nil, "ciphertext")
	if ok {
		t.Error("should not find field in nil response")
	}
}

func TestExtractVaultField_WrongType(t *testing.T) {
	resp := map[string]interface{}{
		"data": "not a map",
	}
	_, ok := extractVaultField(resp, "ciphertext")
	if ok {
		t.Error("should fail when data is not a map")
	}
}
