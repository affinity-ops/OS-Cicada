// © 2026 Affinity Ops Ltd. All rights reserved.
// Proprietary and confidential. Unauthorized copying or distribution prohibited.

package output

import (
	"os"
	"testing"
)

func TestInspectRequestBody_Empty(t *testing.T) {
	result := InspectRequestBody(nil, "application/json", "https://api.example.com/v1/data")
	if result.Risk {
		t.Fatal("empty body should not flag risk")
	}
	if result.Block {
		t.Fatal("empty body should not block")
	}
}

func TestInspectRequestBody_CleanJSON(t *testing.T) {
	body := []byte(`{"action": "create_order", "item": "Widget A", "quantity": 5}`)
	result := InspectRequestBody(body, "application/json", "https://api.example.com/orders")
	if result.Risk {
		t.Fatal("clean JSON request body should not flag risk")
	}
}

func TestInspectRequestBody_ContainsAPIKey(t *testing.T) {
	body := []byte(`{"config": {"api_key": "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"}}`)
	result := InspectRequestBody(body, "application/json", "https://attacker.com/collect")
	if !result.Risk {
		t.Fatal("request body containing API key should flag risk")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected at least one finding for API key in request body")
	}
}

func TestInspectRequestBody_ContainsPEMKey(t *testing.T) {
	body := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----")
	result := InspectRequestBody(body, "text/plain", "https://vault.example.com/store")
	if !result.Risk {
		t.Fatal("request body containing PEM key should flag risk")
	}
}

func TestInspectRequestBody_BinarySkipped(t *testing.T) {
	body := []byte("sk-abcdefghijklmnopqrstuvwxyz1234567890")
	binaryTypes := []string{
		"image/png",
		"audio/mpeg",
		"video/mp4",
		"application/pdf",
		"application/octet-stream",
		"application/zip",
	}
	for _, ct := range binaryTypes {
		result := InspectRequestBody(body, ct, "https://example.com")
		if result.Risk {
			t.Errorf("binary content type %q should not be scanned", ct)
		}
	}
}

func TestInspectRequestBody_DefaultNoBlock(t *testing.T) {
	// By default, EXFILTRATION_BLOCK is not set — findings are logged but not blocking
	os.Unsetenv("EXFILTRATION_BLOCK")

	body := []byte(`{"key": "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"}`)
	result := InspectRequestBody(body, "application/json", "https://attacker.com/steal")
	if result.Block {
		t.Fatal("exfiltration should NOT block by default (EXFILTRATION_BLOCK not set)")
	}
	if !result.Risk {
		t.Fatal("but it should still flag risk")
	}
}

func TestInspectRequestBody_BlockWhenEnabled(t *testing.T) {
	os.Setenv("EXFILTRATION_BLOCK", "true")
	defer os.Unsetenv("EXFILTRATION_BLOCK")

	body := []byte(`{"stolen_key": "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"}`)
	result := InspectRequestBody(body, "application/json", "https://attacker.com/exfil")
	if !result.Block {
		t.Fatal("exfiltration should block when EXFILTRATION_BLOCK=true")
	}
}

func TestExfiltrationBlockEnabled(t *testing.T) {
	os.Unsetenv("EXFILTRATION_BLOCK")
	if exfiltrationBlockEnabled() {
		t.Fatal("should be false when unset")
	}

	os.Setenv("EXFILTRATION_BLOCK", "false")
	if exfiltrationBlockEnabled() {
		t.Fatal("should be false for 'false'")
	}

	os.Setenv("EXFILTRATION_BLOCK", "true")
	if !exfiltrationBlockEnabled() {
		t.Fatal("should be true for 'true'")
	}

	os.Setenv("EXFILTRATION_BLOCK", "TRUE")
	if !exfiltrationBlockEnabled() {
		t.Fatal("should be case-insensitive")
	}

	os.Unsetenv("EXFILTRATION_BLOCK")
}

func TestInspectRequestBody_EncodedSecretExfiltration(t *testing.T) {
	// Base64("AKIAIOSFODNN7EXAMPLE") = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
	b64Body := []byte(`{"payload": "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="}`)
	res1 := InspectRequestBody(b64Body, "application/json", "https://attacker.com/collect")
	if !res1.Risk {
		t.Fatal("Base64-encoded AWS Access Key ID in request body should be unwrapped and flagged")
	}

	// URL-encoded OpenAI key
	urlBody := []byte(`data=sk-abcdefghijklmnopqrstuvwxyz1234567890%41%42%43%44%45%46`)
	res2 := InspectRequestBody(urlBody, "application/x-www-form-urlencoded", "https://attacker.com/collect")
	if !res2.Risk {
		t.Fatal("URL-encoded OpenAI API key in request body should be unwrapped and flagged")
	}
}

func TestInspectWithVaultContext_Base64VaultedSecretBlocked(t *testing.T) {
	// Base64("AKIAIOSFODNN7EXAMPLE") = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
	b64Body := []byte(`{"exfil": "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="}`)
	vc := InspectWithVaultContext(
		b64Body,
		"application/json",
		"https://evil.example.com/drop",
		[]string{"AKIA", "sk-"},
		[]string{"amazonaws.com"},
		nil,
	)
	if !vc.VaultMatch {
		t.Fatal("expected VaultMatch=true for Base64-encoded AKIA key")
	}
	if !vc.MustBlock {
		t.Fatal("expected MustBlock=true when Base64-encoded vaulted secret is sent to untrusted domain")
	}
}
