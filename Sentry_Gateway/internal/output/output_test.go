// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"strings"
	"testing"
)

func TestInspect_CredentialPatterns(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantBlock bool
		wantDesc  string
	}{
		{
			name:      "OpenAI API key",
			body:      `{"key": "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"}`,
			wantBlock: true,
			wantDesc:  "OpenAI API key",
		},
		{
			name:      "Anthropic API key",
			body:      `{"key": "sk-ant-api03-verylongkeyvaluehere1234567890abcdef"}`,
			wantBlock: true,
			wantDesc:  "Anthropic API key",
		},
		{
			name:      "AWS access key",
			body:      `{"aws_key": "AKIAIOSFODNN7EXAMPLE123456"}`,
			wantBlock: true,
			wantDesc:  "AWS access key ID",
		},
		{
			name:      "PEM private key",
			body:      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...",
			wantBlock: true,
			wantDesc:  "PEM private key block",
		},
		{
			name:      "credential JSON field",
			body:      `{"token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.secretstuff"}`,
			wantBlock: true,
			wantDesc:  "credential field in JSON response",
		},
		{
			name:      "Stripe secret key",
			body:      `{"key": "sk_` + `live_abcdefghijklmnopqrstuvwx"}`,
			wantBlock: true,
			wantDesc:  "Stripe secret key",
		},
		{
			name:      "GitHub PAT",
			body:      `{"token": "ghp_` + `abcdefghijklmnopqrstuvwxyz12345678901"}`,
			wantBlock: true,
			wantDesc:  "GitHub personal access token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := Inspect([]byte(tc.body), "application/json", int64(len(tc.body)))
			if result.Block != tc.wantBlock {
				t.Errorf("Block = %v, want %v", result.Block, tc.wantBlock)
			}
			found := false
			for _, f := range result.Findings {
				if f.Pattern == tc.wantDesc {
					found = true
				}
			}
			if !found {
				t.Errorf("Expected finding %q not found. Got: %v", tc.wantDesc, result.Findings)
			}
		})
	}
}

func TestInspect_VolumeLimit(t *testing.T) {
	// Responses exceeding the limit are blocked regardless of content
	huge := strings.Repeat("a", int(maxBodyBytes())+1)
	result := Inspect([]byte(huge), "application/json", int64(len(huge)))
	if !result.Block {
		t.Error("Oversized response must be blocked")
	}
	if result.Findings[0].Category != "volume" {
		t.Errorf("Expected volume finding, got: %v", result.Findings[0].Category)
	}
}

func TestInspect_BinaryContentSkipped(t *testing.T) {
	// Binary content types must not be pattern-scanned
	binaryTypes := []string{
		"image/png",
		"image/jpeg",
		"audio/mpeg",
		"video/mp4",
		"application/pdf",
		"application/octet-stream",
		"application/zip",
		"application/gzip",
	}
	body := []byte("sk-abcdefghijklmnopqrstuvwxyz1234567890") // looks like a key
	for _, ct := range binaryTypes {
		result := Inspect(body, ct, int64(len(body)))
		if result.Block {
			t.Errorf("Binary content-type %q must not trigger pattern scan block", ct)
		}
	}
}

func TestInspect_MediumSeverityNotBlocking(t *testing.T) {
	// Email address in a confirmation response — should log, not block
	body := []byte(`{"message": "Confirmation sent to user@example.com", "status": "ok"}`)
	result := Inspect(body, "application/json", int64(len(body)))
	if result.Block {
		t.Error("Single email address should not block (medium severity)")
	}
	if len(result.Findings) == 0 {
		t.Error("Email should produce a finding even if not blocking")
	}
}

func TestInspect_CleanResponse(t *testing.T) {
	body := []byte(`{"status": "ok", "order_id": "12345", "shipped": true}`)
	result := Inspect(body, "application/json", int64(len(body)))
	if result.Block {
		t.Error("Clean response must not block")
	}
	if len(result.Findings) > 0 {
		t.Errorf("Clean response must have no findings, got: %v", result.Findings)
	}
	if result.RiskScore != 0 {
		t.Errorf("Clean response risk score must be 0, got: %f", result.RiskScore)
	}
}

func TestShouldBlockOnContentLength(t *testing.T) {
	limit := maxBodyBytes()
	if ShouldBlockOnContentLength(limit + 1) != true {
		t.Error("Content-Length above limit should block")
	}
	if ShouldBlockOnContentLength(limit) != false {
		t.Error("Content-Length at limit should not block")
	}
	if ShouldBlockOnContentLength(0) != false {
		t.Error("Content-Length of 0 (unknown) should not block")
	}
	if ShouldBlockOnContentLength(-1) != false {
		t.Error("Content-Length of -1 (unknown) should not block")
	}
}

func TestFindingsSummary(t *testing.T) {
	findings := []Finding{
		{Category: "credential", Pattern: "OpenAI API key", Severity: "critical"},
		{Category: "pii", Pattern: "email address", Severity: "medium"},
	}
	s := FindingsSummary(findings)
	if s != "credential:OpenAI API key, pii:email address" {
		t.Errorf("Unexpected summary: %s", s)
	}
}

func BenchmarkInspect_TypicalAPIResponse(b *testing.B) {
	body := []byte(`{"status":"success","data":{"id":"order_123","customer":"Jane Doe","total":99.99,"items":[{"sku":"WIDGET-A","qty":2}]}}`)
	ct := "application/json"
	size := int64(len(body))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Inspect(body, ct, size)
	}
}
