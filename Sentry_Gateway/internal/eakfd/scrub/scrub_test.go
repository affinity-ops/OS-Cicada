// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package scrub

import (
	"strings"
	"testing"
)

func TestScrub_AWSAccessKey(t *testing.T) {
	input := "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	result := Scrub(input)

	if strings.Contains(result.Output, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS access key was not redacted")
	}
	if !strings.Contains(result.Output, redactionTag) {
		t.Error("expected redaction tag in output")
	}
	if len(result.RedactedKeys) == 0 {
		t.Error("expected at least one redacted key in telemetry")
	}
}

func TestScrub_DatabaseURI(t *testing.T) {
	input := `DATABASE_URL=postgresql://admin:s3cret_p4ss@10.0.1.50:5432/production`
	result := Scrub(input)

	if strings.Contains(result.Output, "s3cret_p4ss") {
		t.Error("database password was not redacted")
	}
	if strings.Contains(result.Output, "10.0.1.50") {
		t.Error("private IP in database URI was not redacted")
	}
}

func TestScrub_PrivateIPs(t *testing.T) {
	input := "Connected to server at 192.168.1.100 and 10.0.0.1, public at 54.23.1.1"
	result := Scrub(input)

	if strings.Contains(result.Output, "192.168.1.100") {
		t.Error("192.168.x IP was not redacted")
	}
	if strings.Contains(result.Output, "10.0.0.1") {
		t.Error("10.x IP was not redacted")
	}
	if !strings.Contains(result.Output, "54.23.1.1") {
		t.Error("public IP should NOT be redacted")
	}
	if len(result.RedactedIPs) != 2 {
		t.Errorf("expected 2 redacted IPs, got %d", len(result.RedactedIPs))
	}
}

func TestScrub_AWSIMDSAddress(t *testing.T) {
	input := "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	result := Scrub(input)

	if strings.Contains(result.Output, "169.254.169.254") {
		t.Error("IMDS address (169.254.x) was not redacted")
	}
}

func TestScrub_SSHPrivateKey(t *testing.T) {
	input := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
	result := Scrub(input)

	if strings.Contains(result.Output, "BEGIN RSA PRIVATE KEY") {
		t.Error("SSH private key header was not redacted")
	}
}

func TestScrub_GitHubToken(t *testing.T) {
	input := "GITHUB_TOKEN=ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234"
	result := Scrub(input)

	if strings.Contains(result.Output, "ghp_ABCDEFGHIJ") {
		t.Error("GitHub token was not redacted")
	}
}

func TestScrub_BearerToken(t *testing.T) {
	input := `Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature`
	result := Scrub(input)

	if strings.Contains(result.Output, "eyJhbGci") {
		t.Error("Bearer token was not redacted")
	}
}

func TestScrub_EnvExport(t *testing.T) {
	input := `export DB_PASSWORD="hunter2_production_key"`
	result := Scrub(input)

	if strings.Contains(result.Output, "hunter2") {
		t.Error("exported DB_PASSWORD was not redacted")
	}
}

func TestScrub_CleanOutput(t *testing.T) {
	input := "Cluster created successfully. 12 resources added, 0 changed, 0 destroyed."
	result := Scrub(input)

	if result.Output != input {
		t.Errorf("clean output was modified: got %q", result.Output)
	}
	if len(result.RedactedKeys) != 0 {
		t.Error("expected zero redacted keys for clean output")
	}
	if len(result.RedactedIPs) != 0 {
		t.Error("expected zero redacted IPs for clean output")
	}
}

func TestScrub_MultiplePatterns(t *testing.T) {
	input := `export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
Connecting to 192.168.0.50:5432...
Token: ghp_` + `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234
Done.`
	result := Scrub(input)

	if strings.Contains(result.Output, "wJalrXUtnFEMI") {
		t.Error("AWS secret key was not redacted")
	}
	if strings.Contains(result.Output, "192.168.0.50") {
		t.Error("private IP was not redacted")
	}
	if strings.Contains(result.Output, "ghp_ABCDEFGHIJ") {
		t.Error("GitHub token was not redacted")
	}
	if !strings.Contains(result.Output, "Done.") {
		t.Error("clean text was incorrectly modified")
	}
}
