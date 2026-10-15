// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", "mint_test_bin", "main.go")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build binary for testing: %v", err)
	}
}

func cleanupBinary() {
	exec.Command("rm", "-f", "mint_test_bin").Run()
}

func TestLicenseMintingCLI(t *testing.T) {
	buildBinary(t)
	defer cleanupBinary()

	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Root license with no root tenant (Valid)",
			args:        []string{"-tenant", "HQ_Corp", "-license-tier", "root", "-keys", "../../master_keys.json"},
			expectError: false,
		},
		{
			name:        "Root license with root tenant (Invalid)",
			args:        []string{"-tenant", "HQ_Corp", "-license-tier", "root", "-root-tenant", "SomeOtherHQ", "-keys", "../../master_keys.json"},
			expectError: true,
			errorMsg:    "--root-tenant must be empty when --license-tier is 'root'",
		},
		{
			name:        "Subsidiary license without root tenant (Invalid)",
			args:        []string{"-tenant", "Sub_Corp", "-license-tier", "subsidiary", "-keys", "../../master_keys.json"},
			expectError: true,
			errorMsg:    "--root-tenant is required when --license-tier is 'subsidiary'",
		},
		{
			name:        "Subsidiary license with root tenant (Valid)",
			args:        []string{"-tenant", "Sub_Corp", "-license-tier", "subsidiary", "-root-tenant", "HQ_Corp", "-keys", "../../master_keys.json"},
			expectError: false,
		},
		{
			name:        "Invalid license tier",
			args:        []string{"-tenant", "HQ_Corp", "-license-tier", "bogus"},
			expectError: true,
			errorMsg:    "--license-tier must be either 'root' or 'subsidiary'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("./mint_test_bin", tt.args...)
			output, err := cmd.CombinedOutput()
			outStr := string(output)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected an error but got none. Output: %s", outStr)
				}
				if !strings.Contains(outStr, tt.errorMsg) {
					t.Errorf("Expected error message containing '%s', got '%s'", tt.errorMsg, outStr)
				}
			} else {
				if err != nil {
					t.Errorf("Expected success but got error: %v. Output: %s", err, outStr)
				}
				// Cleanup generated lic
				for i, arg := range tt.args {
					if arg == "-tenant" && i+1 < len(tt.args) {
						exec.Command("rm", "-f", tt.args[i+1]+".lic").Run()
					}
				}
			}
		})
	}
}
