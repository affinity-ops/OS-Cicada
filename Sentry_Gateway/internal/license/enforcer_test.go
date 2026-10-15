// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"os"
	"testing"
	"time"
)

func TestMeshAllowed(t *testing.T) {
	// Backup original state
	origActiveLicense := ActiveLicense
	defer func() { ActiveLicense = origActiveLicense }()

	// Case 1: ActiveLicense is nil
	ActiveLicense = nil
	if MeshAllowed() {
		t.Error("MeshAllowed() should return false when ActiveLicense is nil")
	}

	// Case 2: MeshAccess is true
	ActiveLicense = &LicenseClaims{
		MeshAccess: true,
	}
	if !MeshAllowed() {
		t.Error("MeshAllowed() should return true when ActiveLicense.MeshAccess is true")
	}

	// Case 3: MeshAccess is false
	ActiveLicense = &LicenseClaims{
		MeshAccess: false,
	}
	if MeshAllowed() {
		t.Error("MeshAllowed() should return false when ActiveLicense.MeshAccess is false")
	}
}

func TestGetMeshTier(t *testing.T) {
	// Backup original state
	origActiveLicense := ActiveLicense
	defer func() { ActiveLicense = origActiveLicense }()

	// Case 1: ActiveLicense is nil
	ActiveLicense = nil
	if tier := GetMeshTier(); tier != "standalone" {
		t.Errorf("GetMeshTier() should return 'standalone' when ActiveLicense is nil, got %s", tier)
	}

	// Case 2: MeshTier is empty string
	ActiveLicense = &LicenseClaims{
		MeshTier: "",
	}
	if tier := GetMeshTier(); tier != "standalone" {
		t.Errorf("GetMeshTier() should return 'standalone' when MeshTier is empty, got %s", tier)
	}

	// Case 3: MeshTier is set to "connected"
	ActiveLicense = &LicenseClaims{
		MeshTier: "connected",
	}
	if tier := GetMeshTier(); tier != "connected" {
		t.Errorf("GetMeshTier() should return 'connected' when MeshTier is 'connected', got %s", tier)
	}

	// Case 4: MeshTier is set to "enterprise"
	ActiveLicense = &LicenseClaims{
		MeshTier: "enterprise",
	}
	if tier := GetMeshTier(); tier != "enterprise" {
		t.Errorf("GetMeshTier() should return 'enterprise' when MeshTier is 'enterprise', got %s", tier)
	}
}

func TestGetMaxAgents(t *testing.T) {
	// Backup original state
	origActiveLicense := ActiveLicense
	defer func() { ActiveLicense = origActiveLicense }()

	// Case 1: ActiveLicense is nil
	ActiveLicense = nil
	if max := GetMaxAgents(); max != 0 {
		t.Errorf("GetMaxAgents() should return 0 when ActiveLicense is nil, got %d", max)
	}

	// Case 2: MaxAgents is set
	ActiveLicense = &LicenseClaims{
		MaxAgents: 42,
	}
	if max := GetMaxAgents(); max != 42 {
		t.Errorf("GetMaxAgents() should return 42, got %d", max)
	}
}

func TestDevModeBypass(t *testing.T) {
	// Backup original state
	origActiveLicense := ActiveLicense
	defer func() { ActiveLicense = origActiveLicense }()

	// Backup environment
	origDevMode := os.Getenv("CICADA_DEV_MODE")
	defer os.Setenv("CICADA_DEV_MODE", origDevMode)

	// Set dev mode to true
	os.Setenv("CICADA_DEV_MODE", "true")

	// Call EnforceOrDie with arbitrary path (should bypass and not read file)
	ActiveLicense = nil
	EnforceOrDie("non_existent_file.lic")

	if ActiveLicense == nil {
		t.Fatal("EnforceOrDie did not set ActiveLicense under CICADA_DEV_MODE")
	}

	if ActiveLicense.TenantID != "dev-tenant" {
		t.Errorf("Expected TenantID 'dev-tenant', got %s", ActiveLicense.TenantID)
	}
	if ActiveLicense.MaxAgents != 9999 {
		t.Errorf("Expected MaxAgents 9999, got %d", ActiveLicense.MaxAgents)
	}
	if !ActiveLicense.MeshAccess {
		t.Error("Expected MeshAccess to be true")
	}
	if ActiveLicense.MeshTier != "enterprise" {
		t.Errorf("Expected MeshTier 'enterprise', got %s", ActiveLicense.MeshTier)
	}
	if ActiveLicense.Tier != "enterprise" {
		t.Errorf("Expected Tier 'enterprise', got %s", ActiveLicense.Tier)
	}
	if ActiveLicense.ExpiresAt.Before(time.Now()) {
		t.Error("Expected license to be valid (not expired)")
	}
}
