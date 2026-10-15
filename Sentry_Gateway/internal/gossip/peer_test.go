// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gossip

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/asai/cicada/sentry/pkg/pqc"
)

// helper: generate a fresh Ed25519 keypair for testing
func genEd25519() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func TestPeerDualSignatureVerification(t *testing.T) {
	// Generate Ed25519 keypair
	pub, priv := genEd25519()
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	// Generate ML-DSA-65 keypair
	mldsaPubB64, mldsaPrivB64, err := pqc.GenerateMLDSA65Keypair()
	if err != nil {
		t.Fatalf("ML-DSA-65 keygen failed: %v", err)
	}

	peer := &PeerIdentity{
		NodeID:     "test-peer-1",
		TenantID:   "tenant-alpha",
		Ed25519Pub: pubB64,
		MlDsa65Pub: mldsaPubB64,
	}

	payload := []byte("compressed gossip batch data for testing dual signatures")

	// Sign with both keys
	edSig, mldsaSig := SignBatch(payload, priv, mldsaPrivB64)

	// Verify — must pass
	if err := VerifyBatchSignature(payload, peer, edSig, mldsaSig); err != nil {
		t.Errorf("Dual signature verification should pass: %v", err)
	}
}

func TestPeerEd25519OnlyFallback(t *testing.T) {
	// Peer has no ML-DSA-65 key (pre-upgrade node) — Ed25519-only should work
	pub, priv := genEd25519()
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	peer := &PeerIdentity{
		NodeID:     "legacy-peer",
		TenantID:   "tenant-alpha",
		Ed25519Pub: pubB64,
		MlDsa65Pub: "", // no PQC key
	}

	payload := []byte("legacy gossip batch")
	edSig, _ := SignBatch(payload, priv, "") // no PQC key

	if err := VerifyBatchSignature(payload, peer, edSig, ""); err != nil {
		t.Errorf("Ed25519-only fallback should pass for pre-upgrade peer: %v", err)
	}
}

func TestPeerForgedEd25519Rejected(t *testing.T) {
	// Valid ML-DSA-65 but forged Ed25519 — must be rejected
	pub, _ := genEd25519()
	_, attackerPriv := genEd25519() // different key!
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	mldsaPubB64, mldsaPrivB64, _ := pqc.GenerateMLDSA65Keypair()

	peer := &PeerIdentity{
		NodeID:     "peer-with-forged-ed",
		Ed25519Pub: pubB64,
		MlDsa65Pub: mldsaPubB64,
	}

	payload := []byte("batch signed by attacker")
	edSig, mldsaSig := SignBatch(payload, attackerPriv, mldsaPrivB64) // ed25519 signed by wrong key

	err := VerifyBatchSignature(payload, peer, edSig, mldsaSig)
	if err == nil {
		t.Error("Forged Ed25519 signature must be REJECTED even if ML-DSA-65 is valid")
	}
}

func TestPeerForgedMLDSA65Rejected(t *testing.T) {
	// Valid Ed25519 but forged ML-DSA-65 — must be rejected
	pub, priv := genEd25519()
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	mldsaPubB64, _, _ := pqc.GenerateMLDSA65Keypair()        // real public key
	_, attackerMLDSAPrivB64, _ := pqc.GenerateMLDSA65Keypair() // different private key!

	peer := &PeerIdentity{
		NodeID:     "peer-with-forged-pqc",
		Ed25519Pub: pubB64,
		MlDsa65Pub: mldsaPubB64,
	}

	payload := []byte("batch with wrong pqc sig")
	edSig, mldsaSig := SignBatch(payload, priv, attackerMLDSAPrivB64) // ML-DSA signed by wrong key

	err := VerifyBatchSignature(payload, peer, edSig, mldsaSig)
	if err == nil {
		t.Error("Forged ML-DSA-65 signature must be REJECTED even if Ed25519 is valid")
	}
}

func TestUnknownPeerRejected(t *testing.T) {
	registry := NewPeerRegistry()

	// Register one known peer
	registry.Register(&PeerIdentity{
		NodeID:   "known-peer",
		Endpoint: "https://known.internal:8080",
	})

	// Lookup unknown peer — must return nil
	if peer := registry.Lookup("unknown-peer"); peer != nil {
		t.Error("Unknown peer must return nil from registry lookup")
	}

	// Lookup known peer — must return identity
	if peer := registry.Lookup("known-peer"); peer == nil {
		t.Error("Known peer must be found in registry")
	}
}

func TestPeerRegistryLookup(t *testing.T) {
	registry := NewPeerRegistry()

	registry.Register(&PeerIdentity{
		NodeID:   "node-a",
		TenantID: "tenant-1",
		Endpoint: "https://a.internal:8080",
	})
	registry.Register(&PeerIdentity{
		NodeID:   "node-b",
		TenantID: "tenant-2",
		Endpoint: "https://b.internal:8080",
	})

	if registry.Count() != 2 {
		t.Errorf("Expected 2 peers, got %d", registry.Count())
	}

	endpoints := registry.Endpoints()
	if len(endpoints) != 2 {
		t.Errorf("Expected 2 endpoints, got %d", len(endpoints))
	}

	peerA := registry.Lookup("node-a")
	if peerA == nil || peerA.TenantID != "tenant-1" {
		t.Error("Peer A lookup failed")
	}
}

func TestPeerConfigLoad(t *testing.T) {
	// Create a temporary config file
	peers := []PeerIdentity{
		{NodeID: "config-peer-1", TenantID: "t1", Endpoint: "https://peer1:8080", Ed25519Pub: "dGVzdA=="},
		{NodeID: "config-peer-2", TenantID: "t2", Endpoint: "https://peer2:8080", Ed25519Pub: "dGVzdA=="},
	}
	data, _ := json.Marshal(peers)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "peers.json")
	os.WriteFile(configPath, data, 0600)

	registry := NewPeerRegistry()
	if err := registry.LoadPeersFromConfig(configPath); err != nil {
		t.Fatalf("LoadPeersFromConfig failed: %v", err)
	}

	if registry.Count() != 2 {
		t.Errorf("Expected 2 peers loaded from config, got %d", registry.Count())
	}

	peer1 := registry.Lookup("config-peer-1")
	if peer1 == nil || peer1.Endpoint != "https://peer1:8080" {
		t.Error("Peer 1 not correctly loaded from config")
	}
}

func TestPeerMissingPQCSigWhenRequired(t *testing.T) {
	// Peer HAS a PQC public key, but batch arrives with no ML-DSA-65 signature
	// This must be rejected — if the peer is PQC-capable, both sigs are required
	pub, priv := genEd25519()
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	mldsaPubB64, _, _ := pqc.GenerateMLDSA65Keypair()

	peer := &PeerIdentity{
		NodeID:     "pqc-peer-no-sig",
		Ed25519Pub: pubB64,
		MlDsa65Pub: mldsaPubB64, // peer HAS PQC key
	}

	payload := []byte("batch without pqc sig")
	edSig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))

	err := VerifyBatchSignature(payload, peer, edSig, "") // no ML-DSA-65 sig
	if err == nil {
		t.Error("Batch without ML-DSA-65 signature must be REJECTED when peer has PQC key registered")
	}
}
