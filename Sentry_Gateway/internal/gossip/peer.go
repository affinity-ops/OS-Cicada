// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gossip

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/asai/cicada/sentry/pkg/pqc"
)

// PeerIdentity represents a known gossip peer with both classical (Ed25519)
// and post-quantum (ML-DSA-65) public keys for dual-signature verification.
// This mirrors the hybrid PQC pattern used by the license enforcer and
// the mobile device pairing system.
type PeerIdentity struct {
	NodeID     string `json:"node_id"`
	TenantID   string `json:"tenant_id"`
	Endpoint   string `json:"endpoint"`
	Ed25519Pub string `json:"ed25519_pub"`           // base64-encoded Ed25519 public key (32 bytes)
	MlDsa65Pub string `json:"ml_dsa65_pub,omitempty"` // base64-encoded ML-DSA-65 public key (~1,952 bytes) — optional during rollout
}

// PeerRegistry holds known gossip peers and provides thread-safe lookup.
// Peers can be loaded from a JSON config file or dynamically added via
// the mesh directory service (Phase 4).
type PeerRegistry struct {
	mu    sync.RWMutex
	peers map[string]*PeerIdentity // keyed by NodeID
}

// NewPeerRegistry creates an empty peer registry.
func NewPeerRegistry() *PeerRegistry {
	return &PeerRegistry{
		peers: make(map[string]*PeerIdentity),
	}
}

// Lookup returns the PeerIdentity for the given node ID, or nil if unknown.
func (r *PeerRegistry) Lookup(nodeID string) *PeerIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.peers[nodeID]
}

// Register adds or updates a peer in the registry.
func (r *PeerRegistry) Register(peer *PeerIdentity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers[peer.NodeID] = peer
	log.Printf("[GOSSIP] Registered peer %s (tenant: %s, endpoint: %s, pqc: %v)",
		peer.NodeID, peer.TenantID, peer.Endpoint, peer.MlDsa65Pub != "")
}

// Endpoints returns the list of all peer gossip receive URLs.
// Used by shipCompressedBatch to push gossip to all known peers.
func (r *PeerRegistry) Endpoints() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.peers))
	for _, p := range r.peers {
		if p.Endpoint != "" {
			out = append(out, p.Endpoint)
		}
	}
	return out
}

// Count returns the number of registered peers.
func (r *PeerRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}

// LoadPeersFromConfig reads a JSON file containing an array of PeerIdentity
// objects and populates the registry. The config file path is typically
// set via CICADA_GOSSIP_PEERS_CONFIG environment variable.
func (r *PeerRegistry) LoadPeersFromConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read peer config %s: %w", path, err)
	}

	var peers []PeerIdentity
	if err := json.Unmarshal(data, &peers); err != nil {
		return fmt.Errorf("failed to parse peer config %s: %w", path, err)
	}

	for i := range peers {
		r.Register(&peers[i])
	}

	log.Printf("[GOSSIP] Loaded %d peers from config %s", len(peers), path)
	return nil
}

// ─── Dual-Signature Signing (Ed25519 + ML-DSA-65) ───────────────────────────

// SignBatch dual-signs a compressed gossip batch payload using both Ed25519
// and ML-DSA-65 (if available). This mirrors the license enforcement pattern
// in enforcer.go: both signatures must be valid for the batch to be accepted.
//
// Parameters:
//   - payload: the compressed gossip batch bytes
//   - edPriv: the local node's Ed25519 private key
//   - mldsaPrivB64: the local node's ML-DSA-65 private key (base64), or "" if PQC not configured
//
// Returns:
//   - edSigB64: base64-encoded Ed25519 signature (64 bytes)
//   - mldsaSigB64: base64-encoded ML-DSA-65 signature (3309 bytes), or "" if PQC not configured
func SignBatch(payload []byte, edPriv ed25519.PrivateKey, mldsaPrivB64 string) (edSigB64, mldsaSigB64 string) {
	// Classical Ed25519 signature (always required)
	edSig := ed25519.Sign(edPriv, payload)
	edSigB64 = base64.StdEncoding.EncodeToString(edSig)

	// Post-quantum ML-DSA-65 signature (if PQC key is configured)
	if mldsaPrivB64 != "" {
		sig, err := pqc.SignMLDSA65(mldsaPrivB64, payload)
		if err != nil {
			log.Printf("[GOSSIP] WARNING: ML-DSA-65 signing failed: %v — batch will be sent with Ed25519-only", err)
			return edSigB64, ""
		}
		mldsaSigB64 = sig
	}

	return edSigB64, mldsaSigB64
}

// ─── Dual-Signature Verification ────────────────────────────────────────────

// VerifyBatchSignature verifies a gossip batch against a known peer's public keys.
//
// Verification rules (mirroring license enforcement):
//   - Ed25519 signature MUST always be valid (hard requirement)
//   - ML-DSA-65 signature MUST be valid IF the peer has a PQC public key registered
//   - If the peer has no PQC key (pre-upgrade node), Ed25519-only is accepted
//   - If BOTH signatures are required and either fails, the batch is rejected
//
// Returns nil if verification passes, or an error describing the failure.
func VerifyBatchSignature(payload []byte, peer *PeerIdentity, edSigB64, mldsaSigB64 string) error {
	// ── 1. Verify Ed25519 (always required) ──────────────────────────────
	edPubBytes, err := base64.StdEncoding.DecodeString(peer.Ed25519Pub)
	if err != nil {
		return fmt.Errorf("peer %s: invalid Ed25519 public key encoding: %w", peer.NodeID, err)
	}
	if len(edPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("peer %s: Ed25519 public key size mismatch: got %d, expected %d",
			peer.NodeID, len(edPubBytes), ed25519.PublicKeySize)
	}

	edSigBytes, err := base64.StdEncoding.DecodeString(edSigB64)
	if err != nil {
		return fmt.Errorf("peer %s: invalid Ed25519 signature encoding: %w", peer.NodeID, err)
	}

	if !ed25519.Verify(ed25519.PublicKey(edPubBytes), payload, edSigBytes) {
		return fmt.Errorf("peer %s: Ed25519 signature verification FAILED", peer.NodeID)
	}

	// ── 2. Verify ML-DSA-65 (if peer has PQC key) ───────────────────────
	if peer.MlDsa65Pub != "" {
		if mldsaSigB64 == "" {
			return fmt.Errorf("peer %s: peer has PQC key registered but batch has no ML-DSA-65 signature", peer.NodeID)
		}
		if err := pqc.VerifyMLDSA65(peer.MlDsa65Pub, payload, mldsaSigB64); err != nil {
			return fmt.Errorf("peer %s: ML-DSA-65 verification FAILED: %w", peer.NodeID, err)
		}
	}

	return nil
}
