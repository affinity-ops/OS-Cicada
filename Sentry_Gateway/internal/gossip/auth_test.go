// Copyright 2026 Patrick Matthews and Patrick Matthews (Affinity Ops / Affinity Smart AI)
// SPDX-License-Identifier: Apache-2.0

package gossip

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/asai/cicada/sentry/pkg/pqc"
)

func newPeer(t *testing.T, nodeID string, withPQC bool) (*PeerIdentity, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &PeerIdentity{NodeID: nodeID, Ed25519Pub: base64.StdEncoding.EncodeToString(pub)}
	mldsaPriv := ""
	if withPQC {
		mpub, mpriv, err := pqc.GenerateMLDSA65Keypair()
		if err != nil {
			t.Fatal(err)
		}
		p.MlDsa65Pub = mpub
		mldsaPriv = mpriv
	}
	return p, priv, mldsaPriv
}

func TestAuthenticateBatch(t *testing.T) {
	payload := []byte("tenant|agent-1|ACTIVE|123|node-a\n")

	peerA, privA, mldsaA := newPeer(t, "node-a", true)
	_, privEvil, _ := newPeer(t, "node-evil", false)
	reg := NewPeerRegistry()
	reg.Register(peerA)

	edOK, mlOK := SignBatch(payload, privA, mldsaA)
	edEvil, _ := SignBatch(payload, privEvil, "")

	cases := []struct {
		name    string
		auth    BatchAuth
		reg     *PeerRegistry
		secret  string
		devLoop bool
		wantErr bool
	}{
		{"valid hybrid signature from registered peer", BatchAuth{NodeID: "node-a", EdSig: edOK, MLDSASig: mlOK}, reg, "", false, false},
		{"PQC peer missing ML-DSA signature is rejected", BatchAuth{NodeID: "node-a", EdSig: edOK}, reg, "", false, true},
		{"signature from wrong key is rejected", BatchAuth{NodeID: "node-a", EdSig: edEvil}, reg, "", false, true},
		{"unknown peer is rejected", BatchAuth{NodeID: "node-evil", EdSig: edEvil}, reg, "", false, true},
		{"unsigned batch rejected once registry exists, even with valid HMAC", BatchAuth{NodeID: "node-a", HMAC: ComputeHMAC(payload, "s3cret")}, reg, "s3cret", false, true},
		{"valid HMAC accepted in legacy mode", BatchAuth{HMAC: ComputeHMAC(payload, "s3cret")}, nil, "s3cret", false, false},
		{"wrong HMAC rejected", BatchAuth{HMAC: ComputeHMAC(payload, "other")}, nil, "s3cret", false, true},
		{"missing HMAC rejected", BatchAuth{}, nil, "s3cret", false, true},
		{"no auth configured is rejected (was: loopback accepted silently)", BatchAuth{}, nil, "", false, true},
		{"dev loopback allowed only when caller opts in", BatchAuth{}, nil, "", true, false},
		{"dev opt-in does not override a bad HMAC", BatchAuth{HMAC: "bad"}, nil, "s3cret", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := AuthenticateBatch(payload, tc.auth, tc.reg, tc.secret, tc.devLoop)
			if tc.wantErr && err == nil {
				t.Fatal("expected rejection, got acceptance")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected acceptance, got %v", err)
			}
			if err != nil && !errors.Is(err, ErrGossipUnauthenticated) {
				t.Fatalf("error should wrap ErrGossipUnauthenticated: %v", err)
			}
		})
	}

	// Tampered payload must fail even with a once-valid signature.
	if _, err := AuthenticateBatch([]byte("tenant|agent-1|ACTIVE|999|node-a\n"),
		BatchAuth{NodeID: "node-a", EdSig: edOK, MLDSASig: mlOK}, reg, "", false); err == nil {
		t.Fatal("tampered payload accepted")
	}
}
