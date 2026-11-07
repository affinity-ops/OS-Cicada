// Copyright 2026 Patrick Matthews and Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package gossip

import (
	"errors"
	"fmt"
)

// BatchAuth carries the authentication headers attached to an inbound gossip
// batch (see shipCompressedBatch for the sending side).
type BatchAuth struct {
	NodeID   string // X-Gossip-Node-ID
	EdSig    string // X-Gossip-Sig-Ed25519 (base64)
	MLDSASig string // X-Gossip-Sig-MLDSA65 (base64), optional unless the peer has a PQC key
	HMAC     string // X-Gossip-HMAC (hex), legacy shared-secret mode
}

// ErrGossipUnauthenticated is returned when a batch carries no acceptable
// authentication for the node's configuration.
var ErrGossipUnauthenticated = errors.New("gossip batch is not authenticated")

// AuthenticateBatch decides whether an inbound gossip batch may be applied.
// It fails closed: there is no configuration in which an unsigned batch is
// accepted outside development mode.
//
// Order of checks:
//  1. Per-peer signatures. If the batch is signed, the sending node must be in
//     the peer registry and VerifyBatchSignature must pass (Ed25519 always;
//     ML-DSA-65 as well when the peer has a PQC key registered).
//  2. Shared-secret HMAC (legacy). Accepted only when CICADA_GOSSIP_SECRET is
//     set and no peer registry is configured. Once a registry exists, signed
//     batches are mandatory.
//  3. Development only: allowUnauthenticated lets a single local node accept
//     its own unsigned loopback traffic. Callers must only set this when
//     CICADA_DEV_MODE=true and the request came from loopback.
//
// The returned string names the mode that authenticated the batch, for logs.
func AuthenticateBatch(payload []byte, a BatchAuth, reg *PeerRegistry, secret string, allowUnauthenticated bool) (string, error) {
	registryConfigured := reg != nil && reg.Count() > 0

	if a.EdSig != "" {
		if !registryConfigured {
			return "", fmt.Errorf("%w: signed batch from %q but no peer registry is configured", ErrGossipUnauthenticated, a.NodeID)
		}
		peer := reg.Lookup(a.NodeID)
		if peer == nil {
			return "", fmt.Errorf("%w: unknown peer %q", ErrGossipUnauthenticated, a.NodeID)
		}
		if err := VerifyBatchSignature(payload, peer, a.EdSig, a.MLDSASig); err != nil {
			return "", fmt.Errorf("%w: %v", ErrGossipUnauthenticated, err)
		}
		if peer.MlDsa65Pub != "" {
			return "ed25519+ml-dsa-65", nil
		}
		return "ed25519", nil
	}

	if registryConfigured {
		return "", fmt.Errorf("%w: peer registry configured, batch from %q is unsigned", ErrGossipUnauthenticated, a.NodeID)
	}

	if secret != "" {
		if a.HMAC == "" || !VerifyHMAC(payload, a.HMAC, secret) {
			return "", fmt.Errorf("%w: missing or invalid HMAC", ErrGossipUnauthenticated)
		}
		return "hmac", nil
	}

	if allowUnauthenticated {
		return "unauthenticated-dev-loopback", nil
	}
	return "", fmt.Errorf("%w: no gossip authentication configured (set CICADA_GOSSIP_PEERS_CONFIG or CICADA_GOSSIP_SECRET)", ErrGossipUnauthenticated)
}
