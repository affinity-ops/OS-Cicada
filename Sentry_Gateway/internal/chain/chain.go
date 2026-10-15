// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package chain — cryptographically signed inter-agent delegation chains.
//
// When Agent B acts on behalf of Agent A, the delegation must be
// cryptographically verifiable. A compromised agent cannot forge or reset
// the chain depth because each hop's entry is signed by the gateway's
// Ed25519 key at the time of transit.
//
// Wire format: the X-Cicada-Agent-Chain header contains a base64-encoded
// JSON array of ChainHop entries. Each entry includes the agent ID, depth,
// timestamp, and an Ed25519 signature over the preceding fields. The
// gateway verifies all existing signatures before appending a new hop.
//
// Why Ed25519 (not HMAC): Ed25519 signatures are publicly verifiable.
// Any gateway node in the cluster can verify without sharing a secret key.
// This is critical for the gossip mesh where verification happens on
// different nodes than signing.
//
// Chain depth enforcement: if the chain exceeds maxDepth (default: 3),
// the gateway returns a 403 requiring CIBA hold. This prevents infinite
// delegation loops where Agent A → B → C → A → B → ...
package chain

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ChainHop represents a single delegation step in the agent chain.
type ChainHop struct {
	AgentID   string `json:"agent_id"`
	Depth     int    `json:"depth"`
	Timestamp int64  `json:"ts"`       // Unix milliseconds
	Signature []byte `json:"sig"`      // Ed25519 signature over AgentID+Depth+Timestamp
}

// ChainResult is returned after verifying and extending a chain.
type ChainResult struct {
	Valid        bool       // Whether all signatures in the chain are valid
	Chain        []ChainHop // The full chain including the current hop
	CurrentDepth int        // The depth of the current (newest) hop
	ExceedsMax   bool       // Whether the chain exceeds the maximum allowed depth
	Error        string     // Human-readable error if invalid
}

// Verifier handles chain verification and extension.
type Verifier struct {
	pubKey   ed25519.PublicKey
	privKey  ed25519.PrivateKey
	maxDepth int
}

// NewVerifier creates a chain verifier with the gateway's Ed25519 key pair.
func NewVerifier(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey, maxDepth int) *Verifier {
	if maxDepth <= 0 {
		maxDepth = 3
	}
	return &Verifier{pubKey: pubKey, privKey: privKey, maxDepth: maxDepth}
}

// signablePayload creates the deterministic byte sequence that is signed
// for each hop. The format is: "agentID|depth|timestamp"
func signablePayload(agentID string, depth int, ts int64) []byte {
	return []byte(fmt.Sprintf("%s|%d|%d", agentID, depth, ts))
}

// VerifyAndExtend parses the X-Cicada-Agent-Chain header, verifies all
// existing signatures, and appends a new hop for the current agent.
//
// If chainHeader is empty, this is the first hop (depth 1).
// Returns a ChainResult with the extended chain and validity status.
func (v *Verifier) VerifyAndExtend(chainHeader string, currentAgentID string) ChainResult {
	var chain []ChainHop

	// Parse existing chain if present.
	if chainHeader != "" {
		decoded, err := base64.StdEncoding.DecodeString(chainHeader)
		if err != nil {
			return ChainResult{Valid: false, Error: "invalid chain encoding: " + err.Error()}
		}
		if err := json.Unmarshal(decoded, &chain); err != nil {
			return ChainResult{Valid: false, Error: "invalid chain JSON: " + err.Error()}
		}

		// Verify every existing hop's signature.
		for i, hop := range chain {
			payload := signablePayload(hop.AgentID, hop.Depth, hop.Timestamp)
			if !ed25519.Verify(v.pubKey, payload, hop.Signature) {
				return ChainResult{
					Valid: false,
					Error: fmt.Sprintf("signature verification failed at hop %d (agent %s)", i, hop.AgentID),
				}
			}
		}

		// Verify depth sequence is monotonically increasing.
		for i := 1; i < len(chain); i++ {
			if chain[i].Depth != chain[i-1].Depth+1 {
				return ChainResult{
					Valid: false,
					Error: fmt.Sprintf("depth sequence broken at hop %d: expected %d, got %d",
						i, chain[i-1].Depth+1, chain[i].Depth),
				}
			}
		}
	}

	// Determine the new depth.
	newDepth := 1
	if len(chain) > 0 {
		newDepth = chain[len(chain)-1].Depth + 1
	}

	// Sign the new hop.
	ts := time.Now().UnixMilli()
	payload := signablePayload(currentAgentID, newDepth, ts)
	sig := ed25519.Sign(v.privKey, payload)

	newHop := ChainHop{
		AgentID:   currentAgentID,
		Depth:     newDepth,
		Timestamp: ts,
		Signature: sig,
	}

	chain = append(chain, newHop)

	return ChainResult{
		Valid:        true,
		Chain:        chain,
		CurrentDepth: newDepth,
		ExceedsMax:   newDepth > v.maxDepth,
	}
}

// Encode serialises the chain to a base64 string for the X-Cicada-Agent-Chain header.
func Encode(chain []ChainHop) (string, error) {
	data, err := json.Marshal(chain)
	if err != nil {
		return "", fmt.Errorf("chain marshal: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// Decode parses a chain from the base64-encoded header value.
func Decode(header string) ([]ChainHop, error) {
	if header == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("invalid chain encoding: %w", err)
	}
	var chain []ChainHop
	if err := json.Unmarshal(decoded, &chain); err != nil {
		return nil, fmt.Errorf("invalid chain JSON: %w", err)
	}
	return chain, nil
}

// ExtractUpstreamAgent returns the agent ID of the most recent upstream hop,
// or empty string if this is the first hop.
func ExtractUpstreamAgent(chain []ChainHop) string {
	if len(chain) < 2 {
		return ""
	}
	return chain[len(chain)-2].AgentID
}

// ErrChainTooDeep is returned when the chain exceeds the maximum depth.
var ErrChainTooDeep = errors.New("agent delegation chain exceeds maximum depth — CIBA hold required")
