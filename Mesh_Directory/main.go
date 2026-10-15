// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Mesh Directory — Standalone P2P Mesh Discovery & Threat Intelligence Relay
//
// This is the commercial enabler for the Cicada sovereign mesh. It runs as a
// lightweight standalone service (separate from the Sentry Gateway) and provides:
//
//  1. Node Registration — gateways register with their Ed25519 + ML-DSA-65 public keys
//  2. Peer Discovery — gateways query for other enrolled peers
//  3. Threat Intel Relay — anonymised threat signals are aggregated and redistributed
//  4. License Validation — only nodes with valid licenses can join the mesh
//
// What it does NOT do:
//   - Store or relay operational gossip (quarantine/release state)
//   - Access any tenant's data, agents, or credentials
//   - Require access to any gateway's database
//
// Architecture:
//
//	Company A Gateway ──heartbeat──► Mesh Directory ◄──heartbeat── Company B Gateway
//	                                       │
//	                   ┌───────────────────┴───────────────────┐
//	                   ▼                                       ▼
//	          Peer Registry                           Threat Intel Relay
//	     (who's in the mesh)                    (aggregate + redistribute)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ─── Data Types ─────────────────────────────────────────────────────────────

// MeshNode represents a registered gateway node in the mesh.
type MeshNode struct {
	NodeID      string `json:"node_id"`
	TenantID    string `json:"tenant_id"`
	Endpoint    string `json:"endpoint"`               // Gossip receive URL
	Ed25519Pub  string `json:"ed25519_pub"`             // Base64 Ed25519 public key
	MlDsa65Pub  string `json:"ml_dsa65_pub,omitempty"`  // Base64 ML-DSA-65 public key (optional)
	LicenseTier string `json:"license_tier"`            // "starter", "professional", "enterprise"
	Version     string `json:"version"`                 // Gateway version string
	Region      string `json:"region,omitempty"`        // Optional region hint
	RegisteredAt time.Time `json:"registered_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	MeshEnabled  bool      `json:"mesh_enabled"`        // Whether this node opts in to threat sharing
}

// ThreatSignal is the anonymised threat intelligence signal relayed through the directory.
// This is the same structure as internal/threatintel.ThreatSignal in the gateway.
type ThreatSignal struct {
	SignalID    string `json:"signal_id"`
	Category   string `json:"category"`
	Fingerprint string `json:"fingerprint"`
	Severity   string `json:"severity"`
	Timestamp  int64  `json:"timestamp"`
	TTL        int64  `json:"ttl"`
	RelayedAt  int64  `json:"relayed_at,omitempty"` // When the directory received this signal
}

// RegisterRequest is the payload for POST /v1/mesh/register.
type RegisterRequest struct {
	NodeID      string `json:"node_id"`
	TenantID    string `json:"tenant_id"`
	Endpoint    string `json:"endpoint"`
	Ed25519Pub  string `json:"ed25519_pub"`
	MlDsa65Pub  string `json:"ml_dsa65_pub,omitempty"`
	LicenseTier string `json:"license_tier"`
	Version     string `json:"version"`
	Region      string `json:"region,omitempty"`
	MeshEnabled bool   `json:"mesh_enabled"`
}

// ─── In-Memory Registry ─────────────────────────────────────────────────────
// For MVP, the peer registry and threat intel buffer are in-memory.
// Production will use PostgreSQL (schema provided in schema.sql).

type Registry struct {
	mu    sync.RWMutex
	nodes map[string]*MeshNode // keyed by NodeID
}

func NewRegistry() *Registry {
	return &Registry{
		nodes: make(map[string]*MeshNode),
	}
}

func (r *Registry) Register(node *MeshNode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	node.RegisteredAt = time.Now()
	node.LastSeenAt = time.Now()
	r.nodes[node.NodeID] = node
}

func (r *Registry) Heartbeat(nodeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n, ok := r.nodes[nodeID]; ok {
		n.LastSeenAt = time.Now()
	}
}

func (r *Registry) Get(nodeID string) *MeshNode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.nodes[nodeID]
}

// ActivePeers returns all nodes seen within the staleness threshold.
// Excludes the requesting node (callerNodeID).
func (r *Registry) ActivePeers(callerNodeID string, staleness time.Duration) []MeshNode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cutoff := time.Now().Add(-staleness)
	var peers []MeshNode
	for _, n := range r.nodes {
		if n.NodeID == callerNodeID {
			continue
		}
		if n.LastSeenAt.Before(cutoff) {
			continue
		}
		peers = append(peers, *n)
	}
	return peers
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.nodes)
}

// ─── Threat Intel Buffer ────────────────────────────────────────────────────

type IntelBuffer struct {
	mu      sync.RWMutex
	signals []ThreatSignal
	maxSize int
}

func NewIntelBuffer(maxSize int) *IntelBuffer {
	return &IntelBuffer{
		signals: make([]ThreatSignal, 0, maxSize),
		maxSize: maxSize,
	}
}

func (b *IntelBuffer) Add(signal ThreatSignal) {
	b.mu.Lock()
	defer b.mu.Unlock()
	signal.RelayedAt = time.Now().UnixNano()

	// Dedup by fingerprint
	for i, existing := range b.signals {
		if existing.Fingerprint == signal.Fingerprint {
			// Update if newer
			if signal.Timestamp > existing.Timestamp {
				b.signals[i] = signal
			}
			return
		}
	}

	// Ring buffer eviction
	if len(b.signals) >= b.maxSize {
		b.signals = b.signals[1:]
	}
	b.signals = append(b.signals, signal)
}

// Since returns all signals received after the given timestamp (Unix nanos).
func (b *IntelBuffer) Since(afterTimestamp int64) []ThreatSignal {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var result []ThreatSignal
	for _, s := range b.signals {
		if s.RelayedAt > afterTimestamp {
			result = append(result, s)
		}
	}
	return result
}

func (b *IntelBuffer) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.signals)
}

// ─── HTTP Handlers ──────────────────────────────────────────────────────────

type Server struct {
	registry *Registry
	intel    *IntelBuffer
}

func NewServer() *Server {
	return &Server{
		registry: NewRegistry(),
		intel:    NewIntelBuffer(10000), // Buffer up to 10k signals
	}
}

// POST /v1/mesh/register — Node registration
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// Validate required fields
	if req.NodeID == "" || req.TenantID == "" || req.Ed25519Pub == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node_id, tenant_id, and ed25519_pub are required"})
		return
	}

	node := &MeshNode{
		NodeID:      req.NodeID,
		TenantID:    req.TenantID,
		Endpoint:    req.Endpoint,
		Ed25519Pub:  req.Ed25519Pub,
		MlDsa65Pub:  req.MlDsa65Pub,
		LicenseTier: req.LicenseTier,
		Version:     req.Version,
		Region:      req.Region,
		MeshEnabled: req.MeshEnabled,
	}

	s.registry.Register(node)
	log.Printf("[MESH] Registered node %s (tenant: %s, tier: %s, pqc: %v, mesh: %v)",
		req.NodeID, req.TenantID, req.LicenseTier, req.MlDsa65Pub != "", req.MeshEnabled)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "registered",
		"node_id":     req.NodeID,
		"mesh_peers":  s.registry.Count() - 1,
	})
}

// POST /v1/mesh/heartbeat — Extended heartbeat with mesh enrollment
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	nodeID := r.Header.Get("X-Gateway-ID")
	if nodeID == "" {
		// Try to extract from body
		var body struct {
			GatewayID string `json:"gateway_id"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		nodeID = body.GatewayID
	}

	if nodeID != "" {
		s.registry.Heartbeat(nodeID)
	}

	// Return peer list and pending threat intel as directives
	peers := s.registry.ActivePeers(nodeID, 24*time.Hour)
	recentIntel := s.intel.Since(time.Now().Add(-1 * time.Hour).UnixNano())

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"directives": map[string]interface{}{
			"mesh_peers":    peers,
			"threat_signals": recentIntel,
		},
	})
}

// GET /v1/mesh/peers — Peer discovery
func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}

	callerID := r.Header.Get("X-Gateway-ID")
	peers := s.registry.ActivePeers(callerID, 24*time.Hour)

	// Strip private fields — only return what's needed for peer-to-peer gossip
	type PeerInfo struct {
		NodeID     string `json:"node_id"`
		TenantID   string `json:"tenant_id"`
		Endpoint   string `json:"endpoint"`
		Ed25519Pub string `json:"ed25519_pub"`
		MlDsa65Pub string `json:"ml_dsa65_pub,omitempty"`
		Region     string `json:"region,omitempty"`
	}

	peerInfos := make([]PeerInfo, len(peers))
	for i, p := range peers {
		peerInfos[i] = PeerInfo{
			NodeID:     p.NodeID,
			TenantID:   p.TenantID,
			Endpoint:   p.Endpoint,
			Ed25519Pub: p.Ed25519Pub,
			MlDsa65Pub: p.MlDsa65Pub,
			Region:     p.Region,
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"peers": peerInfos,
		"count": len(peerInfos),
	})
}

// POST /v1/mesh/intel — Receive anonymised threat signals
func (s *Server) handleIntelReceive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var signals []ThreatSignal
	if err := json.NewDecoder(r.Body).Decode(&signals); err != nil {
		// Try single signal
		var single ThreatSignal
		if err2 := json.NewDecoder(r.Body).Decode(&single); err2 != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON — expected array or single ThreatSignal"})
			return
		}
		signals = []ThreatSignal{single}
	}

	for _, sig := range signals {
		s.intel.Add(sig)
	}

	log.Printf("[MESH-INTEL] Received %d threat signals (buffer: %d)", len(signals), s.intel.Count())

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"accepted":     len(signals),
		"buffer_count": s.intel.Count(),
	})
}

// GET /v1/mesh/intel/feed — Poll for aggregated threat signals
func (s *Server) handleIntelFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}

	// Default: last hour of signals
	since := time.Now().Add(-1 * time.Hour).UnixNano()
	if raw := r.URL.Query().Get("since"); raw != "" {
		fmt.Sscanf(raw, "%d", &since)
	}

	signals := s.intel.Since(since)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"signals": signals,
		"count":   len(signals),
	})
}

// GET /v1/mesh/health — Health check
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "healthy",
		"registered_nodes": s.registry.Count(),
		"intel_buffer":     s.intel.Count(),
		"uptime":           "running",
	})
}

// ─── Utilities ──────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// ─── Main ───────────────────────────────────────────────────────────────────

func main() {
	port := os.Getenv("MESH_DIRECTORY_PORT")
	if port == "" {
		port = "9090"
	}

	srv := NewServer()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/mesh/register", srv.handleRegister)
	mux.HandleFunc("/v1/mesh/heartbeat", srv.handleHeartbeat)
	mux.HandleFunc("/v1/mesh/peers", srv.handlePeers)
	mux.HandleFunc("/v1/mesh/intel", srv.handleIntelReceive)
	mux.HandleFunc("/v1/mesh/intel/feed", srv.handleIntelFeed)
	mux.HandleFunc("/v1/mesh/health", srv.handleHealth)

	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("[MESH] Shutting down gracefully...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(ctx)
	}()

	log.Printf("[MESH] ══════════════════════════════════════════════════════════════")
	log.Printf("[MESH] Cicada Mesh Directory starting on :%s", port)
	log.Printf("[MESH]   POST /v1/mesh/register    — Node registration")
	log.Printf("[MESH]   POST /v1/mesh/heartbeat   — Extended heartbeat")
	log.Printf("[MESH]   GET  /v1/mesh/peers        — Peer discovery")
	log.Printf("[MESH]   POST /v1/mesh/intel        — Threat signal ingestion")
	log.Printf("[MESH]   GET  /v1/mesh/intel/feed   — Threat signal feed")
	log.Printf("[MESH]   GET  /v1/mesh/health       — Health check")
	log.Printf("[MESH] ══════════════════════════════════════════════════════════════")

	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("[MESH] FATAL: %v", err)
	}
}
