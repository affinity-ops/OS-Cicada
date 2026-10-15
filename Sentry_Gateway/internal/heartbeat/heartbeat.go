// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/asai/cicada/sentry/internal/license"
)

// Payload is the JSON body sent to CICADA_HOME_URL/api/v1/gateway/heartbeat.
type Payload struct {
	GatewayID              string            `json:"gateway_id"`
	TenantID               string            `json:"tenant_id,omitempty"`
	GatewayVersion         string            `json:"gateway_version"`
	UptimeSeconds          int64             `json:"uptime_seconds"`
	AgentsRegistered       int               `json:"agents_registered"`
	CallsLastWindow        int64             `json:"calls_last_window"`
	CallsBlockedLastWindow int64             `json:"calls_blocked_last_window"`
	TLSEnabled             bool              `json:"tls_enabled"`
	MTLSEnabled            bool              `json:"mtls_enabled"`
	CanaryTokensActive     int               `json:"canary_tokens_active"`
	QuarantinedAgents      int               `json:"quarantined_agents"`
	RedisHealthy           bool              `json:"redis_healthy"`
	PostgresHealthy        bool              `json:"postgres_healthy"`
	Region                 string            `json:"region,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`

	// Mesh enrollment fields (Phase 4)
	MeshEnabled            bool              `json:"mesh_enabled,omitempty"`
	Ed25519Pub             string            `json:"ed25519_pub,omitempty"`
	MlDsa65Pub             string            `json:"ml_dsa65_pub,omitempty"`
	ThreatSignalCount      int               `json:"threat_signal_count,omitempty"`
	MeshPeerCount          int               `json:"mesh_peer_count,omitempty"`
}

// Directives is the JSON response the home server sends back inside the heartbeat ACK.
// The gateway reads this and acts on any pending operator instructions.
type Directives struct {
	QuarantineAgents []string `json:"quarantine_agents,omitempty"`
	RevokeAgents     []string `json:"revoke_agents,omitempty"`
	ReloadPolicy     bool     `json:"reload_policy,omitempty"`
	Message          string   `json:"message,omitempty"`

	// Mesh directives (Phase 4) — returned by the Mesh Directory service
	MeshPeers        []MeshPeerDirective `json:"mesh_peers,omitempty"`
	ThreatSignals    []json.RawMessage   `json:"threat_signals,omitempty"` // Raw JSON for gateway's threatintel package to parse
}

// MeshPeerDirective carries peer discovery data from the directory service.
type MeshPeerDirective struct {
	NodeID     string `json:"node_id"`
	TenantID   string `json:"tenant_id"`
	Endpoint   string `json:"endpoint"`
	Ed25519Pub string `json:"ed25519_pub"`
	MlDsa65Pub string `json:"ml_dsa65_pub,omitempty"`
}

// Deps are the live subsystem handles the heartbeat reads from. All are
// optional (nil means that subsystem's metric is omitted / reported as zero).
type Deps struct {
	// AgentCountFn returns the current number of registered, non-revoked agents.
	AgentCountFn func(ctx context.Context) int

	// CanaryCountFn returns the number of active canary tokens currently issued.
	CanaryCountFn func(ctx context.Context) int

	// QuarantineCountFn returns the number of agents currently quarantined.
	QuarantineCountFn func() int

	// RedisHealthFn returns true if Redis is reachable.
	RedisHealthFn func(ctx context.Context) bool

	// PostgresHealthFn returns true if Postgres is reachable.
	PostgresHealthFn func(ctx context.Context) bool

	// OnDirectives is called when the home server returns directives.
	// The implementation should act on them (quarantine, revoke, reload, etc.).
	// Called in a goroutine — must be non-blocking.
	OnDirectives func(d Directives)

	// Mesh enrollment deps (Phase 4)
	MeshEnabled       bool
	Ed25519PubB64     string // Base64-encoded Ed25519 public key
	MlDsa65PubB64     string // Base64-encoded ML-DSA-65 public key (empty if PQC not configured)
	ThreatSignalCount func() int
	MeshPeerCount     func() int
	OnMeshPeers       func(peers []MeshPeerDirective) // Called when directory returns new peers
}

// Worker is the background heartbeat goroutine.
type Worker struct {
	gatewayID   string
	version     string
	homeURL     string
	interval    time.Duration
	tlsEnabled  bool
	mtlsEnabled bool
	startedAt   time.Time

	callsTotal   atomic.Int64
	callsBlocked atomic.Int64

	deps   Deps
	client *http.Client
	stop   chan struct{}
}

// New creates a Worker. Call Start() to begin the heartbeat loop.
//
// Configuration from environment:
//   CICADA_GATEWAY_ID       — stable identifier for this installation (default: hostname)
//   CICADA_HOME_URL         — Cicada control-plane base URL (required; heartbeat is skipped if unset)
//   CICADA_HEARTBEAT_INTERVAL — e.g. "3h", "30m" (default: 3h)
//   CICADA_GATEWAY_VERSION  — semver string reported to the home server
func New(tlsEnabled, mtlsEnabled bool, deps Deps) *Worker {
	id := os.Getenv("CICADA_GATEWAY_ID")
	if id == "" {
		hostname, _ := os.Hostname()
		id = fmt.Sprintf("gw-%s", hostname)
	}

	version := os.Getenv("CICADA_GATEWAY_VERSION")
	if version == "" {
		version = "dev"
	}

	interval := 3 * time.Hour
	if raw := os.Getenv("CICADA_HEARTBEAT_INTERVAL"); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			interval = parsed
		}
	}

	return &Worker{
		gatewayID:   id,
		version:     version,
		homeURL:     os.Getenv("CICADA_HOME_URL"),
		interval:    interval,
		tlsEnabled:  tlsEnabled,
		mtlsEnabled: mtlsEnabled,
		startedAt:   time.Now(),
		deps:        deps,
		client:      &http.Client{Timeout: 15 * time.Second},
		stop:        make(chan struct{}),
	}
}

// RecordCall must be called once per admitted request to track call volume.
func (w *Worker) RecordCall() { w.callsTotal.Add(1) }

// RecordBlock must be called once per blocked request to track block volume.
func (w *Worker) RecordBlock() { w.callsBlocked.Add(1) }

// Start launches the background heartbeat goroutine. It fires immediately on
// startup to register the gateway, then repeats on the configured interval.
//
// The heartbeat never blocks the gateway — all errors are logged and swallowed.
func (w *Worker) Start(ctx context.Context) {
	if w.homeURL == "" {
		log.Printf("[HEARTBEAT] CICADA_HOME_URL not set — heartbeat disabled")
		return
	}
	log.Printf("[HEARTBEAT] Starting (gateway_id=%s interval=%v home=%s)", w.gatewayID, w.interval, w.homeURL)

	go func() {
		// Fire immediately on startup to register the gateway in the home server.
		w.beat(ctx)

		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				w.beat(ctx)
			case <-w.stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop halts the heartbeat loop.
func (w *Worker) Stop() { close(w.stop) }

func (w *Worker) beat(ctx context.Context) {
	// Snapshot and reset window counters atomically.
	calls := w.callsTotal.Swap(0)
	blocked := w.callsBlocked.Swap(0)

	p := Payload{
		GatewayID:              w.gatewayID,
		GatewayVersion:         w.version,
		UptimeSeconds:          int64(time.Since(w.startedAt).Seconds()),
		CallsLastWindow:        calls,
		CallsBlockedLastWindow: blocked,
		TLSEnabled:             w.tlsEnabled,
		MTLSEnabled:            w.mtlsEnabled,
		Region:                 os.Getenv("CICADA_REGION"),
		Metadata: map[string]string{
			"go_version": runtime.Version(),
			"os":         runtime.GOOS + "/" + runtime.GOARCH,
		},
	}

	// S5: Enterprise Telemetry Sync — Inject the cryptographically verified license claims
	if license.ActiveLicense != nil {
		p.TenantID = license.ActiveLicense.TenantID
		p.Metadata["license_tier"] = license.ActiveLicense.Tier
		p.Metadata["license_max_agents"] = strconv.Itoa(license.ActiveLicense.MaxAgents)
		p.Metadata["license_expires_at"] = license.ActiveLicense.ExpiresAt.Format(time.RFC3339)
	}

	if w.deps.AgentCountFn != nil {
		p.AgentsRegistered = w.deps.AgentCountFn(ctx)
	}
	if w.deps.CanaryCountFn != nil {
		p.CanaryTokensActive = w.deps.CanaryCountFn(ctx)
	}
	if w.deps.QuarantineCountFn != nil {
		p.QuarantinedAgents = w.deps.QuarantineCountFn()
	}
	if w.deps.RedisHealthFn != nil {
		p.RedisHealthy = w.deps.RedisHealthFn(ctx)
	}
	if w.deps.PostgresHealthFn != nil {
		p.PostgresHealthy = w.deps.PostgresHealthFn(ctx)
	}

	// Mesh enrollment telemetry (Phase 4)
	if w.deps.MeshEnabled {
		p.MeshEnabled = true
		p.Ed25519Pub = w.deps.Ed25519PubB64
		p.MlDsa65Pub = w.deps.MlDsa65PubB64
		if w.deps.ThreatSignalCount != nil {
			p.ThreatSignalCount = w.deps.ThreatSignalCount()
		}
		if w.deps.MeshPeerCount != nil {
			p.MeshPeerCount = w.deps.MeshPeerCount()
		}
	}

	body, err := json.Marshal(p)
	if err != nil {
		log.Printf("[HEARTBEAT] marshal error: %v", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		w.homeURL+"/api/v1/gateway/heartbeat", bytes.NewReader(body))
	if err != nil {
		log.Printf("[HEARTBEAT] request build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-ID", w.gatewayID)

	resp, err := w.client.Do(req)
	if err != nil {
		// Silently swallow — network errors must never crash or block the gateway.
		log.Printf("[HEARTBEAT] unreachable (%v) — will retry at next interval", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[HEARTBEAT] home server returned %d — will retry at next interval", resp.StatusCode)
		return
	}

	log.Printf("[HEARTBEAT] OK (calls=%d blocked=%d agents=%d uptime=%ds)",
		calls, blocked, p.AgentsRegistered, p.UptimeSeconds)

	// Read operator directives from the ACK body.
	var ack struct {
		Directives Directives `json:"directives"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return
	}
	if w.deps.OnDirectives != nil && (len(ack.Directives.QuarantineAgents) > 0 ||
		len(ack.Directives.RevokeAgents) > 0 ||
		ack.Directives.ReloadPolicy ||
		ack.Directives.Message != "") {
		go w.deps.OnDirectives(ack.Directives)
	}

	// Process mesh peer discovery directives (Phase 4)
	if w.deps.OnMeshPeers != nil && len(ack.Directives.MeshPeers) > 0 {
		go w.deps.OnMeshPeers(ack.Directives.MeshPeers)
		log.Printf("[HEARTBEAT] Received %d mesh peers from directory", len(ack.Directives.MeshPeers))
	}
}
