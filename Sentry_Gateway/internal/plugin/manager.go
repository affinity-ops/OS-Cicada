// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asai/cicada/sentry/internal/output"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// ErrInterceptorUnavailable is returned by GetInterceptor when the requested
// plugin is not registered, or the underlying connection is unhealthy.
//
// Source: EPHEMERAL_AGENT_KERNEL_FIREWALL.md §4, line 180 — the sequence
// diagram shows PlugMgr returning ErrInterceptorUnavailable on the
// "Plugin Unregistered / Unhealthy" path.
var ErrInterceptorUnavailable = errors.New("interceptor unavailable")

const (
	// defaultSocketPath is the UNIX Domain Socket where eakfd listens.
	// Source: §7.4, line 287 — "/var/run/cicada/eakf.sock".
	defaultSocketPath = "/var/run/cicada/eakf.sock"

	// healthProbeInterval controls the background health check frequency.
	// 30 seconds balances responsiveness with probe overhead.
	healthProbeInterval = 30 * time.Second

	// healthStrikeThreshold is the number of consecutive probe failures
	// before the interceptor transitions to unhealthy state. Three strikes
	// means worst-case detection latency is 90 seconds.
	healthStrikeThreshold = 3
)

// PluginManager is the registry and lifecycle manager for execution-plane
// plugins. At gateway boot, it reads CICADA_PLUGINS, dials any declared
// plugin sockets, and begins background health probing.
//
// Source: EPHEMERAL_AGENT_KERNEL_FIREWALL.md §4, lines 137–144.
type PluginManager struct {
	interceptors map[string]Interceptor

	// Health tracking for gRPC-based interceptors.
	mu             sync.RWMutex
	conns          map[string]*grpc.ClientConn
	healthStrikes  map[string]int
	healthy        map[string]*atomic.Bool
	cancel         context.CancelFunc
	alertEmittedMu sync.Mutex
	alertEmitted   map[string]bool // tracks whether unreachable alert has been emitted to avoid spam
}

// NewPluginManager reads the CICADA_PLUGINS environment variable and
// initialises the declared plugins. If "eakf" is present, a UDS-based
// gRPC client is established to the eakfd daemon socket.
//
// The socket path can be overridden via EAKF_SOCKET_PATH.
//
// Source: §4, line 137 — "At boot, Sentry Gateway initializes the
// PluginManager. If the environment variable CICADA_PLUGINS=eakf is set,
// the gateway registers a UDS-based client implementing the Interceptor
// interface, binding to /var/run/cicada/eakf.sock."
func NewPluginManager() (*PluginManager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	pm := &PluginManager{
		interceptors:  make(map[string]Interceptor),
		conns:         make(map[string]*grpc.ClientConn),
		healthStrikes: make(map[string]int),
		healthy:       make(map[string]*atomic.Bool),
		alertEmitted:  make(map[string]bool),
		cancel:        cancel,
	}

	pluginList := os.Getenv("CICADA_PLUGINS")
	if pluginList == "" {
		log.Println("[PluginManager] No plugins declared (CICADA_PLUGINS empty)")
		return pm, nil
	}

	for _, name := range strings.Split(pluginList, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		switch name {
		case "eakf":
			if err := pm.registerEAKF(); err != nil {
				log.Printf("[PluginManager] WARNING: failed to register EAKF plugin: %v", err)
				// Do not return error — the gateway should still start.
				// GetInterceptor("eakf") will return ErrInterceptorUnavailable,
				// which triggers fail-closed for agents that require EAKF.
			}
		default:
			log.Printf("[PluginManager] Unknown plugin declared: %q (skipping)", name)
		}
	}

	// Start background health probing for all gRPC-connected plugins.
	go pm.healthProbeLoop(ctx)

	return pm, nil
}

// registerEAKF establishes a persistent gRPC connection to the eakfd daemon
// over a UNIX Domain Socket and registers the EAKF interceptor.
func (pm *PluginManager) registerEAKF() error {
	socketPath := os.Getenv("EAKF_SOCKET_PATH")
	if socketPath == "" {
		socketPath = defaultSocketPath
	}

	target := fmt.Sprintf("unix://%s", socketPath)
	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("dial eakfd at %s: %w", socketPath, err)
	}

	h := &atomic.Bool{}
	h.Store(true) // Assume healthy at boot; probe will correct if wrong.

	client := NewEAKFClient(conn)

	pm.conns["eakf"] = conn
	pm.healthy["eakf"] = h
	pm.healthStrikes["eakf"] = 0
	pm.interceptors["eakf"] = client

	log.Printf("[PluginManager] EAKF plugin registered (socket: %s)", socketPath)
	return nil
}

// GetInterceptor returns the registered interceptor for the given name.
//
// Returns ErrInterceptorUnavailable if:
//   - The plugin is not registered (CICADA_PLUGINS does not include it), or
//   - The plugin's gRPC connection is unhealthy (three consecutive probe failures).
//
// When returning ErrInterceptorUnavailable for an unhealthy plugin, the manager
// emits an "eakfd_unreachable_fail_closed" threat alert via EmitThreatAlert.
//
// Source: §4, lines 160–183 (sequence diagram, alt paths).
func (pm *PluginManager) GetInterceptor(name string) (Interceptor, error) {
	interceptor, exists := pm.interceptors[name]
	if !exists {
		return nil, ErrInterceptorUnavailable
	}

	// Check health state for gRPC-backed interceptors.
	if h, ok := pm.healthy[name]; ok && !h.Load() {
		pm.emitUnreachableAlert(name)
		return nil, ErrInterceptorUnavailable
	}

	return interceptor, nil
}

// IsPluginDeclared returns true if the given plugin name appears in
// CICADA_PLUGINS, regardless of whether it is currently healthy.
//
// This is used for fail-closed intent enforcement (§7.6C): if an agent's
// policy requests EAKF but the plugin is not even declared, the gateway
// must still block code execution requests from that agent.
func (pm *PluginManager) IsPluginDeclared(name string) bool {
	_, exists := pm.interceptors[name]
	return exists
}

// Close shuts down all plugin connections and stops health probing.
func (pm *PluginManager) Close() {
	pm.cancel()
	for name, conn := range pm.conns {
		if err := conn.Close(); err != nil {
			log.Printf("[PluginManager] Error closing %s connection: %v", name, err)
		}
	}
}

// healthProbeLoop runs a background goroutine that pings each gRPC-connected
// plugin at healthProbeInterval. Three consecutive failures transition the
// plugin to unhealthy state. A single success resets the strike counter.
//
// Source: implementation plan — "30-second ping interval with a three-strike
// failure threshold before triggering eakfd_unreachable_fail_closed."
func (pm *PluginManager) healthProbeLoop(ctx context.Context) {
	ticker := time.NewTicker(healthProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.probeAll(ctx)
		}
	}
}

// probeAll checks every gRPC-connected plugin's health.
func (pm *PluginManager) probeAll(ctx context.Context) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for name, conn := range pm.conns {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		healthClient := healthpb.NewHealthClient(conn)
		resp, err := healthClient.Check(probeCtx, &healthpb.HealthCheckRequest{
			Service: "cicada.eakf.v1.EphemeralAgentKernelFirewall",
		})
		cancel()

		if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			pm.healthStrikes[name]++
			log.Printf("[PluginManager] Health probe failed for %s (strike %d/%d): %v",
				name, pm.healthStrikes[name], healthStrikeThreshold, err)

			if pm.healthStrikes[name] >= healthStrikeThreshold {
				wasHealthy := pm.healthy[name].Swap(false)
				if wasHealthy {
					log.Printf("[PluginManager] %s transitioned to UNHEALTHY after %d consecutive failures",
						name, healthStrikeThreshold)
					pm.emitUnreachableAlert(name)
				}
			}
		} else {
			// Probe succeeded — reset strikes and mark healthy.
			if pm.healthStrikes[name] > 0 {
				log.Printf("[PluginManager] %s health probe recovered (resetting %d strikes)",
					name, pm.healthStrikes[name])
			}
			pm.healthStrikes[name] = 0
			wasUnhealthy := !pm.healthy[name].Swap(true)
			if wasUnhealthy {
				log.Printf("[PluginManager] %s transitioned to HEALTHY", name)
				// Reset alert-emitted flag so we can re-alert on next outage.
				pm.alertEmittedMu.Lock()
				pm.alertEmitted[name] = false
				pm.alertEmittedMu.Unlock()
			}
		}
	}
}

// emitUnreachableAlert dispatches the "eakfd_unreachable_fail_closed" threat
// alert. Rate-limited to one emission per unhealthy transition to avoid
// spamming the operator dashboard.
//
// Source: §7.4, line 290 — "a high-severity action ledger event
// (eakfd_unreachable_fail_closed) is recorded."
// Source: §4, line 181 — 'Record "eakfd_unreachable_fail_closed" in Ledger'.
func (pm *PluginManager) emitUnreachableAlert(name string) {
	pm.alertEmittedMu.Lock()
	defer pm.alertEmittedMu.Unlock()

	if pm.alertEmitted[name] {
		return
	}
	pm.alertEmitted[name] = true

	go output.EmitThreatAlert(
		"eakfd_unreachable_fail_closed",
		"critical",
		"", // tenant_id — system-level alert, not tenant-scoped
		"", // agent_id — not agent-specific
		"",
		fmt.Sprintf("EAKF daemon (%s) is unreachable after %d consecutive health probe failures. "+
			"All code execution requests requiring sandboxing are being blocked (fail-closed). "+
			"Verify eakfd process status and UDS socket availability.", name, healthStrikeThreshold),
		"Restart eakfd daemon or investigate host-level failure",
		"",
		nil,
	)
}
