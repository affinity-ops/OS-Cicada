// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package billing

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/asai/cicada/sentry/internal/gossip"
	"github.com/asai/cicada/sentry/internal/queue"
)

// GuardrailFlusher periodically snapshots the in-memory AtomicMeter tallies,
// flushes them to Redis for persistent tracking, and triggers gossip mesh
// quarantine if a tenant exceeds their budget limit.
type GuardrailFlusher struct {
	meter       *AtomicMeter
	gossipMesh  *gossip.Mesh
	budgetLimit int64
}

// NewGuardrailFlusher creates a flusher with a configurable per-window budget limit.
func NewGuardrailFlusher(meter *AtomicMeter, mesh *gossip.Mesh) *GuardrailFlusher {
	return &GuardrailFlusher{
		meter:       meter,
		gossipMesh:  mesh,
		budgetLimit: 5000,
	}
}

// Start launches the 3-second heartbeat flusher in a background goroutine.
func (f *GuardrailFlusher) Start(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)

	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				f.flush(ctx)
			}
		}
	}()
}

func (f *GuardrailFlusher) flush(ctx context.Context) {
	usage := f.meter.ExtractAndReset()
	if len(usage) == 0 {
		return
	}

	log.Printf("[BILLING] Flushing usage for %d active tenants to Redis", len(usage))

	for tenantID, requestVolume := range usage {
		// Persist to Redis via real pipeline
		if err := queue.IncrementTenantUsage(ctx, tenantID, requestVolume); err != nil {
			log.Printf("[BILLING ERROR] Redis increment failed for %s: %v", tenantID, err)
			continue
		}

		// Check budget guardrail
		if requestVolume > f.budgetLimit {
			log.Printf("[BUDGET GUARDRAIL] Tenant %s exceeded limit (%d > %d). Engaging quarantine.", tenantID, requestVolume, f.budgetLimit)
			f.gossipMesh.QuarantineAgent(fmt.Sprintf("%s_WILDCARD", tenantID))
		}
	}
}
