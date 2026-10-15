// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package ghostmode tracks which agents are currently routed to the Shadow
// Sandbox (ghost proxy) rather than their real target API.
//
// Ghost mode is activated via the Aegis-0 MCP control server when an agent's
// behaviour is suspicious but not yet conclusive enough to revoke outright.
// The agent continues to receive plausible-looking responses (from the sandbox)
// and never learns it has been diverted — preserving the attacker's uncertainty
// and allowing Aegis-0 to observe behaviour in the safe environment.
//
// State is stored in Redis with a TTL so that ghost mode expires automatically
// if Aegis-0 does not explicitly release the agent. The default TTL is 4 hours
// (long enough to observe a full agent session, short enough to avoid permanent
// misdirection if the Redis key is orphaned).
package ghostmode

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/asai/cicada/sentry/internal/queue"
)

// defaultTTL is the automatic expiry for a ghost mode entry. If Aegis-0 does
// not explicitly call Release(), the agent returns to normal routing after this
// window. 4 hours covers a typical long-running agent session without being
// permanent if a Redis key is orphaned.
const defaultTTL = 4 * time.Hour

// ttl returns the configured ghost mode TTL.
func ttl() time.Duration {
	if v := os.Getenv("GHOST_MODE_TTL_HOURS"); v != "" {
		if h, err := strconv.Atoi(v); err == nil && h > 0 {
			return time.Duration(h) * time.Hour
		}
	}
	return defaultTTL
}

func key(agentID string) string {
	return fmt.Sprintf("cicada:ghost:%s", agentID)
}

// Activate registers an agent in ghost mode. Subsequent proxy calls for this
// agent are silently routed to the shadow sandbox instead of the real target.
// Returns an error if Redis is unavailable.
func Activate(ctx context.Context, agentID string) error {
	if queue.Client == nil {
		return fmt.Errorf("redis unavailable — ghost mode state cannot be persisted")
	}
	if err := queue.Client.Set(ctx, key(agentID), "1", ttl()).Err(); err != nil {
		return fmt.Errorf("redis SET ghost mode: %w", err)
	}
	log.Printf("[GHOST] Agent %s entered ghost mode (TTL %s)", agentID, ttl())
	return nil
}

// IsActive returns true if the agent is currently in ghost mode.
// Returns false if Redis is unavailable (fail-open: a Redis outage should not
// prevent legitimate agent traffic from reaching the real target).
func IsActive(ctx context.Context, agentID string) bool {
	if queue.Client == nil {
		return false
	}
	val, err := queue.Client.Get(ctx, key(agentID)).Result()
	if err != nil {
		return false
	}
	return val == "1"
}

// Release removes the agent from ghost mode, returning it to normal proxy
// routing. Called by Aegis-0 after investigation is complete.
func Release(ctx context.Context, agentID string) error {
	if queue.Client == nil {
		return fmt.Errorf("redis unavailable")
	}
	if err := queue.Client.Del(ctx, key(agentID)).Err(); err != nil {
		return fmt.Errorf("redis DEL ghost mode: %w", err)
	}
	log.Printf("[GHOST] Agent %s released from ghost mode", agentID)
	return nil
}

// RecordViolation increments a violation counter for an agent in Redis.
// If the agent accumulates >=3 violations within 5 minutes, it is automatically
// placed into ghost mode (provided it has opted in, which is checked at proxy time).
func RecordViolation(ctx context.Context, agentID string) {
	if queue.Client == nil {
		return
	}
	vKey := fmt.Sprintf("cicada:violations:%s", agentID)
	
	// Increment and get new value
	count, err := queue.Client.Incr(ctx, vKey).Result()
	if err != nil {
		log.Printf("[GHOST] Failed to record violation for %s: %v", agentID, err)
		return
	}
	
	// First violation sets the 5-minute rolling window
	if count == 1 {
		queue.Client.Expire(ctx, vKey, 5*time.Minute)
	}

	if count >= 3 {
		log.Printf("[GHOST] Agent %s hit violation threshold (%d) - auto-activating Ghost Mode", agentID, count)
		_ = Activate(ctx, agentID)
		// Reset violation counter to avoid redundant triggers
		queue.Client.Del(ctx, vKey)
	}
}
