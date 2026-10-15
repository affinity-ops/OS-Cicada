// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package queue manages Redis-backed queues for async workloads in Cicada's
// Sentry Gateway.
//
// Queues in use:
//   cicada_rollback_queue — saga compensating transaction intents (LPUSH/BRPOP)
//   cicada_swarm_queue    — anomalous payload analysis jobs (RPUSH/BLPOP)
//
// Idempotency:
// Every saga job carries an IdempotencyKey. Before enqueuing, PushRollback checks
// a Redis set (cicada:saga:idempotency) for the key. If the key already exists,
// the enqueue is skipped and success is returned — the compensation was already
// initiated. This prevents duplicate compensating transactions when the Saga
// Executor retries or when a network error causes the caller to retry the rollback
// endpoint. Idempotency keys expire after 24 hours — long enough for any
// reasonable retry window, short enough that the set does not grow unbounded.
package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client holds the shared Redis connection used for all queue operations.
var Client *redis.Client

// sagaIdempotencyTTL is how long an idempotency key is retained after the saga
// is enqueued. 24 hours covers all realistic retry windows while preventing
// unbounded growth of the idempotency set for long-running deployments.
const sagaIdempotencyTTL = 24 * time.Hour

// sagaIdempotencyKey is the Redis key for the idempotency set.
// Stored as individual string keys (not a set) so per-key TTL is supported.
func sagaIdempotencyKey(idempotencyKey string) string {
	return fmt.Sprintf("cicada:saga:idempotency:%s", idempotencyKey)
}

// InitRedis creates a Redis client from the CICADA_REDIS_URL environment
// variable and verifies connectivity with a ping.
func InitRedis(ctx context.Context) error {
	addr := os.Getenv("CICADA_REDIS_URL")
	if addr == "" {
		return fmt.Errorf("CICADA_REDIS_URL environment variable is required")
	}

	opts, err := redis.ParseURL(addr)
	if err != nil {
		return fmt.Errorf("invalid redis URL: %w", err)
	}

	Client = redis.NewClient(opts)

	if err := Client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}

	log.Printf("[QUEUE] Redis connection established at %s", addr)
	return nil
}

// Close gracefully shuts down the Redis client.
func Close() error {
	if Client != nil {
		return Client.Close()
	}
	return nil
}

// SagaJob represents a compensating transaction intent pushed to the rollback queue.
// IdempotencyKey must be unique per logical rollback operation. The recommended
// format is "{trace_id}:{failed_action}" — this ensures that retrying the same
// failed action produces exactly one compensation, not N compensations for N retries.
type SagaJob struct {
	RollbackID         string `json:"rollback_id"`
	TraceID            string `json:"trace_id"`
	OriginalActionHash string `json:"original_action_hash"`
	RevertRoute        string `json:"revert_route"`
	FailedAction       string `json:"failed_action"`

	// IdempotencyKey prevents duplicate compensating transactions when the
	// gateway retries or the caller retries the rollback endpoint.
	// If empty, no idempotency check is performed (backwards compatible with
	// callers that predate this field).
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// SwarmJob represents an anomalous payload pushed to the verification swarm queue.
type SwarmJob struct {
	AgentID   string                 `json:"agent_id"`
	Payload   map[string]interface{} `json:"payload"`
	Threshold int                    `json:"threshold"`
	Priority  string                 `json:"priority,omitempty"` // "high" or ""
}

// PushRollback enqueues a saga rollback intent to Redis.
// If the job carries an IdempotencyKey and that key is already in the Redis
// idempotency store, the function returns success without enqueuing — the
// compensation was already initiated in a prior call.
func PushRollback(ctx context.Context, job SagaJob) error {
	// ── Idempotency check ─────────────────────────────────────────────────────
	if job.IdempotencyKey != "" && Client != nil {
		idemKey := sagaIdempotencyKey(job.IdempotencyKey)

		// SETNX (SET if Not eXists): atomically sets the key only if absent.
		// Returns true if the key was set (first time), false if already present.
		// Using a dedicated string key rather than a Redis SET gives us per-key TTL.
		set, err := Client.SetNX(ctx, idemKey, job.RollbackID, sagaIdempotencyTTL).Result()
		if err != nil {
			// Redis error on the idempotency check — log and continue enqueuing.
			// Failing closed here would silently drop valid rollbacks if Redis
			// is temporarily degraded.
			log.Printf("[QUEUE] Idempotency check error for key %s: %v — enqueuing anyway", job.IdempotencyKey, err)
		} else if !set {
			// Key already exists — this is a duplicate enqueue attempt.
			log.Printf("[QUEUE] Saga rollback deduplicated (idempotency key %s already seen)", job.IdempotencyKey)
			return nil // return success — the compensation is already in flight
		}
	}

	payload, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal saga job: %w", err)
	}
	if err := Client.LPush(ctx, "cicada_rollback_queue", payload).Err(); err != nil {
		return fmt.Errorf("redis lpush rollback: %w", err)
	}

	log.Printf("[QUEUE] Saga rollback enqueued: %s idem_key=%s", job.RollbackID, job.IdempotencyKey)
	return nil
}

// PushSwarmAnomaly enqueues an anomalous payload for the verification swarm.
func PushSwarmAnomaly(ctx context.Context, job SwarmJob) error {
	payload, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal swarm job: %w", err)
	}
	
	queueName := "cicada_swarm_queue"
	if job.Priority == "high" {
		queueName = "cicada_swarm_queue_high"
	}
	
	if err := Client.RPush(ctx, queueName, payload).Err(); err != nil {
		return fmt.Errorf("redis rpush swarm: %w", err)
	}
	log.Printf("[QUEUE] Swarm anomaly enqueued (%s) for agent: %s", queueName, job.AgentID)
	return nil
}

// IncrementTenantUsage atomically increments a tenant's request counter.
func IncrementTenantUsage(ctx context.Context, tenantID string, count int64) error {
	key := fmt.Sprintf("tenant:%s:usage", tenantID)
	return Client.IncrBy(ctx, key, count).Err()
}

// GetTenantUsage reads the current request count for a tenant from Redis.
func GetTenantUsage(ctx context.Context, tenantID string) (int64, error) {
	key := fmt.Sprintf("tenant:%s:usage", tenantID)
	val, err := Client.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}
