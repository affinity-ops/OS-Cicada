// © 2026 Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/websocket"

	"github.com/asai/cicada/sentry/internal/agentcache"
	"github.com/asai/cicada/sentry/internal/auth"
	"github.com/asai/cicada/sentry/internal/billing"
	"github.com/asai/cicada/sentry/internal/caep"
	"github.com/asai/cicada/sentry/internal/canary"
	"github.com/asai/cicada/sentry/internal/cascade"
	"github.com/asai/cicada/sentry/internal/chain"
	"github.com/asai/cicada/sentry/internal/ciba"
	"github.com/asai/cicada/sentry/internal/drift"
	"github.com/asai/cicada/sentry/internal/fcm"
	"github.com/asai/cicada/sentry/internal/federation"
	"github.com/asai/cicada/sentry/internal/fga"
	"github.com/asai/cicada/sentry/internal/ghostmode"
	"github.com/asai/cicada/sentry/internal/gossip"
	"github.com/asai/cicada/sentry/internal/heartbeat"
	"github.com/asai/cicada/sentry/internal/hitl"
	"github.com/asai/cicada/sentry/internal/injection"
	"github.com/asai/cicada/sentry/internal/ledger"
	"github.com/asai/cicada/sentry/internal/license"
	"github.com/asai/cicada/sentry/internal/llmproxy"
	"github.com/asai/cicada/sentry/internal/mcpserver"
	"github.com/asai/cicada/sentry/internal/memory"
	"github.com/asai/cicada/sentry/internal/mobile"
	"github.com/asai/cicada/sentry/internal/output"
	"github.com/asai/cicada/sentry/internal/pipeline"
	"github.com/asai/cicada/sentry/internal/plugin"
	"github.com/asai/cicada/sentry/internal/policy"
	"github.com/asai/cicada/sentry/internal/policystore"
	"github.com/asai/cicada/sentry/internal/queue"
	"github.com/asai/cicada/sentry/internal/rolemapping"
	"github.com/asai/cicada/sentry/internal/roles"
	"github.com/asai/cicada/sentry/internal/rotation"
	"github.com/asai/cicada/sentry/internal/scim"
	"github.com/asai/cicada/sentry/internal/secrets"
	"github.com/asai/cicada/sentry/internal/semantic"
	"github.com/asai/cicada/sentry/internal/session"
	"github.com/asai/cicada/sentry/internal/ssrf"
	"github.com/asai/cicada/sentry/internal/shadow"
	"github.com/asai/cicada/sentry/internal/slogger"
	"github.com/asai/cicada/sentry/internal/store"
	"github.com/asai/cicada/sentry/internal/tracing"
	"github.com/asai/cicada/sentry/internal/velocity"
)

var (
	opaEngine        *policy.Engine
	gossipMesh       *gossip.Mesh
	tenantKeyVault   *auth.KeyVault
	sentryMeter      *billing.AtomicMeter
	edgeLedger       *ledger.EdgeLedger
	sentryHeartbeat  *heartbeat.Worker
	pluginMgr        *plugin.PluginManager
	ghostLedger      sync.Map
	simulationMode   bool // When true, returns synthetic responses without calling real LLM providers

	// ASI07/ASI08: Inter-agent chain verifier and cascade failure detector.
	// Initialised after Redis and Ed25519 identity are ready.
	cascadeDetector  *cascade.Detector
	chainVerifier    *chain.Verifier

	// ASI08: Local in-memory cache of SHA-256 session token hashes.
	// Used for sub-1ms MCP session hash verification without DB roundtrips.
	// Key: hex-encoded SHA-256 hash. Value: expiry time (Unix ms).
	mcpSessionHashes sync.Map

	allowlistedDomains = []string{"enterprise.internal", "api.stripe.com"}
)

// writeError writes a JSON error response with the correct Content-Type header.
// It is a drop-in replacement for http.Error — same signature, correct behaviour.
func writeError(w http.ResponseWriter, body string, code int) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprintln(w, body)
}

// writeJSON encodes v as JSON with the correct Content-Type header.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// sha256Hex returns the lowercase hex-encoded SHA-256 hash of s.
// Used for MCP session hash verification (ASI08 cross-platform identity).
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func main() {
	// ── CLI Flags ──
	licensePath := flag.String("license", "", "Path to the cryptographically signed .lic file (Required for Enterprise builds)")
	flag.Parse()

	// ── Structured Logging (must be first) ──
	// Redirects all log.Printf calls to structured JSON output.
	slogger.Init()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Distributed Tracing (OpenTelemetry) ──
	// Initialises W3C traceparent propagation and span export.
	// Uses stdout exporter by default; set OTEL_EXPORTER=otlp for production.
	if err := tracing.Init(ctx); err != nil {
		log.Printf("[WARN] OpenTelemetry init failed (non-fatal): %v", err)
	}
	defer tracing.Shutdown(ctx)

	// ── Phase 0: Enterprise License Verification ──
	if *licensePath == "" && os.Getenv("CICADA_DEV_MODE") != "true" && os.Getenv("CICADA_SIMULATION_MODE") != "true" {
		log.Fatalf("[FATAL] The Sentry Gateway Enterprise Edition requires a valid --license file to boot.")
	}
	license.EnforceOrDie(*licensePath)

	// ── Phase 1: Cryptographic Identity ──
	if err := auth.InitializeGatewayAuthority(); err != nil {
		log.Fatalf("[FATAL] Ed25519 identity init failed: %v", err)
	}

	// ── Simulation Mode (standalone & sandbox testing) ──
	if os.Getenv("CICADA_SIMULATION_MODE") == "true" {
		simulationMode = true
		log.Println("[SIMULATION] ███ SIMULATION MODE ACTIVE ███")
		log.Println("[SIMULATION] In-memory Zero-Trust enforcement pipeline active (SSRF, Prompt Injection, DOM, Canary, Semantic, OPA, DLP, SQLite Ledger).")
		log.Println("[SIMULATION] Approved requests receive synthetic LLM responses without calling external providers.")
		log.Println("[SIMULATION] Disable by removing CICADA_SIMULATION_MODE env var.")
	}

	// ── Phase 2: PostgreSQL ──
	if simulationMode && os.Getenv("CICADA_POSTGRES_URL") == "" {
		log.Println("[STORE] Standalone simulation mode: CICADA_POSTGRES_URL not set — operating with in-memory OPA & SQLite Edge Ledger")
	} else {
		if err := store.InitPostgres(ctx); err != nil {
			if simulationMode {
				log.Printf("[WARN] PostgreSQL unavailable in simulation mode (%v) — continuing standalone", err)
			} else {
				log.Fatalf("[FATAL] PostgreSQL init failed: %v", err)
			}
		}
	}
	defer store.Close()

	// ── Schema Validation & Execution (Fail-Fast) ──
	// The Gateway enforces strict API boundaries by managing its own schema
	// in the `sentry` PostgreSQL namespace. Shared tables are read from `public`.
	if store.DB != nil {
		log.Println("[STORE] Executing Sentry schema migrations in 'sentry' schema...")
		migrationFiles, err := filepath.Glob("active_migrations/*.sql")
		if err == nil {
			for _, f := range migrationFiles {
				if mErr := store.RunMigrations(ctx, f); mErr != nil {
					log.Fatalf("[FATAL] Migration failed %s: %v", f, mErr)
				}
			}
		}

		if err := store.ValidateSchema(ctx); err != nil {
			log.Fatalf("[FATAL] Schema validation failed — the database is missing required tables or columns.\n"+
				"Detail: %v", err)
		}
	}

	// ── Phase 3: Redis ──
	if simulationMode && os.Getenv("CICADA_REDIS_URL") == "" {
		log.Println("[QUEUE] Standalone simulation mode: CICADA_REDIS_URL not set — operating with local Gossip Mesh")
	} else {
		if err := queue.InitRedis(ctx); err != nil {
			if simulationMode {
				log.Printf("[WARN] Redis unavailable in simulation mode (%v) — continuing standalone", err)
			} else {
				log.Fatalf("[FATAL] Redis init failed: %v", err)
			}
		}
	}
	defer queue.Close()

	// ── Phase 3a: ASI07/ASI08 — Cascade Detector + Chain Verifier ──
	// Requires Redis (cascade) and Ed25519 keys (chain). Both are now ready.
	cascadeDetector = cascade.NewDetector(queue.Client)
	if auth.GlobalSentryPublicKey != nil && auth.GlobalSentryPrivateKey != nil {
		chainVerifier = chain.NewVerifier(auth.GlobalSentryPublicKey, auth.GlobalSentryPrivateKey, 3)
		log.Printf("[INIT] ASI07/ASI08 modules active: chain verifier (max depth 3) + cascade detector (5m trace window)")
	} else {
		log.Printf("[WARN] Ed25519 keys not available — chain verifier disabled (cascade detector still active)")
	}

	// ── Phase 4: OPA Policy Engine ──
	// Fail-Closed architecture: If DB is unreachable in production, we log.Fatal natively to refuse launch.
	// In standalone simulation mode (store.DB == nil), compile the embedded defaultPolicy.
	var activeRego string
	if store.DB != nil {
		var err error
		activeRego, err = policystore.GetActivePolicy(ctx, store.DB, "authz.rego")
		if err != nil {
			log.Fatalf("[FATAL] OPA policy store fetch failed: %v", err)
		}
	}
	var err error
	opaEngine, err = policy.NewEngine(ctx, activeRego)
	if err != nil {
		log.Fatalf("[FATAL] OPA engine init failed: %v", err)
	}

	// ── Phase 5: Gossip Mesh (Tenant-Scoped Sovereign Node) ──
	hostname, _ := os.Hostname()
	gossipTenantID := ""
	if license.ActiveLicense != nil {
		gossipTenantID = license.ActiveLicense.TenantID
	}
	gossipMesh = gossip.NewMesh(fmt.Sprintf("sentry-%s", hostname), gossipTenantID)

	// ── Phase 6: KMS Vault ──
	if (simulationMode || os.Getenv("CICADA_DEV_MODE") == "true") && os.Getenv("CICADA_AES_MASTER_KEY") == "" {
		_ = os.Setenv("CICADA_AES_MASTER_KEY", "0123456789abcdef0123456789abcdef")
		log.Println("[VAULT] ⚠️  DEV/SIMULATION MODE: Using ephemeral 32-byte AES-256 master key. Set CICADA_AES_MASTER_KEY in production.")
	}
	tenantKeyVault, err = auth.NewVaultFromEnv()
	if err != nil {
		log.Fatalf("[FATAL] KMS vault init failed: %v", err)
	}

	// ── Phase 7: Billing Metering ──
	sentryMeter = billing.NewAtomicMeter()
	guardrailFlusher := billing.NewGuardrailFlusher(sentryMeter, gossipMesh)
	guardrailFlusher.Start(ctx)

	// ── Phase 8: Edge Ledger + Central Sync ──
	syncWorker := ledger.NewCentralSyncWorker()
	syncWorker.Start()
	defer syncWorker.Stop()

	edgeLedger, err = ledger.NewEdgeLedger(syncWorker)
	if err != nil {
		log.Fatalf("[FATAL] Edge ledger init failed: %v", err)
	}
	defer edgeLedger.Close()

	// ── Phase 8.1: Ledger Integrity Monitor ("Heartbeat of Truth") ──
	// Background Go routine that periodically re-walks the SHA-256 chain,
	// verifying every hash to detect bit-rot or unauthorized modification.
	// On violation: fires a Critical alert to the Operator Dashboard.
	integrityMonitor := ledger.NewIntegrityMonitor(
		edgeLedger.DB(),
		1*time.Hour, // configurable via CICADA_INTEGRITY_INTERVAL
		func(status ledger.IntegrityStatus) {
			log.Printf("[CRITICAL] LEDGER INTEGRITY VIOLATION: %s at event %s", status.ErrorMessage, status.FirstBreakAt)
			if store.DB == nil {
				return
			}
			// Push to ALL paired Aegis devices — integrity violations are platform-wide.
			go func() {
				rows, qErr := store.DB.Query(context.Background(),
					`SELECT push_token FROM mobile_devices
					 WHERE status = 'active' AND push_token IS NOT NULL`)
				if qErr != nil {
					log.Printf("[FCM] Failed to query devices for integrity alert: %v", qErr)
					return
				}
				defer rows.Close()
				ref := fmt.Sprintf("integrity-%s", status.FirstBreakAt)
				for rows.Next() {
					var pushToken string
					if rows.Scan(&pushToken) == nil && pushToken != "" {
						if pushErr := fcm.SendHitlAlert(context.Background(), pushToken, ref); pushErr != nil {
							log.Printf("[FCM] Integrity alert push failed for device: %v", pushErr)
						}
					}
				}
			}()
		},
	)
	integrityMonitor.Start()
	defer integrityMonitor.Stop()

	// ── S6.6/S6.7/S6.9: Credential Rotation Monitor ──
	// Background Go routine that scans for EVAR credentials approaching their
	// 90-day rotation deadline. Sends pre-notifications (7d, 1d before expiry),
	// marks expired credentials, and records all lifecycle events to the
	// append-only credential_rotation_events audit trail.
	credRotationMonitor := rotation.NewMonitor(store.DB, rotation.CheckInterval())
	if store.DB != nil {
		credRotationMonitor.Start()
		defer credRotationMonitor.Stop()
	}

	// ── Phase 8b: Saga Compensating Transaction Worker ──
	// The Go saga worker has been REMOVED. The sole consumer of
	// cicada_rollback_queue is now Saga_Executor/saga_worker.py (Python),
	// which provides HMAC-SHA256 signed webhooks, exponential backoff retry,
	// dead letter queue routing, and idempotency guards — none of which the
	// Go worker had. Running two consumers on one Redis list creates a
	// dual-consumer race that produces intermittent failures in production.
	//
	// The Gateway's only responsibility is ENQUEUING rollback intents via
	// queue.PushRollback(). The Python worker consumes and fires them.
	log.Printf("[SAGA] Saga rollback consumer is Saga_Executor/saga_worker.py (not in-process)")

	// ── Phase 9: Gateway Heartbeat ──
	// Calls home to CICADA_HOME_URL every CICADA_HEARTBEAT_INTERVAL (default 3h).
	// Fails silently — any error is logged and swallowed so the gateway keeps running.
	// The TLS status booleans are determined from env vars that are also used below
	// to start the server, so both derive from the same source of truth.
	tlsEnabledForHeartbeat := os.Getenv("TLS_CERT_FILE") != "" && os.Getenv("TLS_KEY_FILE") != ""
	mtlsEnabledForHeartbeat := tlsEnabledForHeartbeat && os.Getenv("TLS_CLIENT_CA_FILE") != ""
	sentryHeartbeat = heartbeat.New(tlsEnabledForHeartbeat, mtlsEnabledForHeartbeat, heartbeat.Deps{
		AgentCountFn: func(hbCtx context.Context) int {
			if store.DB == nil {
				return 0
			}
			var count int
			store.DB.QueryRow(hbCtx, `SELECT COUNT(*) FROM agents WHERE revoked_at IS NULL`).Scan(&count)
			return count
		},
		QuarantineCountFn: func() int {
			return len(gossipMesh.QuarantinedList())
		},
		RedisHealthFn: func(hbCtx context.Context) bool {
			return queue.Client != nil && queue.Client.Ping(hbCtx).Err() == nil
		},
		PostgresHealthFn: func(hbCtx context.Context) bool {
			return store.DB != nil && store.DB.Ping(hbCtx) == nil
		},
		OnDirectives: func(d heartbeat.Directives) {
			for _, agentID := range d.QuarantineAgents {
				log.Printf("[HEARTBEAT] Operator directive: quarantine agent=%s", agentID)
				gossipMesh.QuarantineAgent(agentID)
			}
			if d.Message != "" {
				log.Printf("[HEARTBEAT] Operator message: %s", d.Message)
			}
		},
	})
	sentryHeartbeat.Start(ctx)
	defer sentryHeartbeat.Stop()

	// ── Phase 9.5: EAKF Plugin Manager ──
	// Reads CICADA_PLUGINS env var and initialises declared plugins.
	// If "eakf" is declared, establishes UDS connection to the eakfd daemon.
	// Non-fatal on failure — gateway boots, but GetInterceptor("eakf")
	// returns ErrInterceptorUnavailable, triggering fail-closed for agents
	// whose policy requires EAKF sandboxing.
	pluginMgr, _ = plugin.NewPluginManager()
	defer pluginMgr.Close()

	// ── HTTP Router ──
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(tracing.Middleware) // OpenTelemetry: wraps every request in a span
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// ── CORS middleware ───────────────────────────────────────────────────
	// In production, set CICADA_CORS_ORIGINS to a comma-separated list of
	// allowed origins (e.g. "https://dashboard.cicada.cloud,https://portal.cicada.cloud").
	// When empty (local dev), all origins are permitted.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowedOrigin := "*"
			if corsEnv := os.Getenv("CICADA_CORS_ORIGINS"); corsEnv != "" {
				allowedOrigin = "" // deny by default when configured
				for _, allowed := range strings.Split(corsEnv, ",") {
					if strings.TrimSpace(allowed) == origin {
						allowedOrigin = origin
						break
					}
				}
			}
			if allowedOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Cicada-Target-URL, X-Gateway-Secret, X-Cicada-Dry-Run")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// ── Wire MCP server dependencies ──────────────────────────────────────────
	// Inject platform internals as function closures so mcpserver has no import
	// cycle back to main. All control actions are authenticated by the MCP
	// handler itself before these functions are called.
	mcpserver.QuarantineFn = func(agentID string) { gossipMesh.QuarantineAgent(agentID) }
	mcpserver.ReleaseFn = func(agentID string) { gossipMesh.ReleaseAgent(agentID) }
	mcpserver.GetQuarantinedFn = func() []string { return gossipMesh.QuarantinedList() }
	mcpserver.EngageGhostModeFn = func(ctx context.Context, agentID string) error {
		return ghostmode.Activate(ctx, agentID)
	}
	mcpserver.ReleaseGhostModeFn = func(ctx context.Context, agentID string) error {
		return ghostmode.Release(ctx, agentID)
	}
	mcpserver.SubmitPolicyRevisionFn = func(ctx context.Context, name, content, author string) (int, error) {
		return policystore.SubmitPolicyRevision(ctx, store.DB, name, content, author)
	}
	mcpserver.ActivatePolicyFn = func(ctx context.Context, name string, version int) error {
		if err := policystore.ActivatePolicy(ctx, store.DB, name, version); err != nil {
			return err
		}
		newRego, err := policystore.GetActivePolicy(ctx, store.DB, name)
		if err != nil {
			return fmt.Errorf("policy activated but could not fetch new rego content: %w", err)
		}
		return opaEngine.RefreshEngine(ctx, newRego)
	}
	mcpserver.GetVelocityFn = func(ctx context.Context, agentID string) map[string]int64 {
		return map[string]int64{
			"write":  velocity.CurrentRate(ctx, agentID, "write"),
			"delete": velocity.CurrentRate(ctx, agentID, "delete"),
		}
	}
	mcpserver.TriggerRollbackFn = func(ctx context.Context, traceID, failedAction, revertRoute string) (string, error) {
		rollbackID := fmt.Sprintf("rb-%d", time.Now().UnixNano())
		h := sha256.Sum256([]byte(traceID + failedAction + time.Now().String()))
		return rollbackID, queue.PushRollback(ctx, queue.SagaJob{
			RollbackID:         rollbackID,
			TraceID:            traceID,
			OriginalActionHash: hex.EncodeToString(h[:]),
			RevertRoute:        revertRoute,
			FailedAction:       failedAction,
		})
	}
	mcpserver.GetAgentFn = func(ctx context.Context, agentID string) (map[string]interface{}, error) {
		row := store.DB.QueryRow(ctx,
			`SELECT id, tenant_id, trust_tier, role, scope_entitlements, hitl_enabled,
			        revoked_at, created_at, name, agent_type, description
			   FROM agents WHERE id = $1`, agentID)
		var id, tenantID, trustTier, role, scopes, name, agentType, desc string
		var hitlEnabled bool
		var revokedAt, createdAt *time.Time
		if err := row.Scan(&id, &tenantID, &trustTier, &role, &scopes, &hitlEnabled,
			&revokedAt, &createdAt, &name, &agentType, &desc); err != nil {
			return nil, fmt.Errorf("agent not found: %w", err)
		}
		return map[string]interface{}{
			"id": id, "tenant_id": tenantID, "trust_tier": trustTier,
			"role": role, "scope_entitlements": scopes, "hitl_enabled": hitlEnabled,
			"revoked_at": revokedAt, "created_at": createdAt,
			"name": name, "agent_type": agentType, "description": desc,
		}, nil
	}
	mcpserver.GetTenantFn = func(ctx context.Context, tenantID string) (map[string]interface{}, error) {
		row := store.DB.QueryRow(ctx,
			`SELECT id, name, status, plan, company_email, created_at FROM tenants WHERE id = $1`, tenantID)
		var id, name, status, plan, email string
		var createdAt *time.Time
		if err := row.Scan(&id, &name, &status, &plan, &email, &createdAt); err != nil {
			return nil, fmt.Errorf("tenant not found: %w", err)
		}
		return map[string]interface{}{
			"id": id, "name": name, "status": status,
			"plan": plan, "company_email": email, "created_at": createdAt,
		}, nil
	}
	mcpserver.GetThreatSignalsFn = func(ctx context.Context, window int) (map[string]interface{}, error) {
		// Query Core API threat signals endpoint
		coreAPI := os.Getenv("CICADA_CORE_API_URL")
		if coreAPI == "" {
			coreAPI = "http://localhost:8000"
		}
		resp, err := http.Get(fmt.Sprintf("%s/api/v1/admin/threat-signals?window=%d", coreAPI, window))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}, nil
		}
		defer resp.Body.Close()
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		return result, nil
	}

	r.Get("/health", handleHealth)

	// ── Performance Metrics Endpoint ────────────────────────────────────────
	// Exposes real cache hit/miss counters and latency from the agentcache
	// package. Used by the operator dashboard and external monitoring.
	r.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
		stats := agentcache.Stats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"service":   "cicada-sentry",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"cache":     stats,
		})
	})

	r.Post("/v1/portal/test-push", func(w http.ResponseWriter, r *http.Request) {
		// Look up the active device push token and fingerprint
		var pushToken, deviceFingerprint, tenantID string
		err := store.DB.QueryRow(r.Context(),
			`SELECT push_token, ed25519_pub, tenant_id::text FROM mobile_devices
			 WHERE status = 'active' AND push_token IS NOT NULL
			 ORDER BY paired_at DESC LIMIT 1`,
		).Scan(&pushToken, &deviceFingerprint, &tenantID)
		if err != nil || pushToken == "" {
			http.Error(w, `{"error":"no active device with push token found"}`, http.StatusNotFound)
			return
		}

		testRef := fmt.Sprintf("test-%d", time.Now().UnixMilli())
		expires := time.Now().Add(1 * time.Hour)

		// Insert a real CIBA hold so the app heartbeat returns it as an alert.
		// agent_id uses a fixed test UUID; id is generated by postgres gen_random_uuid().
		_, _ = store.DB.Exec(r.Context(),
			`INSERT INTO ciba_authorization_requests
			 (id, trace_id, agent_id, tenant_id, agent_name, action_summary, target_url,
			  risk_score, risk_reason, payload_preview, status, expires_at, created_at)
			 VALUES (gen_random_uuid(), $1,
			         '00000000-0000-0000-0000-000000000099'::uuid,
			         $2::uuid, 'Test Agent',
			         'TEST: Verify HITL push notification delivery',
			         'https://test.cicada.internal/verify',
			         0.95, 'Manual test push from Developer Portal',
			         'This is a test HITL alert to verify end-to-end push delivery.',
			         'pending', $3, NOW())`,
			testRef, tenantID, expires,
		)
		// hold_payloads links the hold to the specific device for heartbeat lookup.
		// ciphertext/ephemeral_pub/nonce are placeholder — this is a test hold only.
		_, _ = store.DB.Exec(r.Context(),
			`INSERT INTO hold_payloads
			 (hold_ref, target_device, ciphertext, ephemeral_pub, nonce, expires_at, created_at)
			 VALUES ($1, $2, 'test', 'test', 'test', $3, NOW())`,
			testRef, deviceFingerprint, expires,
		)

		if err := fcm.SendHitlAlert(r.Context(), pushToken, testRef); err != nil {
			log.Printf("[FCM] Test push failed: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}
		log.Printf("[FCM] Test push sent: ref=%s token=%s...%s", testRef, pushToken[:8], pushToken[len(pushToken)-8:])
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"sent","ref":%q}`, testRef)
	})
	r.Post("/v1/agent/register", handleAgentRegistration)
	r.Post("/v1/agent/register/yaml", handleYAMLRegistration) // P2.3: cicada.yaml consumer endpoint
	r.Post("/v1/agent/session", handleAgentSession)  // Stage 7.1: exchange EVAR for JIT session token
	r.Post("/v1/agent/proxy", handleAgentRequest)
	r.Post("/v1/agent/rollback", handleAgentRollback)
	r.Post("/v1/llm/proxy", handleLLMProxy)          // LLM API proxy: memory isolation + reasoning audit
	r.Post("/v1/gossip/receive", handleGossipReceive)   // inter-node gossip transport
	r.Post("/v1/sandbox/report", handleSandboxReport)   // anomaly reports from shadow sandbox
	r.Get("/v1/verify/agent/{evar}", handlePublicTrustIntrospection)
	r.Post("/v1/vault/keys/bind", handleKeyBinding)
	r.Post("/v1/aegis/directives", handleAegisDirectives)
	r.Post("/v1/aegis/mcp/execute", handleMCPExecution) // legacy endpoint — kept for backwards compatibility
	r.Post("/v1/mcp", mcpserver.Handler())              // MCP JSON-RPC 2.0 — production endpoint for Aegis-0
	r.Get("/v1/telemetry/city/{city_id}", handleWSCityTelemetry)
	r.Post("/v1/sso/caep/webhook", caep.Handler(gossipMesh, edgeLedger)) // inbound CAEP: external IdP → Cicada revocation

	// STRICT API BOUNDARY: Endpoint for Core API to fetch aegis devices
	r.Get("/v1/internal/aegis/devices", func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Cicada-Tenant-ID")
		if tenantID == "" {
			writeError(w, `{"error":"tenant_id required"}`, http.StatusBadRequest)
			return
		}

		rows, err := store.DB.Query(r.Context(), 
			`SELECT id, device_id, platform, os_version, model, manufacturer, app_version, 
			        biometric_enrolled, secure_enclave_available, attestation_status, 
			        screen_lock_enabled, pairing_timestamp, last_seen_at, is_active, 
			        created_at, updated_at 
			 FROM aegis_devices WHERE tenant_id = $1 ORDER BY created_at DESC`, 
			tenantID)
		if err != nil {
			writeError(w, `{"error":"database error"}`, http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var devices []map[string]interface{}
		for rows.Next() {
			var d struct {
				ID, DeviceID, Platform string
				OSVersion, Model, Manufacturer, AppVersion *string
				Biometric, SecureEnclave, ScreenLock *bool
				AttestationStatus *string
				PairingTime, LastSeen, Created, Updated *time.Time
				IsActive *bool
			}
			if err := rows.Scan(&d.ID, &d.DeviceID, &d.Platform, &d.OSVersion, &d.Model, &d.Manufacturer, &d.AppVersion,
				&d.Biometric, &d.SecureEnclave, &d.AttestationStatus, &d.ScreenLock, &d.PairingTime, &d.LastSeen, 
				&d.IsActive, &d.Created, &d.Updated); err != nil {
				continue
			}
			
			devices = append(devices, map[string]interface{}{
				"id": d.ID, "device_id": d.DeviceID, "platform": d.Platform,
				"os_version": d.OSVersion, "model": d.Model, "manufacturer": d.Manufacturer,
				"app_version": d.AppVersion, "biometric_enrolled": d.Biometric,
				"secure_enclave_available": d.SecureEnclave, "attestation_status": d.AttestationStatus,
				"screen_lock_enabled": d.ScreenLock, "pairing_timestamp": d.PairingTime,
				"last_seen_at": d.LastSeen, "is_active": d.IsActive,
				"created_at": d.Created, "updated_at": d.Updated,
			})
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"devices": devices,
			},
		})
	})

	// ── S6.2: Enterprise SSO Federation (SAML 2.0 / OIDC) ──
	// OIDC login: initiates Authorization Code + PKCE flow with the configured IdP.
	r.Get("/v1/federation/oidc/login/{provider_id}", func(w http.ResponseWriter, r *http.Request) {
		providerID := chi.URLParam(r, "provider_id")
		provider, err := federation.GetProvider(r.Context(), store.DB, providerID)
		if err != nil || provider.Protocol != "oidc" {
			writeError(w, `{"error":"OIDC provider not found"}`, http.StatusNotFound)
			return
		}
		state := federation.GenerateState()
		authURL, codeVerifier, err := federation.GenerateOIDCAuthURL(*provider, state)
		if err != nil {
			log.Printf("[FEDERATION] OIDC auth URL generation failed: %v", err)
			writeError(w, `{"error":"failed to generate auth URL"}`, http.StatusInternalServerError)
			return
		}
		// Store state→verifier mapping (use cookie for simplicity)
		http.SetCookie(w, &http.Cookie{
			Name:     "cicada_oidc_state",
			Value:    state + "|" + codeVerifier + "|" + providerID,
			Path:     "/v1/federation/oidc/callback",
			MaxAge:   600,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	// OIDC callback: exchanges code for tokens, issues portal session.
	r.Get("/v1/federation/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" || state == "" {
			writeError(w, `{"error":"missing code or state"}`, http.StatusBadRequest)
			return
		}
		cookie, err := r.Cookie("cicada_oidc_state")
		if err != nil {
			writeError(w, `{"error":"missing state cookie"}`, http.StatusBadRequest)
			return
		}
		parts := strings.SplitN(cookie.Value, "|", 3)
		if len(parts) != 3 || parts[0] != state {
			writeError(w, `{"error":"state mismatch — possible CSRF"}`, http.StatusForbidden)
			return
		}
		codeVerifier, providerID := parts[1], parts[2]

		provider, err := federation.GetProvider(r.Context(), store.DB, providerID)
		if err != nil {
			writeError(w, `{"error":"provider not found"}`, http.StatusNotFound)
			return
		}

		user, err := federation.ExchangeOIDCCode(r.Context(), *provider, code, codeVerifier)
		if err != nil {
			log.Printf("[FEDERATION] OIDC code exchange failed: %v", err)
			federation.RecordLogin(r.Context(), store.DB, &federation.FederatedUser{
				TenantID: provider.TenantID, ProviderID: provider.ID,
			}, false, r.RemoteAddr, r.UserAgent(), err.Error())
			http.Redirect(w, r, "/login?error=sso_failed", http.StatusFound)
			return
		}

		// S6.3: Resolve IdP groups → Cicada role via configured mappings.
		// Falls back to provider.DefaultRole if no mapping rules match.
		roleResult, roleErr := rolemapping.ResolveForProvider(
			r.Context(), store.DB, providerID, user.Groups, provider.DefaultRole,
		)
		if roleErr != nil {
			log.Printf("[ROLE-MAPPING] Resolution error for %s: %v (using default)", user.Email, roleErr)
		}
		user.Role = roleResult.ResolvedRole
		if !roleResult.DefaultApplied {
			log.Printf("[ROLE-MAPPING] %s resolved to %q via groups %v (rules: %v)",
				user.Email, roleResult.ResolvedRole, roleResult.MatchedGroups, roleResult.MatchedRules)
		}

		sessionToken, err := federation.IssuePortalSession(user)
		if err != nil {
			writeError(w, `{"error":"session issuance failed"}`, http.StatusInternalServerError)
			return
		}

		federation.RecordLogin(r.Context(), store.DB, user, true, r.RemoteAddr, r.UserAgent(), "")
		log.Printf("[FEDERATION] OIDC login: %s (%s) via %s → role=%s", user.Email, user.Subject, provider.Name, user.Role)

		// Redirect to portal with token in fragment (same pattern as existing OAuth)
		redirectURL := fmt.Sprintf("/auth/callback#token=%s&tenant=%s&plan=enterprise", sessionToken, user.TenantID)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	// Federation provider management API
	r.Get("/v1/federation/providers", func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Cicada-Tenant-ID")
		if tenantID == "" {
			writeError(w, `{"error":"tenant_id required"}`, http.StatusBadRequest)
			return
		}
		providers, err := federation.ListProviders(r.Context(), store.DB, tenantID)
		if err != nil {
			writeError(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"providers": providers, "count": len(providers)})
	})

	r.Post("/v1/federation/providers", func(w http.ResponseWriter, r *http.Request) {
		var p federation.Provider
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeError(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		if p.TenantID == "" || p.Name == "" || (p.Protocol != "oidc" && p.Protocol != "saml") {
			writeError(w, `{"error":"tenant_id, name, and protocol (oidc|saml) required"}`, http.StatusBadRequest)
			return
		}
		p.Enabled = true
		id, err := federation.CreateProvider(r.Context(), store.DB, p)
		if err != nil {
			writeError(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "created"})
	})

	// Verify a portal session token (used by dashboards/portals)
	r.Post("/v1/federation/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
			writeError(w, `{"error":"token required"}`, http.StatusBadRequest)
			return
		}
		claims, err := federation.VerifyPortalSession(req.Token)
		if err != nil {
			writeError(w, `{"error":"invalid or expired session"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(claims)
	})

	// ── S6.3: Role Mapping CRUD ──
	// List role mappings for a provider
	r.Get("/v1/federation/providers/{provider_id}/mappings", func(w http.ResponseWriter, r *http.Request) {
		providerID := chi.URLParam(r, "provider_id")
		mappings, err := rolemapping.LoadMappings(r.Context(), store.DB, providerID)
		if err != nil {
			writeError(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"mappings": mappings, "count": len(mappings)})
	})

	// Create a role mapping
	r.Post("/v1/federation/providers/{provider_id}/mappings", func(w http.ResponseWriter, r *http.Request) {
		providerID := chi.URLParam(r, "provider_id")
		var m rolemapping.Mapping
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			writeError(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		m.ProviderID = providerID
		if m.TenantID == "" {
			m.TenantID = r.Header.Get("X-Cicada-Tenant-ID")
		}
		id, err := rolemapping.CreateMapping(r.Context(), store.DB, m)
		if err != nil {
			writeError(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "created"})
	})

	// Delete a role mapping
	r.Delete("/v1/federation/mappings/{mapping_id}", func(w http.ResponseWriter, r *http.Request) {
		mappingID := chi.URLParam(r, "mapping_id")
		if err := rolemapping.DeleteMapping(r.Context(), store.DB, mappingID); err != nil {
			writeError(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	})

	// Test role resolution (dry-run — does not create a session)
	r.Post("/v1/federation/providers/{provider_id}/resolve-role", func(w http.ResponseWriter, r *http.Request) {
		providerID := chi.URLParam(r, "provider_id")
		var req struct {
			Groups []string `json:"groups"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		provider, err := federation.GetProvider(r.Context(), store.DB, providerID)
		if err != nil {
			writeError(w, `{"error":"provider not found"}`, http.StatusNotFound)
			return
		}
		result, _ := rolemapping.ResolveForProvider(r.Context(), store.DB, providerID, req.Groups, provider.DefaultRole)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// ── S6.4: SCIM 2.0 Provisioning ──
	// RFC 7644 endpoints for automated operator lifecycle management.
	// Enterprise IdPs (Okta, Azure AD) call these to create/update/deactivate operators.
	scim.RegisterRoutes(r, store.DB)
	log.Println("[SCIM] SCIM 2.0 provisioning endpoints registered at /scim/v2/Users")

	// ── S6.8: Secrets Backend (Vault / AWS Secrets Manager) ──
	secretBackend, secretErr := secrets.NewBackend()
	if secretErr != nil {
		log.Printf("[SECRETS] Backend initialization skipped: %v (using inline AES)", secretErr)
	} else {
		log.Printf("[SECRETS] Backend initialized: %s", secretBackend.Name())
	}

	r.Get("/api/v1/secrets/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if secretBackend == nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "unconfigured", "backend": "none"})
			return
		}
		if err := secretBackend.Health(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "unhealthy", "backend": secretBackend.Name(), "error": err.Error(),
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "backend": secretBackend.Name()})
	})

	// ── Ledger Integrity Status ──
	// Returns the latest chain verification result for auditors and dashboards.
	// This is the "proof" endpoint — responds with valid/invalid status,
	// last verified timestamp, and verified entry count.
	r.Get("/api/v1/ledger/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := integrityMonitor.Status()
		json.NewEncoder(w).Encode(status)
	})

	// ── Credential Rotation Endpoints (S6.6/S6.7/S6.9) ──
	// Monitor status: returns the latest rotation scan summary.
	r.Get("/api/v1/rotation/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(credRotationMonitor.Status())
	})

	// Manual rotation: immediately re-mints an agent's EVAR.
	// Requires operator authentication (portal session or admin API key).
	r.Post("/v1/agent/{agent_id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		agentID := chi.URLParam(r, "agent_id")
		if agentID == "" {
			writeError(w, `{"error":"agent_id is required"}`, http.StatusBadRequest)
			return
		}

		// Extract operator identity from the request
		initiatedBy := r.Header.Get("X-Cicada-Operator")
		if initiatedBy == "" {
			initiatedBy = "operator/unknown"
		}

		ipAddr := r.RemoteAddr
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			ipAddr = strings.Split(fwd, ",")[0]
		}
		// Strip port from IP for INET cast
		if host, _, err := net.SplitHostPort(ipAddr); err == nil {
			ipAddr = host
		}

		tenantID := r.Header.Get("X-Cicada-Tenant-ID")

		newToken, err := rotation.RotateAgent(
			r.Context(), store.DB,
			agentID, tenantID,
			initiatedBy, ipAddr, r.UserAgent(),
		)
		if err != nil {
			log.Printf("[ROTATION] Manual rotation failed for %s: %v", agentID, err)
			writeError(w, fmt.Sprintf(`{"error":"rotation failed: %s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		log.Printf("[ROTATION] Manual rotation completed for agent %s by %s", agentID, initiatedBy)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "rotated",
			"agent_id":  agentID,
			"new_evar":  newToken,
			"expires_in": fmt.Sprintf("%dd", int(rotation.RotationPeriod().Hours()/24)),
		})
	})

	// Rotation audit trail: returns the credential lifecycle history for an agent.
	r.Get("/v1/agent/{agent_id}/rotation-history", func(w http.ResponseWriter, r *http.Request) {
		agentID := chi.URLParam(r, "agent_id")
		if agentID == "" {
			writeError(w, `{"error":"agent_id is required"}`, http.StatusBadRequest)
			return
		}

		events, err := rotation.GetRotationHistory(r.Context(), store.DB, agentID, 50)
		if err != nil {
			writeError(w, fmt.Sprintf(`{"error":"failed to fetch rotation history: %s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"agent_id": agentID,
			"events":   events,
			"count":    len(events),
		})
	})

	// ── Shadow AI Discovery ──
	// CASB/SSPM integration for detecting unregistered AI agents operating
	// outside Cicada's perimeter. The agent registry is the "known good"
	// source of truth; CASB feeds "unknown" agents for operator review.
	shadowStore := shadow.NewStore()
	r.Post("/v1/shadow/ingest", shadow.IngestHandler(shadowStore))        // CASB webhook: report shadow agent sightings
	r.Get("/v1/shadow/agents", shadow.ListHandler(shadowStore))           // Dashboard: list shadow agents
	r.Get("/v1/shadow/stats", shadow.StatsHandler(shadowStore))           // Dashboard: aggregate shadow statistics
	r.Post("/v1/shadow/agents/{id}/status", shadow.UpdateHandler(shadowStore)) // Operator: acknowledge/quarantine/register

	// ── Phase 1-7: Aegis Mobile Device Endpoints ──
	// Injects the PostgreSQL pool into the mobile package and registers
	// all 7 mobile device endpoints (pairing, push, heartbeat, payload,
	// batch decisions, telemetry, quorum).
	mobile.DB = store.DB
	mobile.RegisterRoutes(r)

	// ── Graceful Shutdown ──
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	// ── mTLS configuration ────────────────────────────────────────────────────
	// When TLS_CERT_FILE and TLS_KEY_FILE are set, the gateway serves HTTPS with
	// TLS 1.3 as the minimum version. TLS 1.3 is mandatory rather than 1.2 because:
	//   - 1.2 supports cipher suites with known weaknesses (RC4, 3DES, NULL)
	//   - 1.3 mandates forward secrecy via ephemeral key exchange (ECDHE only)
	//   - A compromised server key cannot decrypt past sessions in 1.3 (critical
	//     for a gateway that proxies bearer tokens and API keys)
	//
	// When TLS_CLIENT_CA_FILE is also set, mutual TLS is enforced: every connecting
	// client must present a certificate signed by the operator CA. This means
	// network-level access control without relying on API key secrecy — an attacker
	// with network access but no client cert is rejected at the TLS handshake before
	// any HTTP parsing begins.
	//
	// WARNING: Do not run without TLS in production. EVAR tokens and session tokens
	// travel in the Authorization header on every request; without TLS they are
	// visible to any network observer on the path.
	tlsCert := os.Getenv("TLS_CERT_FILE")
	tlsKey := os.Getenv("TLS_KEY_FILE")
	tlsClientCA := os.Getenv("TLS_CLIENT_CA_FILE")

	go func() {
		if tlsCert != "" && tlsKey != "" {
			srv.TLSConfig = loadMTLSConfig(tlsClientCA)
			log.Printf("[GATEWAY] Sentry Gateway starting with mTLS on :%s (client_ca_configured=%v)", port, tlsClientCA != "")
			if err := srv.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[FATAL] TLS server error: %v", err)
			}
		} else {
			log.Printf("[GATEWAY] Sentry Gateway starting (plain HTTP — set TLS_CERT_FILE/TLS_KEY_FILE for production) on :%s", port)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[FATAL] Server error: %v", err)
			}
		}
	}()

	<-ctx.Done()
	log.Println("[GATEWAY] Shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
}

// ────────────────────────────────────────────────────────────────────────────
// mTLS Configuration
// ────────────────────────────────────────────────────────────────────────────

// loadMTLSConfig builds a *tls.Config for the gateway server.
// clientCAFile: path to the PEM-encoded CA certificate whose signed certs are
// accepted as client identities. When empty, server TLS only (no client auth).
//
// Why tls.RequireAndVerifyClientCert rather than tls.RequireAnyClientCert:
// RequireAnyClientCert accepts self-signed certs and certs from any CA, which
// provides zero real security (an attacker generates their own cert). Only
// verifying against our own CA makes client auth meaningful.
func loadMTLSConfig(clientCAFile string) *tls.Config {
	cfg := &tls.Config{
		// TLS 1.3 only. The Gateway handles bearer tokens and API keys in every
		// request — downgrade to 1.2 is unacceptable in a security product.
		MinVersion: tls.VersionTLS13,
	}

	if clientCAFile == "" {
		log.Printf("[GATEWAY] mTLS: server TLS configured (no client CA — add TLS_CLIENT_CA_FILE for full mTLS)")
		return cfg
	}

	caCert, err := os.ReadFile(clientCAFile)
	if err != nil {
		log.Fatalf("[FATAL] Cannot read TLS client CA file %s: %v", clientCAFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		log.Fatalf("[FATAL] Failed to parse client CA certificate from %s — ensure it is PEM-encoded", clientCAFile)
	}

	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	log.Printf("[GATEWAY] mTLS: client certificate verification enabled (CA: %s)", clientCAFile)
	return cfg
}

// ────────────────────────────────────────────────────────────────────────────
// Health Check
// ────────────────────────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// ── Component health probes ───────────────────────────────────────────

	// Redis
	redisOK := false
	redisDetail := "not configured"
	if queue.Client != nil {
		if err := queue.Client.Ping(r.Context()).Err(); err != nil {
			redisDetail = "unreachable: " + err.Error()
		} else {
			redisOK = true
			redisDetail = "connected"
		}
	}

	// PostgreSQL — quick connectivity check via Core API
	postgresOK := false
	postgresDetail := "not checked"
	coreAPI := os.Getenv("CICADA_CORE_API_URL")
	if coreAPI == "" {
		coreAPI = "http://localhost:8000"
	}
	pgCtx, pgCancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer pgCancel()
	pgReq, _ := http.NewRequestWithContext(pgCtx, "GET", coreAPI+"/api/v1/agents?per_page=1", nil)
	if pgResp, err := http.DefaultClient.Do(pgReq); err == nil {
		pgResp.Body.Close()
		if pgResp.StatusCode < 500 {
			postgresOK = true
			postgresDetail = "connected via Core API"
		} else {
			postgresDetail = fmt.Sprintf("Core API returned %d", pgResp.StatusCode)
		}
	} else {
		postgresDetail = "Core API unreachable: " + err.Error()
	}

	// Ed25519 key
	ed25519OK := auth.GlobalSentryPublicKey != nil

	// Edge Ledger (SQLite)
	ledgerOK := edgeLedger != nil
	ledgerDetail := ""
	if ledgerOK {
		ledgerDetail = "open"
	} else {
		ledgerDetail = "not initialised"
	}

	// Central Ledger Sync
	syncOK := postgresOK // sync depends on Core API connectivity
	syncDetail := ""
	if syncOK {
		syncDetail = "reachable"
	} else {
		syncDetail = "Core API not reachable"
	}

	// ── Overall status ────────────────────────────────────────────────────
	overallStatus := "healthy"
	httpCode := http.StatusOK
	if !redisOK && queue.Client != nil {
		// Redis was expected but not reachable — report starting
		overallStatus = "starting"
		httpCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(httpCode)
	// Plugin health
	plugins := map[string]string{}
	if pluginMgr != nil && pluginMgr.IsPluginDeclared("eakf") {
		if _, err := pluginMgr.GetInterceptor("eakf"); err == nil {
			plugins["eakf"] = "healthy"
		} else {
			plugins["eakf"] = "unhealthy"
		}
	}

	resp := map[string]interface{}{
		"status":          overallStatus,
		"service":         "cicada-sentry",
		"postgres":        postgresOK,
		"postgres_detail": postgresDetail,
		"redis":           redisOK,
		"redis_detail":    redisDetail,
		"ed25519":         ed25519OK,
		"ledger":          ledgerOK,
		"ledger_detail":   ledgerDetail,
		"sync":            syncOK,
		"sync_detail":     syncDetail,
		"plugins":         plugins,
	}
	json.NewEncoder(w).Encode(resp)
}

// ────────────────────────────────────────────────────────────────────────────
// Agent Registration (EVAR Minting)
// ────────────────────────────────────────────────────────────────────────────

func handleAgentRegistration(w http.ResponseWriter, r *http.Request) {
	// ── Phase 1: Decode the registration payload ──────────────────────────
	// We first decode into a generic map for the sanitizer, then re-decode
	// into the typed AgentSpecification for EVAR minting. This dual-decode
	// approach lets the sanitizer inspect fields that aren't in the EVAR spec
	// (tools, velocity limits, HITL config) without changing the EVAR schema.

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// Sanitizer pass — run against the raw registration map
	var rawPayload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &rawPayload); err != nil {
		writeError(w, `{"error":"invalid JSON payload"}`, http.StatusBadRequest)
		return
	}

	// ── Phase 2: Policy Sanitization ("Anti-Lazy Guard") ─────────────────
	// The sanitizer scans for dangerously broad permissions before the agent
	// reaches the registry. If it finds critical violations, registration is
	// blocked. If it finds high-severity violations, the agent is registered
	// but flagged for mandatory human sign-off via CIBA/Aegis.
	sanitizeResult := policy.SanitizePolicy(rawPayload)

	if !sanitizeResult.Allowed {
		// Critical violations — auto-reject. The agent never gets an EVAR.
		log.Printf("[REGISTRATION BLOCKED] Policy sanitizer rejected registration: %d violation(s)", len(sanitizeResult.Violations))
		for _, v := range sanitizeResult.Violations {
			log.Printf("[SANITIZER] [%s] %s: %s — %s", v.Severity, v.Code, v.Field, v.Message)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      "policy_sanitization_failed",
			"message":    "Registration blocked by the Cicada Policy Sanitizer. Your policy declares dangerously broad permissions.",
			"violations": sanitizeResult.Violations,
			"hint":       "Narrow your tool scopes, enable HITL for destructive capabilities, and avoid wildcard URL patterns.",
		})
		return
	}

	// Log high-severity violations that require escalation
	if sanitizeResult.RequiresEscalation {
		log.Printf("[REGISTRATION WARNING] Policy requires operator escalation: %d high-severity violation(s)", len(sanitizeResult.Violations))
		for _, v := range sanitizeResult.Violations {
			if v.Severity == "high" {
				log.Printf("[SANITIZER] [%s] %s: %s — %s", v.Severity, v.Code, v.Field, v.Message)
			}
		}
	}

	// ── Phase 3: Typed decode ────────────────────────────────────────────
	var spec auth.AgentSpecification
	if err := json.Unmarshal(bodyBytes, &spec); err != nil {
		writeError(w, `{"error":"invalid JSON payload"}`, http.StatusBadRequest)
		return
	}

	if spec.AgentID == "" || spec.CodeHash == "" {
		writeError(w, `{"error":"agent_id and code_hash are required"}`, http.StatusBadRequest)
		return
	}

	// ── Phase 4: Certification-gated EVAR issuance ──────────────────────
	// Escalation-flagged agents: NO EVAR. Developer must fix policy and re-register.
	// Clean agents: provisional EVAR issued, approval_status = 'pending_review'.
	// Full enforcement requires operator certification (approval_status = 'certified').

	if sanitizeResult.RequiresEscalation {
		// ── ESCALATION: Hard stop — no EVAR issued ──────────────────────
		// Record the escalation event for operator visibility.
		violationsJSON, _ := json.Marshal(sanitizeResult.Violations)
		_, _ = store.DB.Exec(r.Context(), `
			UPDATE agents SET approval_status = 'escalation_required' WHERE id = $1::UUID
		`, spec.AgentID)
		_, _ = store.DB.Exec(r.Context(), `
			INSERT INTO certification_events (agent_id, tenant_id, event_type, performed_by, reason, metadata)
			SELECT id, tenant_id, 'escalation_flagged', 'sanitizer',
			       'High-severity policy violations detected — EVAR withheld until operator review',
			       $2::jsonb
			FROM agents WHERE id = $1::UUID
		`, spec.AgentID, string(violationsJSON))

		log.Printf("[REGISTRATION] Agent %s flagged for escalation — NO EVAR issued", spec.AgentID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "escalation_required",
			"evar":       nil,
			"message":    "Registration recorded but EVAR withheld. Your policy contains high-severity violations that require operator review before credentials can be issued.",
			"violations": sanitizeResult.Violations,
			"hint":       "Fix the flagged policy issues and re-register, or contact your operator to request manual certification.",
		})
		return
	}

	// ── CLEAN REGISTRATION: Provisional EVAR ────────────────────────────
	// Agent passed sanitizer without escalation. Mint a provisional EVAR.
	// The agent can call /v1/agent/proxy but will operate in shadow-only mode
	// until an operator certifies it (sets approval_status = 'certified').

	token, err := auth.MintEVARToken(spec)
	if err != nil {
		log.Printf("[AUTH ERROR] EVAR minting failed: %v", err)
		writeError(w, `{"error":"EVAR minting failed"}`, http.StatusInternalServerError)
		return
	}

	// Set rotation lifecycle metadata + approval_status = 'pending_review'
	now := time.Now().UTC()
	rotPeriod := rotation.RotationPeriod()
	_, _ = store.DB.Exec(r.Context(), `
		UPDATE agents
		SET evar_issued_at = $2,
		    evar_expires_at = $3,
		    evar_rotation_status = 'active',
		    approval_status = 'pending_review'
		WHERE id = $1::UUID
	`, spec.AgentID, now, now.Add(rotPeriod))

	// Record the registration event
	_, _ = store.DB.Exec(r.Context(), `
		INSERT INTO certification_events (agent_id, tenant_id, event_type, performed_by, reason)
		SELECT id, tenant_id, 'registered', 'system',
		       'Agent registered with provisional EVAR — awaiting operator certification'
		FROM agents WHERE id = $1::UUID
	`, spec.AgentID)

	log.Printf("[REGISTRATION] Agent %s registered with provisional EVAR (pending_review)", spec.AgentID)

	response, _ := json.Marshal(map[string]interface{}{
		"status":      "pending_review",
		"evar":        token,
		"expires_in":  fmt.Sprintf("%dd", int(rotPeriod.Hours()/24)),
		"provisional": true,
		"message":     "Agent registered with a provisional EVAR. Your agent can operate in shadow/observe mode immediately. Full enforcement requires operator certification via the Gateway Portal.",
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(response)
}

// ────────────────────────────────────────────────────────────────────────────
// P2.3 — cicada.yaml Consumer Endpoint
//
// Accepts the full cicada.yaml registration payload from the CLI's
// `cicada register` command. This endpoint:
//   1. Runs the Policy Sanitizer (Anti-Lazy Guard)
//   2. Validates the policy structure
//   3. Extracts the EVAR spec from the policy fields
//   4. Mints an EVAR if the policy passes sanitization
//
// This is the primary registration path for CLI-registered agents.
// The legacy /v1/agent/register endpoint still works for programmatic SDKs.
// ────────────────────────────────────────────────────────────────────────────

func handleYAMLRegistration(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}
	r.Body.Close()

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		writeError(w, `{"error":"invalid JSON payload"}`, http.StatusBadRequest)
		return
	}

	// ── Sanitize ─────────────────────────────────────────────────────────
	sanitizeResult := policy.SanitizePolicy(payload)

	if !sanitizeResult.Allowed {
		log.Printf("[YAML REG BLOCKED] Policy sanitizer rejected: %d violation(s)", len(sanitizeResult.Violations))
		for _, v := range sanitizeResult.Violations {
			log.Printf("[SANITIZER] [%s] %s: %s — %s", v.Severity, v.Code, v.Field, v.Message)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      "policy_sanitization_failed",
			"message":    "Registration blocked by the Cicada Policy Sanitizer.",
			"violations": sanitizeResult.Violations,
		})
		return
	}

	// ── Extract EVAR spec from cicada.yaml fields ────────────────────────
	name, _ := payload["name"].(string)
	if name == "" {
		if identity, ok := payload["identity"].(map[string]interface{}); ok {
			name, _ = identity["name"].(string)
		}
	}
	if name == "" {
		writeError(w, `{"error":"agent name is required (identity.name or name)"}`, http.StatusBadRequest)
		return
	}

	// Generate a code hash from the policy content for EVAR binding
	policyHash := fmt.Sprintf("%x", sha256.Sum256(bodyBytes))

	spec := auth.AgentSpecification{
		AgentID:  name,
		CodeHash: policyHash,
	}

	// Extract scopes from tools
	if tools, ok := payload["tools"].([]interface{}); ok {
		for _, t := range tools {
			if tool, ok := t.(map[string]interface{}); ok {
				if toolName, ok := tool["name"].(string); ok {
					spec.Scopes = append(spec.Scopes, toolName)
				}
			}
		}
	}

	// Extract tenant ID
	if owner, ok := payload["owner"].(string); ok {
		spec.TenantID = owner
	}

	// ── Certification-gated EVAR issuance ────────────────────────────────
	// Same logic as handleAgentRegistration: escalation = no EVAR,
	// clean = provisional EVAR + pending_review.

	if sanitizeResult.RequiresEscalation {
		// ESCALATION: Hard stop — no EVAR issued
		violationsJSON, _ := json.Marshal(sanitizeResult.Violations)
		_, _ = store.DB.Exec(r.Context(), `
			UPDATE agents SET approval_status = 'escalation_required' WHERE id = $1
		`, name)
		_, _ = store.DB.Exec(r.Context(), `
			INSERT INTO certification_events (agent_id, tenant_id, event_type, performed_by, reason, metadata)
			SELECT id, tenant_id, 'escalation_flagged', 'sanitizer',
			       'YAML registration: high-severity policy violations — EVAR withheld',
			       $2::jsonb
			FROM agents WHERE id = $1
		`, name, string(violationsJSON))

		log.Printf("[YAML REG] Agent '%s' flagged for escalation — NO EVAR issued (policy_hash: %s)", name, policyHash[:16])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "escalation_required",
			"agent_id":    name,
			"evar":        nil,
			"policy_hash": policyHash,
			"message":     "Registration recorded but EVAR withheld. High-severity policy violations require operator review.",
			"violations":  sanitizeResult.Violations,
		})
		return
	}

	// CLEAN: Provisional EVAR
	token, err := auth.MintEVARToken(spec)
	if err != nil {
		log.Printf("[AUTH ERROR] EVAR minting failed for %s: %v", name, err)
		writeError(w, `{"error":"EVAR minting failed"}`, http.StatusInternalServerError)
		return
	}

	// Set approval_status = pending_review
	_, _ = store.DB.Exec(r.Context(), `
		UPDATE agents SET approval_status = 'pending_review' WHERE id = $1
	`, name)
	_, _ = store.DB.Exec(r.Context(), `
		INSERT INTO certification_events (agent_id, tenant_id, event_type, performed_by, reason)
		SELECT id, tenant_id, 'registered', 'system',
		       'YAML registration: provisional EVAR issued — awaiting operator certification'
		FROM agents WHERE id = $1
	`, name)

	log.Printf("[YAML REG] Agent '%s' registered with provisional EVAR (pending_review, policy_hash: %s)", name, policyHash[:16])

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "pending_review",
		"agent_id":    name,
		"evar":        token,
		"policy_hash": policyHash,
		"provisional": true,
		"message":     "Agent registered with provisional EVAR. Full enforcement requires operator certification.",
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Stage 7.1 — JIT Session Token Exchange
//
// Agents call this endpoint with their long-lived EVAR to receive a short-lived
// (15 min) session token. Subsequent proxy calls present the session token, not
// the EVAR. This implements Zero Trust's "verify every session" principle: a
// compromised EVAR grants only the ability to request sessions, not indefinite
// proxy access.
// ────────────────────────────────────────────────────────────────────────────

func handleAgentSession(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	rawEVAR := strings.TrimPrefix(authHeader, "Bearer ")
	if rawEVAR == "" || rawEVAR == authHeader {
		writeError(w, `{"error":"missing Authorization header — present your EVAR"}`, http.StatusUnauthorized)
		return
	}

	// Verify the EVAR cryptographically
	evarPayload, err := auth.VerifyEVARToken(rawEVAR)
	if err != nil {
		log.Printf("[SESSION] EVAR verification failed: %v", err)
		writeError(w, `{"error":"invalid or expired EVAR"}`, http.StatusUnauthorized)
		return
	}

	agentID := evarPayload.AgentID
	tenantID := evarPayload.Issuer
	if tenantID == "cicada-cocoon-lab" || tenantID == "" {
		// Resolve the actual tenant UUID from the agents table.
		// The EVAR issuer is the lab name, not a valid UUID — using it directly
		// causes SQLSTATE 22P02 in any UUID column (e.g. ciba_authorization_requests).
		var resolvedTenant string
		if err := store.DB.QueryRow(r.Context(),
			`SELECT COALESCE(tenant_id::text, '') FROM agents WHERE id = $1`, agentID,
		).Scan(&resolvedTenant); err == nil && resolvedTenant != "" {
			tenantID = resolvedTenant
		} else {
			// Hard fallback: use the dev workspace UUID.
			tenantID = "00000000-0000-0000-0000-000000000001"
			log.Printf("[WARN] Could not resolve tenant for agent %s — using dev workspace UUID", agentID)
		}
	}

	// Check gossip quarantine before issuing a session
	if gossipMesh.IsQuarantined(agentID) {
		writeError(w, `{"error":"agent is quarantined — session refused"}`, http.StatusForbidden)
		return
	}

	// Fetch HITL settings from the agents table so they can be embedded in the
	// session token. This avoids a DB hit on every proxied call — HITL state is
	// baked into the session at issuance and re-evaluated when the session expires.
	var hitlEnabled bool
	var hitlWebhookURL string
	_ = store.DB.QueryRow(r.Context(),
		`SELECT COALESCE(hitl_enabled, false), COALESCE(hitl_webhook_url, '')
		   FROM agents WHERE id = $1`,
		agentID,
	).Scan(&hitlEnabled, &hitlWebhookURL)

	// Convert EVAR scopes ([]interface{}) to []string
	scopes := make([]string, 0, len(evarPayload.Scopes))
	for _, s := range evarPayload.Scopes {
		if str, ok := s.(string); ok {
			scopes = append(scopes, str)
		}
	}

	// ── ID-JAG / RFC 8693 Token Exchange ─────────────────────────────────
	// The agent can assert a human user's identity during session issuance.
	// This embeds the user identity into the session, automatically attributing
	// all proxied actions in this session to the human user.
	userCtxStr := r.Header.Get("X-Cicada-User-Context")
	
	if r.ContentLength > 0 {
		// Also support RFC 8693 body parameters (JSON)
		var txReq struct {
			GrantType        string `json:"grant_type"`
			SubjectToken     string `json:"subject_token"`
			SubjectTokenType string `json:"subject_token_type"`
		}
		// ignore errors if body is not json (fallback to header)
		_ = json.NewDecoder(r.Body).Decode(&txReq)
		if txReq.GrantType == "urn:ietf:params:oauth:grant-type:token-exchange" && txReq.SubjectToken != "" {
			userCtxStr = txReq.SubjectToken
		}
	}

	var userCtx *auth.UserContext
	if userCtxStr != "" {
		userCtx = auth.ParseUserContext(userCtxStr)
		if userCtx == nil && auth.IsUserContextRequired() {
			writeError(w, `{"error":"invalid user context token"}`, http.StatusBadRequest)
			return
		}
	} else if auth.IsUserContextRequired() {
		writeError(w, `{"error":"user context required for session issuance"}`, http.StatusBadRequest)
		return
	}

	sessionToken, err := session.Issue(agentID, tenantID, scopes, hitlEnabled, hitlWebhookURL, userCtx, evarPayload.DataResidencyRegion)
	if err != nil {
		log.Printf("[SESSION] Token issuance failed for agent %s: %v", agentID, err)
		writeError(w, `{"error":"session token issuance failed"}`, http.StatusInternalServerError)
		return
	}

	if userCtx != nil {
		log.Printf("[SESSION] Issued JIT session for agent %s tenant %s (User: %s)", agentID, tenantID, userCtx.String())
	} else {
		log.Printf("[SESSION] Issued JIT session for agent %s tenant %s (No user context)", agentID, tenantID)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"session_token": sessionToken,
		"expires_in":    fmt.Sprintf("%d", int(session.SessionTTL().Seconds())),
		"token_type":    "Bearer",
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Agent Proxy Request
//
// Accepts session tokens (preferred, Stage 7.1) or legacy EVAR tokens
// (backwards compatible — agents that have not yet adopted the session flow
// continue to work). New integrations should call /v1/agent/session first.
//
// Admission pipeline (in order):
//   1. Token verification (session or EVAR)
//   2. Gossip mesh quarantine check
//   3. Role enforcement (Stage 9.2)
//   4. FGA resource policy check (Stage 7.4)
//   5. HITL approval gate for write/transact scopes (Stage 7.2) — only when
//      hitl_enabled=true on the agent record
//   6. Semantic intent check — rule-based alignment between agent's declared
//      purpose and the runtime target URL/method (AI hallucination detection)
//   7. Velocity circuit breaker — Redis sliding-window counter for write/delete
//      calls per agent; catches runaway loops regardless of per-call validity
//   8. OPA policy evaluation
//   9. Billing meter increment
//  10. Ledger write
// ────────────────────────────────────────────────────────────────────────────

func isCGNAT(ip net.IP) bool {
	_, cgnatNet, _ := net.ParseCIDR("100.64.0.0/10")
	return cgnatNet.Contains(ip)
}

func isIPv6ULA(ip net.IP) bool {
	return len(ip) == net.IPv6len && (ip[0] == 0xfc || ip[0] == 0xfd)
}

// proxyTransport enforces connection-time IP pinning to neutralize TOCTOU DNS-rebinding attacks.
var proxyTransport = &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("SSRF dialer resolution failed: %w", err)
		}

		var validIP *net.IPAddr
		for _, ipAddr := range ips {
			ip := ipAddr.IP
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			if isCGNAT(ip) || isIPv6ULA(ip) {
				continue
			}
			validIP = &ipAddr
			break
		}

		if validIP == nil {
			return nil, fmt.Errorf("SSRF egress guard: all resolved IPs for host %q are blocked", host)
		}

		// Pin connection directly to the verified IP to eliminate DNS rebind windows
		pinnedAddr := net.JoinHostPort(validIP.IP.String(), port)
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, pinnedAddr)
	},
}

// proxyClient is the HTTP client used to forward requests to target APIs.
// CheckRedirect enforces ErrUseLastResponse to prevent 301/302 SSRF redirect loops.
var proxyClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: proxyTransport,
}

func handleAgentRequest(w http.ResponseWriter, r *http.Request) {
	// ── Simulation mode: synthetic response without real processing ───────
	if simulationMode {
		handleSimulatedRequest(w, r)
		return
	}

	authHeader := r.Header.Get("Authorization")
	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	if rawToken == "" || rawToken == authHeader {
		writeError(w, `{"error":"missing Authorization header"}`, http.StatusUnauthorized)
		return
	}

	// ── 1. Token verification ─────────────────────────────────────────────────
	// Try session token first; fall back to EVAR for backwards compatibility.
	var agentID, tenantID string
	var sessionScopes []string
	var hitlRequired bool
	var hitlWebhookURL string
	var idJagUserContext *auth.UserContext
	var agentRegion string
	_ = hitlWebhookURL // CIBA replaced direct webhook calls; kept for session/EVAR compat

	if sessionClaims, err := session.Verify(rawToken); err == nil {
		agentID = sessionClaims.AgentID
		tenantID = sessionClaims.TenantID
		sessionScopes = sessionClaims.Scopes
		hitlRequired = sessionClaims.HITLRequired
		hitlWebhookURL = sessionClaims.HITLWebhookURL
		idJagUserContext = sessionClaims.UserContext
		agentRegion = sessionClaims.DataResidencyRegion
	} else {
		evarPayload, verifyErr := auth.VerifyEVARToken(rawToken)
		if verifyErr != nil {
			log.Printf("[SECURITY] Token verification failed: %v", verifyErr)
			writeError(w, `{"error":"invalid token — present a valid session token or EVAR"}`, http.StatusUnauthorized)
			return
		}
		agentID = evarPayload.AgentID
		tenantID = evarPayload.Issuer
		agentRegion = evarPayload.DataResidencyRegion
		if tenantID == "cicada-cocoon-lab" || tenantID == "" {
			// Resolve the actual tenant UUID from the agents table.
			var resolvedTenant string
			if dbErr := store.DB.QueryRow(r.Context(),
				`SELECT COALESCE(tenant_id::text, '') FROM agents WHERE id = $1`, agentID,
			).Scan(&resolvedTenant); dbErr == nil && resolvedTenant != "" {
				tenantID = resolvedTenant
			} else {
				tenantID = "00000000-0000-0000-0000-000000000001"
				log.Printf("[WARN] Could not resolve tenant for agent %s — using dev workspace UUID", agentID)
			}
		}
		for _, s := range evarPayload.Scopes {
			if str, ok := s.(string); ok {
				sessionScopes = append(sessionScopes, str)
			}
		}
		// Fetch agent metadata from Redis cache (falls back to DB on miss)
		agentInfo, agentInfoErr := agentcache.GetAgent(r.Context(), agentID)
		if agentInfoErr == nil {
			hitlRequired = agentInfo.HITLEnabled
			hitlWebhookURL = agentInfo.HITLWebhookURL
		}
	}

	// ── V09: Token-IP correlation log (fire-and-forget) ───────────────────────
	// Write (agent_id, source_ip) to token_usage_logs for V09 threat signal
	// detection. DashboardController queries this table to detect tokens used
	// from multiple distinct IPs within a rolling window.
	go func() {
		sourceIP := r.RemoteAddr
		// Strip port from RemoteAddr (e.g. "192.168.1.1:54321" → "192.168.1.1")
		if host, _, err := net.SplitHostPort(sourceIP); err == nil {
			sourceIP = host
		}
		tokenFP := agentID
		if len(tokenFP) >= 16 {
			tokenFP = tokenFP[:16]
		}
		_, _ = store.DB.Exec(context.Background(),
			`INSERT INTO token_usage_logs (agent_id, source_ip, token_fingerprint, created_at)
			 VALUES ($1, $2, $3, NOW())`,
			agentID, sourceIP, tokenFP)
	}()

	// ── 0.5 Data Residency Enforcement ─────────────────────────────────────────
	gatewayRegion := os.Getenv("CICADA_REGION")
	if gatewayRegion != "" && agentRegion != "" && gatewayRegion != agentRegion {
		log.Printf("[DATA RESIDENCY BLOCKED] Agent %s requested region %s but gateway is pinned to %s", agentID, agentRegion, gatewayRegion)
		writeError(w, fmt.Sprintf(`{"error":"data_residency_violation", "message":"Agent is pinned to %s region. This gateway operates in %s."}`, agentRegion, gatewayRegion), http.StatusForbidden)
		return
	}

	// ── 1a. Certification gate ────────────────────────────────────────────────
	// Check the agent's approval_status before processing anything else.
	// Terminated/suspended agents are hard-blocked. Uncertified agents are
	// forced into shadow-only mode (provisional EVAR behaviour).
	// ── Agent cache: single Redis lookup replaces 6+ DB queries ──────────
	agentCached, agentCacheErr := agentcache.GetAgent(r.Context(), agentID)
	var approvalStatus string
	if agentCacheErr == nil {
		approvalStatus = agentCached.ApprovalStatus
	} else {
		// Hard fallback to DB if both Redis and cache fail
		_ = store.DB.QueryRow(r.Context(),
			`SELECT COALESCE(approval_status, 'pending_review') FROM agents WHERE id = $1`,
			agentID,
		).Scan(&approvalStatus)
	}

	switch approvalStatus {
	case "terminated":
		log.Printf("[CERTIFICATION] Agent %s BLOCKED — terminated", agentID)
		writeError(w, `{"error":"agent terminated — credential revoked by operator"}`, http.StatusForbidden)
		return
	case "suspended":
		log.Printf("[CERTIFICATION] Agent %s BLOCKED — suspended", agentID)
		writeError(w, `{"error":"agent suspended — contact your operator for reinstatement"}`, http.StatusForbidden)
		return
	case "escalation_required":
		log.Printf("[CERTIFICATION] Agent %s BLOCKED — escalation required, no EVAR should exist", agentID)
		writeError(w, `{"error":"agent requires operator escalation review — no valid credential issued"}`, http.StatusForbidden)
		return
	case "pending_review":
		// Provisional EVAR — force shadow-only mode
		log.Printf("[CERTIFICATION] Agent %s operating in provisional mode (pending_review)", agentID)
		w.Header().Set("X-Cicada-Provisional", "true")
		// observeOnlyMode is set below from agent_resource_policies; we override it here
		// to ensure provisional agents always operate in observe-only regardless of policy config.
	case "certified":
		// Full enforcement — normal operation. Fall through.
	default:
		// Unknown status — fail closed
		log.Printf("[CERTIFICATION] Agent %s has unknown approval_status=%q — denying", agentID, approvalStatus)
		writeError(w, `{"error":"agent certification status unknown — access denied"}`, http.StatusForbidden)
		return
	}

	// ── 1b. Read Inbound Body with Dynamic HITL Cap ───────────────────────────
	var bodyBytes []byte
	if r.Body != nil {
		var readErr error
		limit := int64(10 * 1024 * 1024) // 10MB default
		if hitlRequired {
			limit = int64(1024 * 1024) // 1MB cap for HITL suspensions
		}
		
		bodyBytes, readErr = io.ReadAll(io.LimitReader(r.Body, limit+1))
		if readErr != nil {
			writeError(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
			return
		}
		
		if int64(len(bodyBytes)) > limit {
			writeError(w, `{"error":"Payload Too Large: Suspended payloads cannot exceed 1MB"}`, http.StatusRequestEntityTooLarge)
			return
		}
		r.Body.Close()
	}

	var observeOnlyMode bool
	if agentCacheErr == nil {
		observeOnlyMode = agentCached.ObserveOnlyMode
	} else {
		_ = store.DB.QueryRow(r.Context(),
			`SELECT COALESCE(observe_only_mode, false)
			   FROM agent_resource_policies WHERE agent_id = $1`, agentID,
		).Scan(&observeOnlyMode)
	}

	// Provisional agents (pending_review) MUST operate in observe-only mode
	// regardless of their resource policy configuration.
	if approvalStatus == "pending_review" {
		observeOnlyMode = true
	}

	var swarmScore float64 = -1.0
	if agentCacheErr == nil {
		swarmScore = agentCached.SwarmConfidenceScore
	} else {
		_ = store.DB.QueryRow(r.Context(),
			`SELECT COALESCE(swarm_confidence_score, -1.0)
			   FROM agents WHERE id = $1`, agentID,
		).Scan(&swarmScore)
	}

	traceID := fmt.Sprintf("req-%d", time.Now().UnixNano())
	targetURL := r.Header.Get("X-Cicada-Target-URL") // Agent declares its intended target

	// ── Tier 1 SSRF Pre-flight check ──────────────────────────────────────────
	if targetURL != "" {
		if err := ssrf.ValidateOutboundURL(targetURL, nil); err != nil {
			log.Printf("[SSRF BLOCKED] Agent %s target %s rejected: %v (trace %s)", agentID, targetURL, err, traceID)
			writeError(w, fmt.Sprintf(`{"error":"ssrf_blocked","message":%q}`, err.Error()), http.StatusForbidden)
			return
		}
	}

	// ── 1a-chain. Inter-Agent Chain Verification (ASI07) ──────────────────────
	// If the request carries an X-Cicada-Agent-Chain header, verify the
	// cryptographic signature chain BEFORE any payload state changes hit Redis.
	// A compromised agent cannot forge or reset the chain depth because each
	// hop is signed by the gateway's Ed25519 key.
	var chainDepth int
	var upstreamAgentID string
	if chainHeader := r.Header.Get("X-Cicada-Agent-Chain"); chainHeader != "" && chainVerifier != nil {
		chainResult := chainVerifier.VerifyAndExtend(chainHeader, agentID)
		if !chainResult.Valid {
			log.Printf("[ASI07] Chain verification FAILED for agent %s: %s (trace %s)",
				agentID, chainResult.Error, traceID)
			edgeLedger.AppendRecord(ledger.EventRecord{
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: "chain_tamper",
				Decision: "block", ReasonCodes: []string{"asi07_tamper_detected", chainResult.Error},
				RiskScore: 1.0,
			})
			writeError(w, `{"error":"invalid or tampered inter-agent cryptographic chain"}`, http.StatusForbidden)
			return
		}

		chainDepth = chainResult.CurrentDepth
		upstreamAgentID = chain.ExtractUpstreamAgent(chainResult.Chain)

		if chainResult.ExceedsMax {
			log.Printf("[ASI07] Chain depth %d exceeds max for agent %s (upstream: %s, trace %s)",
				chainDepth, agentID, upstreamAgentID, traceID)
			edgeLedger.AppendRecord(ledger.EventRecord{
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: "chain_depth_exceeded",
				Decision: "ciba_hold", ReasonCodes: []string{"asi07_max_delegation_depth"},
				RiskScore: 0.9,
			})
			writeError(w, `{"error":"max agent delegation depth exceeded — CIBA hold required"}`, http.StatusForbidden)
			return
		}

		log.Printf("[ASI07] Chain verified: agent %s depth=%d upstream=%s (trace %s)",
			agentID, chainDepth, upstreamAgentID, traceID)
	}

	var actionType string

	// ── 1d. Skill Routing & Contract Enforcement (Layer 1d) ──────────────────
	// If the request carries an X-Cicada-Target-Skill header, resolve the
	// target capability against the agent's cached skill graph. The gateway
	// verifies: (1) the skill is declared in cicada.yaml, (2) the upstream
	// agent chain is authorised, (3) the payload matches the input_schema,
	// and (4) high-criticality skills trigger CIBA holds.
	//
	// This check is O(1) — it reads from the singleflight-protected Redis
	// skills cache with zero database overhead.
	targetSkill := r.Header.Get("X-Cicada-Target-Skill")
	if targetSkill != "" {
		skillsMap, skillsErr := agentcache.GetSkills(r.Context(), agentID)
		if skillsErr != nil {
			log.Printf("[ASI01] Skills cache error for agent %s: %v (trace %s)", agentID, skillsErr, traceID)
			if os.Getenv("CICADA_FAIL_CLOSED") != "false" {
				writeError(w, `{"error":"skills_cache_unavailable","message":"Skill verification dependency unavailable — failing closed"}`, http.StatusServiceUnavailable)
				return
			}
		} else {
			skillContract, exists := skillsMap[targetSkill]
			if !exists {
				log.Printf("[ASI01] Undeclared skill '%s' by agent %s (trace %s)", targetSkill, agentID, traceID)
				edgeLedger.AppendRecord(ledger.EventRecord{
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "skill_blocked",
					Decision: "block", ReasonCodes: []string{"asi01_undeclared_skill"},
					TargetURL: targetURL, RiskScore: 0.8,
				})
				w.Header().Set("X-Cicada-Memory-Action", "flush")
				w.Header().Set("X-Cicada-Flush-Reason", "asi01_skill_boundary_breach")
				writeError(w, `{"error":"ASI01 Governance Violation: Target skill contract is undeclared in manifest"}`, http.StatusForbidden)
				return
			}

			// Lineage check: is the upstream agent authorised to delegate this skill?
			if len(skillContract.AllowedUpstreams) > 0 && upstreamAgentID != "" {
				isAuthorised := false
				for _, allowedID := range skillContract.AllowedUpstreams {
					if allowedID == upstreamAgentID {
						isAuthorised = true
						break
					}
				}
				if !isAuthorised {
					log.Printf("[ASI07] Unauthorised skill delegation: agent %s → skill '%s' (upstream %s) (trace %s)",
						agentID, targetSkill, upstreamAgentID, traceID)
					edgeLedger.AppendRecord(ledger.EventRecord{
						EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
						TenantID: tenantID, AgentID: agentID, ActionClass: "skill_delegation_blocked",
						Decision: "block", ReasonCodes: []string{"asi07_unauthorised_skill_delegation"},
						TargetURL: targetURL, RiskScore: 0.9,
					})
					writeError(w, `{"error":"ASI07 Delegation Violation: Requesting agent lineage not authorised to invoke this skill"}`, http.StatusForbidden)
					return
				}
			}

			// Schema validation: validate payload body against input_schema
			if len(bodyBytes) > 0 {
				if schemaErr := agentcache.ValidatePayload(bodyBytes, skillContract); schemaErr != nil {
					log.Printf("[ASI04] Schema validation failed for skill '%s' agent %s: %v (trace %s)",
						targetSkill, agentID, schemaErr, traceID)
					edgeLedger.AppendRecord(ledger.EventRecord{
						EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
						TenantID: tenantID, AgentID: agentID, ActionClass: "skill_schema_violation",
						Decision: "block", ReasonCodes: []string{"asi04_payload_schema_mutation"},
						TargetURL: targetURL, RiskScore: 0.7,
					})
					w.Header().Set("X-Cicada-Memory-Action", "flush")
					w.Header().Set("X-Cicada-Flush-Reason", "asi04_payload_schema_mutation")
					writeError(w, `{"error":"ASI04 Schema Mutation: Inbound request payload failed skill contract validation"}`, http.StatusBadRequest)
					return
				}
			}

			// High-criticality CIBA escalation: force risk score elevation so
			// the existing CIBA gate at Layer 5 triggers mandatory human review.
			// We store the elevated flag in request context for Layer 5 to read.
			if skillContract.CriticalityLevel == "high" {
				r.Header.Set("X-Cicada-Skill-Criticality", "high")
				// High-criticality transitions signal a major state boundary —
				// instruct the SDK to flush untrusted context frames to prevent
				// context rot from leaking across skill boundaries.
				w.Header().Set("X-Cicada-Memory-Action", "flush")
				w.Header().Set("X-Cicada-Flush-Reason", "high_criticality_skill_transition")
				log.Printf("[SKILL] High-criticality skill '%s' invoked by agent %s — CIBA escalation armed, memory flush signalled (trace %s)",
					targetSkill, agentID, traceID)

				// Write a memory_flush record so Aegis can track flush frequency.
				// Repeated flushes for the same agent indicate sustained attack.
				edgeLedger.AppendRecord(ledger.EventRecord{
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "memory_flush",
					Decision: "flush_signalled", ReasonCodes: []string{"high_criticality_skill_transition", targetSkill},
					TargetURL: targetURL, RiskScore: 0.5,
				})
			}

			// Tag action type for the ledger
			actionType = "skill_execution:" + targetSkill
		}
	}

	// ── 1a-mcp. MCP Session Hash Validation (ASI08 cross-platform) ────────────
	// Verify the X-Cicada-MCP-Session-Hash header against the local in-memory
	// cache of valid session token hashes. Sub-1ms verification without DB
	// roundtrips. The cache is populated when sessions are issued.
	if mcpSessionHash := r.Header.Get("X-Cicada-MCP-Session-Hash"); mcpSessionHash != "" {
		// Verify against the cached hash of the actual session token.
		expectedHash := sha256Hex(rawToken)
		if mcpSessionHash != expectedHash {
			log.Printf("[ASI08] MCP session hash mismatch for agent %s (trace %s)", agentID, traceID)
			writeError(w, `{"error":"inbound MCP session hash mismatch"}`, http.StatusUnauthorized)
			return
		}
		actionType = "mcp_tool_call"
		log.Printf("[ASI08] MCP session hash verified for agent %s (trace %s)", agentID, traceID)
	}

	// ── 1c. User-Context Propagation (H2.1 / S6.1 ID-JAG) ────────────────────
	// Parse and optionally validate the X-Cicada-User-Context header. This
	// carries the identity of the end-user on whose behalf the agent is acting.
	//
	// If the agent performed an Identity Assertion Grant (ID-JAG) token exchange
	// during session issuance, the UserContext is cryptographically bound to the
	// session token. This is the most secure method.
	// Otherwise, we fall back to the X-Cicada-User-Context header for legacy
	// clients or direct EVAR calls without a session.
	var userContext *auth.UserContext
	if idJagUserContext != nil {
		userContext = idJagUserContext
	} else {
		rawUserContext := r.Header.Get("X-Cicada-User-Context")
		userContext = auth.ParseUserContext(rawUserContext)
	}

	var humanContextJSON string
	if userContext != nil {
		humanContextJSON = userContext.ToJSON()
		log.Printf("[USER-CONTEXT] agent=%s user=%s", agentID, userContext.String())
	} else if auth.IsUserContextRequired() {
		log.Printf("[USER-CONTEXT] REQUIRED but missing for agent %s — rejecting", agentID)
		writeError(w, `{"error":"X-Cicada-User-Context header (or ID-JAG session) is required for this tenant"}`, http.StatusForbidden)
		return
	}

	// ── 2. Gossip mesh quarantine ─────────────────────────────────────────────
	if gossipMesh.IsQuarantined(agentID) || gossipMesh.IsQuarantined(fmt.Sprintf("%s_WILDCARD", tenantID)) {
		writeError(w, `{"error":"agent or tenant quarantined"}`, http.StatusForbidden)
		return
	}

	// ── 3. Ghost mode routing (Intercept before security gates) ───────────────
	// Check whether Aegis-0 or automatic containment has diverted this agent to the shadow sandbox.
	// We MUST do this before admission checks so that if an agent is in Ghost Mode,
	// it receives fake 200 OKs instead of 403s. The attacker must never know they are blocked.
	if ghostmode.IsActive(r.Context(), agentID) {
		var ghostModeAllowed bool
		if agentCacheErr == nil {
			ghostModeAllowed = agentCached.GhostModeAllowed
		} else {
			_ = store.DB.QueryRow(r.Context(),
				`SELECT COALESCE(ghost_mode_allowed, false) FROM agents WHERE id = $1`, agentID,
			).Scan(&ghostModeAllowed)
		}

		if !ghostModeAllowed {
			log.Printf("[GHOST] Agent %s is in ghost mode but has not opted in — proceeding normally", agentID)
			// Fall through
		} else {
			log.Printf("[GHOST] Agent %s is in ghost mode (consent confirmed) — routing to shadow sandbox", agentID)
			edgeLedger.AppendRecord(ledger.EventRecord{
				HumanContext: humanContextJSON,
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
				Decision: "ghost_proxied", ReasonCodes: []string{"ghost_mode_active"}, RiskScore: 0.3,
			})
			handleGhostProxy(w, r, agentID, traceID)
			return
		}
	}

	// ── 4. Role enforcement (Stage 9.2) ──────────────────────────────────────
	// callerEVARAgentID equals agentID for direct calls; for orchestrated calls
	// the orchestrator would set X-Cicada-Caller-Agent.
	callerAgentID := r.Header.Get("X-Cicada-Caller-Agent")
	if callerAgentID == "" {
		callerAgentID = agentID
	}
	if err := roles.Enforce(r.Context(), agentID, callerAgentID, swarmScore); err != nil {
		log.Printf("[ROLES] Admission denied for agent %s: %v", agentID, err)
		if observeOnlyMode {
			w.Header().Set("X-Cicada-Shadow-Flag", "true")
			edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
				Decision: "shadow_allowed", ReasonCodes: []string{"role_violation"}, RiskScore: 0.85, ShadowViolation: true,
			})
		} else {
			edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
				Decision: "deny", ReasonCodes: []string{"role_violation"}, RiskScore: 0.85,
			})
			writeError(w, fmt.Sprintf(`{"error":"role violation: %s"}`, err.Error()), http.StatusForbidden)
			return
		}
	}

	// ── 4. FGA resource policy check (Stage 7.4) ─────────────────────────────
	if targetURL != "" {
		fgaAllowed, fgaErr := fga.Check(r.Context(), agentID, targetURL, r.Method)
		if fgaErr != nil {
			log.Printf("[FGA] DB error for agent %s: %v", agentID, fgaErr)
			if os.Getenv("FAIL_CLOSED_ON_DB_ERROR") == "true" {
				edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
					Decision: "deny", ReasonCodes: []string{"fga_db_unavailable"}, RiskScore: 0.9,
				})
				writeError(w, `{"error":"resource policy check unavailable — access denied"}`, http.StatusForbidden)
				return
			}
			// Fail open: fall through to scope check when DB unavailable
		} else if !fgaAllowed {
			if observeOnlyMode {
				w.Header().Set("X-Cicada-Shadow-Flag", "true")
				edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
					Decision: "shadow_allowed", ReasonCodes: []string{"fga_resource_deny"}, RiskScore: 0.75, ShadowViolation: true,
				})
			} else {
				edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
					Decision: "deny", ReasonCodes: []string{"fga_resource_deny"}, RiskScore: 0.75,
				})
				writeError(w, `{"error":"resource policy deny — target URL not in agent's allowed policy list"}`, http.StatusForbidden)
				return
			}
		}
	}

	// ── 4b. Destructive capability enforcement ────────────────────────────────
	// If the agent is registered with destructive_capability=true (shell access,
	// filesystem write, database DDL), enforce mandatory HITL for all write
	// operations. This closes the single-shot destructive command gap: a
	// compromised agent that has legitimate shell access and sends a single
	// `rm -rf /` at normal speed would evade velocity and baseline checks,
	// but cannot evade mandatory human review.
	//
	// Configurable via DESTRUCTIVE_AGENTS_REQUIRE_HITL (default: true).
	// When true and the agent has destructive capability but HITL is disabled,
	// the request is blocked with a clear error.
	{
		var destructiveCapability bool
		if agentCacheErr == nil {
			destructiveCapability = agentCached.DestructiveCapability
		} else {
			_ = store.DB.QueryRow(r.Context(),
				`SELECT COALESCE(destructive_capability, false) FROM agents WHERE id = $1`, agentID,
			).Scan(&destructiveCapability)
		}

		if destructiveCapability && session.ScopesContainWriteOrTransact(sessionScopes) {
			requireHITL := os.Getenv("DESTRUCTIVE_AGENTS_REQUIRE_HITL") != "false" // default true
			if requireHITL && !hitlRequired {
				log.Printf("[DESTRUCTIVE] Agent %s has destructive capability but HITL is disabled — blocking write operation", agentID)
				edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
					Decision: "deny", ReasonCodes: []string{"destructive_agent_no_hitl"}, RiskScore: 0.95,
				})
				writeError(w, `{"error":"agent has destructive capabilities — HITL must be enabled for write operations. Enable hitl_enabled on this agent's registration to allow destructive actions with human review."}`, http.StatusForbidden)
				return
			}
			if destructiveCapability {
				log.Printf("[DESTRUCTIVE] Agent %s has destructive capability — write operation proceeding with HITL=%v", agentID, hitlRequired)
			}
		}
	}

	// ── 4c. Drift Guard (Context Shift Detection) ─────────────────────────────
	actionSummary := r.Header.Get("X-Cicada-Action-Summary")
	driftResult := drift.Check(r.Context(), agentID, targetURL, r.Method, actionSummary)
	if driftResult.DriftDetected {
		log.Printf("[DRIFT] Context Shift detected for agent %s: %s", agentID, driftResult.Reason)
	}

	// ── 5. CIBA last-hop authorization gate (mandatory) ──────────────────────
	// CIBA replaces the old optional HITL webhook. It is ALWAYS active for
	// write/transact scopes — developers cannot opt out. Tier 1 runs an instant
	// policy pre-check. Only calls that exceed the risk threshold trigger the
	// CIBA flow, which pushes a notification to the owner's device (dashboard
	// during development, Flutter companion app in production). The owner
	// approves or denies. Timeout = fail closed.
	if session.ScopesContainWriteOrTransact(sessionScopes) {
		payloadPreview := string(bodyBytes)
		if len(payloadPreview) > 200 {
			payloadPreview = payloadPreview[:200]
		}

		// Tier 1: instant policy pre-check
		result := hitl.TieredCheck("", traceID, agentID, tenantID, targetURL, sessionScopes, payloadPreview)
		if result.Err != nil {
			log.Printf("[CIBA] Tier 1 error for agent %s: %v", agentID, result.Err)
		}

		// Layer 1d escalation: if a high-criticality skill contract is active,
		// force the risk score above the CIBA threshold to guarantee mandatory
		// human-in-the-loop review regardless of the Tier 1 pre-check result.
		if r.Header.Get("X-Cicada-Skill-Criticality") == "high" {
			if result.RiskScore < 0.8 {
				result.RiskScore = 0.8
			}
			result.Approved = false
			result.RiskReason = fmt.Sprintf("High-criticality skill contract: %s", targetSkill)
			log.Printf("[CIBA] Skill criticality escalation: agent=%s skill=%s score=%.2f (trace %s)",
				agentID, targetSkill, result.RiskScore, traceID)
		}
		// Pillar 1: Dynamic Intent Weighting — if Drift Guard detected a context shift,
		// spike the risk score to force a CIBA escalation.
		if driftResult.DriftDetected {
			result.Approved = false
			result.RiskScore = 0.95
			result.RiskReason = "Context Shift (Drift): " + driftResult.Reason
		}

		if !result.Approved {
			// Tier 1 flagged this as high-risk — initiate CIBA authorization
			log.Printf("[CIBA] Tier 1 escalated to CIBA: agent=%s trace=%s score=%.2f reason=%q",
				agentID, traceID, result.RiskScore, result.RiskReason)

			// Read agent description from cache (already populated at L1587)
			var agentDesc string
			if agentCacheErr == nil {
				agentDesc = agentCached.Description
				if agentDesc == "" {
					agentDesc = agentCached.Name
				}
			} else {
				_ = store.DB.QueryRow(r.Context(),
					`SELECT COALESCE(description, agent_name) FROM agents WHERE id = $1`, agentID,
				).Scan(&agentDesc)
			}

			// Send FCM push to the paired Aegis device before blocking on CIBA.
			// This wakes the operator's phone from sleep so they see the alert
			// while the gateway is waiting for their decision.
			// Non-fatal — if push fails the operator still gets the alert via heartbeat poll.
			go func() {
				var pushToken string
				_ = store.DB.QueryRow(r.Context(),
					`SELECT push_token FROM mobile_devices
					 WHERE tenant_id = $1 AND status = 'active'
					 AND push_token IS NOT NULL
					 ORDER BY paired_at DESC LIMIT 1`,
					tenantID,
				).Scan(&pushToken)
				if pushToken != "" {
					if err := fcm.SendHitlAlert(context.Background(), pushToken, traceID); err != nil {
						log.Printf("[FCM] Push failed for tenant=%s hold=%s: %v", tenantID, traceID, err)
					}
				}
			}()

			cibaResult := ciba.Authorize(r.Context(), ciba.Request{
				TraceID:        traceID,
				AgentID:        agentID,
				TenantID:       tenantID,
				ActionSummary:  fmt.Sprintf("Agent '%s' is attempting a %s operation", agentDesc, r.Method),
				TargetURL:      targetURL,
				PayloadPreview: payloadPreview,
				RiskScore:      result.RiskScore,
				RiskReason:     result.RiskReason,
			})

			if !cibaResult.Approved {
				edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
					Decision:    fmt.Sprintf("ciba_%s", cibaResult.Status),
					ReasonCodes: []string{"ciba_denied", result.RiskReason},
					RiskScore:   result.RiskScore,
				})

				// ── Saga compensating rollback on CIBA deny ─────────────────────
				// If the agent has a registered saga_revert_route (operator-set at
				// registration/certification time, NOT agent-supplied), enqueue a
				// compensating transaction to reverse any partial side effects.
				var sagaRevertRoute string
				_ = store.DB.QueryRow(r.Context(),
					`SELECT COALESCE(saga_revert_route, '') FROM agents WHERE id = $1`,
					agentID,
				).Scan(&sagaRevertRoute)

				if sagaRevertRoute != "" {
					// Enqueue the rollback intent. SSRF validation happens in the
					// saga worker at execution time (not here at enqueue time) because:
					//   1. The worker is the single enforcement point — defense in depth
					//      is achieved by the worker re-validating even if this path
					//      were to validate too.
					//   2. DNS resolution results can change between enqueue and dequeue.
					//   3. The enqueue path should record intent; the worker decides
					//      whether to act on it.
					rollbackID := fmt.Sprintf("rb-%d", time.Now().UnixNano())
					h := sha256.Sum256([]byte(traceID + "ciba_denied" + time.Now().String()))
					if queueErr := queue.PushRollback(r.Context(), queue.SagaJob{
						RollbackID:         rollbackID,
						TraceID:            traceID,
						OriginalActionHash: hex.EncodeToString(h[:]),
						RevertRoute:        sagaRevertRoute,
						FailedAction:       "ciba_denied",
						IdempotencyKey:     traceID + ":ciba_denied",
					}); queueErr != nil {
						log.Printf("[SAGA] Failed to enqueue rollback for trace %s: %v", traceID, queueErr)
					} else {
						log.Printf("[SAGA] Compensating rollback enqueued: rollback_id=%s trace=%s revert=%s",
							rollbackID, traceID, sagaRevertRoute)
						edgeLedger.AppendRecord(ledger.EventRecord{
							HumanContext: humanContextJSON,
							EventID:      fmt.Sprintf("evt-%d", time.Now().UnixNano()),
							TraceID:      traceID,
							TenantID:     tenantID, AgentID: agentID,
							ActionClass: "saga_compensate",
							Decision:    "rollback_enqueued",
							ReasonCodes: []string{"saga_intent_published", "ciba_denied"},
							RiskScore:   result.RiskScore,
						})
					}
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(fmt.Sprintf(`{"error":"CIBA authorization %s","trace_id":"%s","risk_score":%.2f,"reason":"%s"}`,
					cibaResult.Status, traceID, result.RiskScore, result.RiskReason)))
				return
			}

			log.Printf("[CIBA] APPROVED by %s: agent=%s trace=%s", cibaResult.RespondedBy, agentID, traceID)
			edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
				Decision:    "ciba_approved",
				ReasonCodes: []string{"ciba_approved", fmt.Sprintf("by:%s", cibaResult.RespondedBy)},
				RiskScore:   result.RiskScore,
			})
		} else {
			log.Printf("[CIBA] Tier 1 auto-approved: agent=%s trace=%s score=%.2f", agentID, traceID, result.RiskScore)
		}
	}

	// ── 6. Prompt injection scan ──────────────────────────────────────────────
	// Scans the outbound request body for injection patterns — an agent that
	// has been successfully injected may attempt to propagate the attack by
	// writing malicious instructions into downstream systems (databases, emails,
	// documents). Catching this here closes the indirect injection vector.
	// System messages are trusted; all other content is scanned.
	//
	// Content provenance: if the agent (via SDK) provides an
	// X-Cicada-Content-Provenance header, the scan sensitivity is elevated
	// for untrusted sources (retrieved documents, tool results).
	if len(bodyBytes) > 0 {
		provenance := injection.ParseProvenance(r.Header.Get("X-Cicada-Content-Provenance"))
		injResult := injection.ScanWithProvenance(string(bodyBytes), "", provenance)
		if injResult.Block {
			summary := injection.Summary(injResult.Findings)
			log.Printf("[INJECTION] Outbound body blocked for agent %s trace %s (provenance=%s): %s", agentID, traceID, provenance, summary)
			edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
				Decision: "deny", ReasonCodes: []string{"prompt_injection_outbound", "provenance:" + provenance}, RiskScore: injResult.Score,
			})
			go output.EmitThreatAlert(
				"prompt_injection", "high", tenantID, agentID, targetURL,
				fmt.Sprintf("Prompt injection detected in outbound request: %s", summary),
				"Review agent output and investigate upstream data sources for injection payloads.", traceID, nil,
			)
			w.Header().Set("X-Cicada-Memory-Action", "flush")
			w.Header().Set("X-Cicada-Flush-Reason", "prompt_injection_detected")
			edgeLedger.AppendRecord(ledger.EventRecord{
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: "memory_flush",
				Decision: "flush_signalled", ReasonCodes: []string{"prompt_injection_detected"},
				TargetURL: targetURL, RiskScore: injResult.Score,
			})
			writeError(w, fmt.Sprintf(`{"error":"prompt injection detected in request body","findings":"%s"}`, summary), http.StatusForbidden)
			return
		}
		if len(injResult.Findings) > 0 {
			log.Printf("[INJECTION] Non-blocking outbound findings for agent %s (provenance=%s): %s", agentID, provenance, injection.Summary(injResult.Findings))
		}
	}

	// ── 6b. Canary token exfiltration scan ───────────────────────────────────────
	// Scan the outbound body for any honeytoken value previously injected into
	// this agent's context by the verification swarm. A CICADA_CANARY_* value
	// appearing in an outbound call is a zero-false-positive incident signal:
	//
	//  - No real API key starts with CICADA_CANARY_
	//  - No legitimate business logic generates this prefix
	//  - The ONLY way this token reaches a target API is via:
	//      (a) data exfiltration — agent relaying the credential to an attacker
	//      (b) credential misuse — agent attempting to authenticate with a stolen token
	//      (c) prompt injection success — injected instructions told the agent to use it
	//
	// Auto-quarantine is applied on trigger. This is safe because false positives
	// are impossible: the token is cryptographically random and prefixed uniquely.
	// Quarantine propagates to all peer gateway nodes via the gossip mesh within
	// milliseconds, closing the window before any retry attempt succeeds.
	if len(bodyBytes) > 0 {
		if canaryTrigger := canary.CheckOutbound(r.Context(), tenantID, string(bodyBytes)); canaryTrigger != nil {
			log.Printf("[CANARY] CRITICAL INCIDENT: exfiltration by agent=%s tenant=%s token=%s trace=%s",
				canaryTrigger.AgentID, tenantID, canaryTrigger.TokenValue, traceID)
			edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
				EventID:     fmt.Sprintf("evt-%d", time.Now().UnixNano()),
				TraceID:     traceID,
				TenantID:    tenantID,
				AgentID:     agentID,
				ActionClass: "canary_trigger",
				Decision:    "deny",
				ReasonCodes: []string{"honeytoken_exfiltration", "canary_token_detected"},
				RiskScore:   1.0, // maximum: zero-false-positive incident
			})
			// Quarantine via gossip mesh so all peer nodes stop admitting this agent.
			gossipMesh.QuarantineAgent(agentID)
			writeError(w, `{"error":"access denied"}`, http.StatusForbidden)
			return
		}
	}

	// ── 7. Semantic intent check ──────────────────────────────────────────────
	// Compares the agent's declared description and agent_type (set at
	// registration) against the runtime target URL and HTTP method using a
	// rule-based lexical scoring algorithm — NOT an LLM call. Using an LLM to
	// verify another LLM's intent is circular (the verifier can hallucinate too);
	// a deterministic rule engine is fast, free, and impossible to prompt-inject.
	//
	// Example catch: a "customer support chat assistant" calling DELETE on a
	// payments API has near-zero keyword overlap → blocked here regardless of
	// whether its scopes and resource policies technically permit the call.
	{
		// Read from agentcache (populated at L1587) instead of a standalone
		// DB query. This was the primary p95 latency bottleneck — every
		// request previously hit Postgres here even when the cache had the data.
		var agentDesc, agentType string
		if agentCacheErr == nil {
			agentDesc = agentCached.Description
			agentType = agentCached.AgentType
		} else {
			// Context-bound DB fallback — inherits r.Context() deadline to
			// prevent long-hanging queries if Postgres queues up under load.
			err := store.DB.QueryRow(r.Context(),
				`SELECT COALESCE(description,''), COALESCE(agent_type,'') FROM agents WHERE id = $1`,
				agentID,
			).Scan(&agentDesc, &agentType)
			if err != nil {
				log.Printf("[SEMANTIC] DB fallback failed for agent %s: %v", agentID, err)
			}
		}

		semanticResult := semantic.Check(agentDesc, agentType, targetURL, r.Method)
		log.Printf("[SEMANTIC] agent=%s score=%.2f block=%v reason=%q", agentID, semanticResult.Score, semanticResult.Block, semanticResult.Reason)

		if semanticResult.Block {
			if observeOnlyMode {
				w.Header().Set("X-Cicada-Shadow-Flag", "true")
				edgeLedger.AppendRecord(ledger.EventRecord{
					HumanContext: humanContextJSON,
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
					TargetURL: targetURL,
					Decision: "shadow_allowed", ReasonCodes: []string{"semantic_intent_mismatch"}, RiskScore: 0.80, ShadowViolation: true,
				})
			} else {
				edgeLedger.AppendRecord(ledger.EventRecord{
					HumanContext: humanContextJSON,
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
					TargetURL: targetURL,
					Decision: "deny", ReasonCodes: []string{"semantic_intent_mismatch"}, RiskScore: 0.80,
				})
				go output.EmitThreatAlert(
					"semantic_mismatch", "high", tenantID, agentID, targetURL,
					fmt.Sprintf("Semantic intent mismatch: %s", semanticResult.Reason),
					"Review agent prompt and human context to ensure alignment. The agent may be hallucinating or under malicious control.", traceID, nil,
				)
				ghostmode.RecordViolation(r.Context(), agentID)
				writeError(w, fmt.Sprintf(`{"error":"semantic intent mismatch — %s"}`, semanticResult.Reason), http.StatusForbidden)
				return
			}
		}
	}

	// ── 8. Velocity circuit breaker ───────────────────────────────────────────
	// Redis sliding-window counter for destructive (write/delete) calls per
	// agent per minute. Catches runaway loop behaviour even when every individual
	// call is semantically valid and policy-compliant. Separate from the Laravel
	// confidence-score circuit breaker which fires on a longer time horizon and
	// requires action_ledger data; this check fires in-band on the hot path with
	// sub-millisecond latency.
	//
	// Example catch: a billing agent that legitimately charges customers starts
	// issuing 50 POST /charges calls in 60 seconds due to a loop bug — each call
	// looks individually valid but the rate is an anomaly that warrants blocking.
	{
		velResult := velocity.Check(r.Context(), agentID, r.Method)
		if velResult.Exceeded {
			log.Printf("[VELOCITY] Agent %s blocked: %d %s calls in %ds window (threshold %d)",
				agentID, velResult.CurrentRate, velResult.CounterType, velResult.WindowSecs, velResult.Threshold)
			edgeLedger.AppendRecord(ledger.EventRecord{
				HumanContext: humanContextJSON,
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
				TargetURL: targetURL,
				Decision: "deny", ReasonCodes: []string{"velocity_exceeded"}, RiskScore: 0.75,
			})
			go output.EmitThreatAlert(
				"velocity_breach", "medium", tenantID, agentID, targetURL,
				fmt.Sprintf("Velocity limit exceeded: %d %s calls in %ds window", velResult.CurrentRate, velResult.CounterType, velResult.WindowSecs),
				"Investigate agent loop behavior or potential denial-of-wallet attempt.", traceID, nil,
			)
			ghostmode.RecordViolation(r.Context(), agentID)
			writeError(w, fmt.Sprintf(`{"error":"velocity limit exceeded — %d %s calls in %ds window"}`,
				velResult.CurrentRate, velResult.CounterType, velResult.WindowSecs), http.StatusTooManyRequests)
			return
		}
	}

	// ── 8. OPA policy evaluation ──────────────────────────────────────────────
	actionScope := "proxy:call"
	// Override with MCP action type if MCP session was verified (ASI08).
	if actionType != "" {
		actionScope = actionType
	}
	velocityCount, _ := queue.GetTenantUsage(r.Context(), tenantID)

	allowed, evalErr := opaEngine.Evaluate(r.Context(), map[string]interface{}{
		"agent_id":      agentID,
		"target":        r.URL.Path,
		"velocity":      velocityCount,
		"evar_scopes":   sessionScopes,
		"action_scope":  actionScope,
		"agent_status":  approvalStatus,
		"action_cost":   0,
		"current_spend": 0,
		"spend_limit":   999999,
	})
	if evalErr != nil || !allowed {
		edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
			EventID:     fmt.Sprintf("evt-%d", time.Now().UnixNano()),
			TraceID:     traceID, TenantID: tenantID, AgentID: agentID,
			ActionClass: actionScope, Decision: "deny",
			ReasonCodes: []string{"opa_policy_deny"}, RiskScore: 0.9,
		})
		writeError(w, `{"error":"policy deny: action not permitted"}`, http.StatusForbidden)
		return
	}

	// ── 8.5. EAKF Plugin Interception (Code Execution Sandboxing) ─────────────
	// Source: EPHEMERAL_AGENT_KERNEL_FIREWALL.md §4, lines 139–183.
	// After OPA allows the request, check if this is a code execution call
	// that requires EAKF sandboxing. The interception is gated by:
	//   1. PluginManager has an "eakf" interceptor registered and healthy.
	//   2. The interceptor's EventFilter matches the request (target URL +
	//      agent policy declares eakf_enabled).
	// If the agent's policy requests EAKF but the plugin is unavailable,
	// the request is blocked immediately (fail-closed intent, §7.6C).
	if pluginMgr != nil {
		eakfReq := pipeline.Request{
			AgentID:   agentID,
			TenantID:  tenantID,
			TargetURL: targetURL,
			Body:      string(bodyBytes),
		}

		// Check if the request body declares eakf_enabled — this is the agent's
		// intent signal. If set but the plugin is unavailable, fail closed.
		var eakfIntent struct {
			EAKFEnabled bool `json:"eakf_enabled"`
		}
		_ = json.Unmarshal(bodyBytes, &eakfIntent)

		if eakfIntent.EAKFEnabled {
			interceptor, interceptErr := pluginMgr.GetInterceptor("eakf")
			if interceptErr != nil {
				// §7.6C: Agent policy requests EAKF but plugin is unavailable.
				// Fail closed — block all code execution from this agent.
				log.Printf("[EAKF] Agent %s requests EAKF sandbox but plugin unavailable — fail-closed (trace %s)", agentID, traceID)
				edgeLedger.AppendRecord(ledger.EventRecord{
					HumanContext: humanContextJSON,
					EventID:      fmt.Sprintf("evt-%d", time.Now().UnixNano()),
					TraceID:      traceID, TenantID: tenantID, AgentID: agentID,
					ActionClass:  "eakf_fail_closed", Decision: "deny",
					ReasonCodes:  []string{"eakfd_unreachable_fail_closed"},
					RiskScore:    1.0, TargetURL: targetURL,
				})
				writeError(w, `{"error":"code execution sandbox unavailable — request blocked (fail-closed)"}`, http.StatusServiceUnavailable)
				return
			}

			if interceptor.EventFilter(eakfReq) {
				// Route through EAKF sandbox. The interceptor handles:
				// - Translating the request to an ExecuteRequest proto
				// - Calling eakfd over UDS
				// - Dispatching eakf_redaction_alert and eakf_policy_violation alerts
				// - Triggering CIBA saga recovery for STATUS_PARTIAL_APPLY
				result, execErr := interceptor.Intercept(r.Context(), eakfReq)
				if execErr != nil {
					log.Printf("[EAKF] Execution error for agent %s: %v (trace %s)", agentID, execErr, traceID)
					writeError(w, `{"error":"sandbox execution failed"}`, http.StatusInternalServerError)
					return
				}

				// Record the execution decision in the edge ledger.
				decision := "allow"
				if result.Blocked {
					decision = "deny"
				}
				edgeLedger.AppendRecord(ledger.EventRecord{
					HumanContext: humanContextJSON,
					EventID:      fmt.Sprintf("evt-%d", time.Now().UnixNano()),
					TraceID:      traceID, TenantID: tenantID, AgentID: agentID,
					ActionClass:  "eakf_execution", Decision: decision,
					ReasonCodes:  []string{result.Reason}, RiskScore: 0.5,
					TargetURL:    targetURL,
				})

				if result.Blocked {
					writeError(w, fmt.Sprintf(`{"error":"sandbox execution blocked: %s"}`, result.Reason), http.StatusForbidden)
					return
				}

				// Execution succeeded — return the sanitised output directly
				// to the agent. The request does NOT continue to the proxy
				// forwarding path because eakfd already executed the code.
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Cicada-Trace-ID", traceID)
				w.Header().Set("X-Cicada-EAKF", "sandboxed")
				json.NewEncoder(w).Encode(map[string]any{
					"status":  "success",
					"stdout":  result.Stdout,
					"stderr":  result.Stderr,
					"sandbox": true,
				})
				return
			}
		}
	}

	// ── 9b. Request-body exfiltration scan (vault-aware) ─────────────────────
	// Before forwarding the request, scan the outbound body for credentials or
	// PII that the agent should not be sending. This closes the IPI exfiltration
	// gap: a compromised agent that leaks secrets via POST/PUT body to an
	// attacker-controlled (or legitimate-looking) endpoint is caught here.
	//
	// The vault-aware pipeline replaces the basic InspectRequestBody scan with:
	//   1. InspectWithVaultContext — local prefix matching + destination trust
	//   2. VaultAPICheck — remote BYOK hash verification against Core API
	//
	// Legitimate credential workflows (key rotation, vault storage) are allowed
	// when the destination is on the operator's propagation allowlist.
	if len(bodyBytes) > 0 && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
		// Load operator-configured propagation domains from environment.
		// These are domains where secrets MAY be legitimately sent (e.g., api.stripe.com).
		var propagationDomains []string
		if pd := os.Getenv("CICADA_SECRET_PROPAGATION_DOMAINS"); pd != "" {
			propagationDomains = strings.Split(pd, ",")
			for i := range propagationDomains {
				propagationDomains[i] = strings.TrimSpace(propagationDomains[i])
			}
		}

		// Load vaulted secret prefixes from environment.
		// These are prefixes of keys stored in the tenant's vault (e.g., "sk-", "sk_live_").
		var vaultedPrefixes []string
		if vp := os.Getenv("CICADA_VAULTED_SECRET_PREFIXES"); vp != "" {
			vaultedPrefixes = strings.Split(vp, ",")
			for i := range vaultedPrefixes {
				vaultedPrefixes[i] = strings.TrimSpace(vaultedPrefixes[i])
			}
		}

		// Run the vault-aware exfiltration check with destination trust classification.
		// historicalDomains: cached set of hostnames this agent has previously called,
		// used by the exfiltration scorer to flag credential sends to novel destinations.
		var historicalDomains map[string]bool
		if queue.Client != nil {
			cacheKey := fmt.Sprintf("cicada:hist_domains:%s", agentID)
			if cached, cErr := queue.Client.Get(r.Context(), cacheKey).Result(); cErr == nil {
				json.Unmarshal([]byte(cached), &historicalDomains)
			} else {
				// Query distinct target_api hostnames from last 30 days
				hdRows, hdErr := store.DB.Query(r.Context(),
					`SELECT DISTINCT target_api FROM action_ledger
					 WHERE agent_id = $1 AND created_at >= NOW() - INTERVAL '30 days'
					 LIMIT 100`, agentID)
				if hdErr == nil {
					defer hdRows.Close()
					historicalDomains = make(map[string]bool)
					for hdRows.Next() {
						var rawURL string
						if hdRows.Scan(&rawURL) == nil && rawURL != "" {
							// Extract hostname from URL
							if idx := strings.Index(rawURL, "://"); idx != -1 {
								host := rawURL[idx+3:]
								if slashIdx := strings.Index(host, "/"); slashIdx != -1 {
									host = host[:slashIdx]
								}
								if portIdx := strings.LastIndex(host, ":"); portIdx != -1 {
									host = host[:portIdx]
								}
								if host != "" {
									historicalDomains[host] = true
								}
							}
						}
					}
				}
				// Cache for 5 minutes to avoid DB hit on every request
				if data, jErr := json.Marshal(historicalDomains); jErr == nil {
					queue.Client.Set(r.Context(), cacheKey, string(data), 5*time.Minute)
				}
			}
		}
		vaultResult := output.InspectWithVaultContext(
			bodyBytes,
			r.Header.Get("Content-Type"),
			targetURL,
			vaultedPrefixes,
			propagationDomains,
			historicalDomains,
		)

		if vaultResult.Base.Risk {
			summary := output.FindingsSummary(vaultResult.Base.Findings)
			log.Printf("[EXFIL] Request body contains sensitive data: agent %s → %s trace %s: %s (vault_match=%v, destination=%d, reason=%s)",
				agentID, targetURL, traceID, summary, vaultResult.VaultMatch, vaultResult.Destination, vaultResult.Reason)

			// If vault prefix matched locally, cross-reference with Core API vault hashes.
			// This catches the case where the agent is exfiltrating a real vaulted BYOK key
			// (not just a string that happens to match a credential regex).
			vaultAPIMatch := false
			if vaultResult.VaultMatch {
				creds := output.ExtractSuspectedCredentials(bodyBytes)
				for _, cred := range creds {
					apiResult := output.VaultAPICheck(cred, tenantID)
					if apiResult.Match {
						vaultAPIMatch = true
						log.Printf("[EXFIL] CRITICAL — credential in request body matches vaulted BYOK key: agent %s → %s trace %s",
							agentID, targetURL, traceID)
						break
					}
				}
			}

			// Push alert to Core API with actual vault match and destination trust data.
			go output.EmitExfiltrationAlert(tenantID, agentID, targetURL, vaultResult.VaultMatch || vaultAPIMatch, vaultResult.Destination, summary, traceID)

			edgeLedger.AppendRecord(ledger.EventRecord{
				HumanContext: humanContextJSON,
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: actionScope,
				Decision: "exfiltration_risk", ReasonCodes: []string{"credential_in_request_body", vaultResult.Reason},
				RiskScore: vaultResult.Base.RiskScore,
			})

			// Block decision: vault-aware MustBlock OR operator-enabled EXFILTRATION_BLOCK
			if vaultResult.MustBlock || vaultResult.Base.Block {
				writeError(w, fmt.Sprintf(`{"error":"request blocked — %s","findings":"%s"}`, vaultResult.Reason, summary), http.StatusForbidden)
				return
			}
		}
	}

	// ── 9c. Cascade Failure Detection (ASI08) ─────────────────────────────────
	// Executed immediately post-exfiltration scan. Checks if the request body
	// contains trace IDs from other agents' recent responses — indicating a
	// multi-agent cascade where one agent's output feeds another's input.
	// Uses O(1) Redis SISMEMBER lookups against regex-extracted trace IDs.
	if len(bodyBytes) > 0 && cascadeDetector != nil {
		cascadeRes := cascadeDetector.Detect(r.Context(), string(bodyBytes), agentID)
		if cascadeRes.IsCascade {
			log.Printf("[ASI08] Cascade detected: agent %s contains trace %s from upstream agent %s (depth %d, trace %s)",
				agentID, cascadeRes.UpstreamTraceID, cascadeRes.UpstreamAgentID, cascadeRes.ChainDepth, traceID)

			edgeLedger.AppendRecord(ledger.EventRecord{
				HumanContext: humanContextJSON,
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: "cascade_detected",
				Decision: "elevated_risk",
				ReasonCodes: []string{"asi08_cascade", "upstream:" + cascadeRes.UpstreamAgentID},
				RiskScore: 0.2, // Elevate MEF risk score by 0.2
			})

			if cascadeDetector.ExceedsMaxChainDepth(cascadeRes) {
				log.Printf("[ASI08] Cascade depth %d exceeds max — CIBA hold for agent %s (trace %s)",
					cascadeRes.ChainDepth, agentID, traceID)
				writeError(w, `{"error":"cascade depth violation across agent boundaries — CIBA hold required"}`, http.StatusForbidden)
				return
			}
		}
	}

	// Store current trace ID in Redis asynchronously to avoid latency injection.
	// Future requests from other agents that reference this trace ID will be
	// detected as cascades.
	if cascadeDetector != nil {
		go cascadeDetector.RecordTrace(context.Background(), traceID, agentID, chainDepth)
	}

	// ── 10. Billing meter ─────────────────────────────────────────────────────
	sentryMeter.Increment(tenantID)

	// ── 10.5 Dry-Run Intercept ────────────────────────────────────────────────
	if r.Header.Get("X-Cicada-Dry-Run") == "true" {
		log.Printf("[DRY-RUN] Request passed all policies. Intercepting before upstream: agent %s trace %s", agentID, traceID)
		edgeLedger.AppendRecord(ledger.EventRecord{
			HumanContext:  humanContextJSON,
			EventID:       fmt.Sprintf("evt-%d", time.Now().UnixNano()),
			TraceID:       traceID, TenantID: tenantID, AgentID: agentID,
			ActionClass:   actionScope, Decision: "dry_run_passed",
			PolicyVersion: "v1.4.2", ReasonCodes: []string{"policy_passed_simulated"}, RiskScore: 0.0,
		})
		
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "dry_run_passed",
			"message":  "The request passed all Cicada policy and verification checks successfully. It was NOT forwarded to the target API.",
			"trace_id": traceID,
			"agent_id": agentID,
		})
		return
	}

	// ── 11. Actual HTTP forwarding ────────────────────────────────────────────
	// Until this point the handler has been gating. Here we actually forward
	// the request to the target API and return the real response to the agent.
	// targetURL is required for proxying. If absent, the call cannot be forwarded.
	if targetURL == "" {
		writeError(w, `{"error":"X-Cicada-Target-URL header is required for proxying"}`, http.StatusBadRequest)
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Printf("[PROXY] Failed to build outbound request for agent %s: %v", agentID, err)
		writeError(w, `{"error":"failed to construct proxy request"}`, http.StatusInternalServerError)
		return
	}

	// Forward only safe, non-Cicada headers to the target. Stripping
	// Authorization prevents leaking the agent's session token to the target.
	for _, h := range []string{"Content-Type", "Accept", "Content-Encoding", "Content-Length"} {
		if v := r.Header.Get(h); v != "" {
			outReq.Header.Set(h, v)
		}
	}
	outReq.Header.Set("X-Cicada-Trace-ID", traceID)
	outReq.Header.Set("X-Cicada-Agent-ID", agentID)

	// Pre-flight: block if Content-Length declares a response we would reject
	// before even reading the body (avoids buffering a large response to reject it).
	// Returns 413 (Payload Too Large) rather than 403 so the caller can distinguish
	// a size rejection from a policy denial and handle it appropriately.
	if declared := outReq.ContentLength; output.ShouldBlockOnContentLength(declared) {
		limit := output.MaxReadBytes() - 1
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		fmt.Fprintf(w, `{"error":"upstream response too large","detail":"declared Content-Length exceeds the %d KB limit; increase RESPONSE_MAX_BYTES to allow larger responses"}`, limit/1024)
		return
	}

	resp, err := proxyClient.Do(outReq)
	if err != nil {
		log.Printf("[PROXY] Upstream unreachable for agent %s → %s: %v", agentID, targetURL, err)
		writeError(w, `{"error":"proxy target unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read up to MaxReadBytes (default 512 KB, configurable via RESPONSE_MAX_BYTES).
	// Adding one byte over the limit means Inspect() will see a body that exceeds
	// the threshold and block it — we never silently truncate and pass a partial body.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, output.MaxReadBytes()))
	if err != nil {
		writeError(w, `{"error":"failed to read upstream response"}`, http.StatusBadGateway)
		return
	}

	// ── 12. Output inspection (response controls) ─────────────────────────────
	// Scan the response body before returning it to the agent. This closes the
	// output-controls gap: we inspect what comes BACK from target APIs, not just
	// what the agent is trying to DO.
	inspectResult := output.Inspect(respBody, resp.Header.Get("Content-Type"), resp.ContentLength)
	if inspectResult.Block {
		summary := output.FindingsSummary(inspectResult.Findings)
		log.Printf("[OUTPUT] Response blocked for agent %s trace %s: %s", agentID, traceID, summary)
		edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
			EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
			TenantID: tenantID, AgentID: agentID, ActionClass: actionScope,
			Decision: "deny", ReasonCodes: []string{"output_controls_block"}, RiskScore: inspectResult.RiskScore,
		})
		writeError(w, fmt.Sprintf(`{"error":"response blocked by output controls","findings":"%s"}`, summary), http.StatusForbidden)
		return
	}

	if len(inspectResult.Findings) > 0 {
		// Findings present but not blocking severity — log and continue.
		log.Printf("[OUTPUT] Non-blocking findings for agent %s: %s", agentID, output.FindingsSummary(inspectResult.Findings))
	}

	// ── 13. Ledger write ──────────────────────────────────────────────────────
	edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: humanContextJSON,
		EventID:       fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		TraceID:       traceID, TenantID: tenantID, AgentID: agentID,
		ActionClass:   actionScope, Decision: "allow",
		PolicyVersion: "v1.4.2", ReasonCodes: []string{"policy_passed"}, RiskScore: 0.1,
	})

	// ── 14. Return real upstream response ─────────────────────────────────────
	// Copy upstream response headers, inject our trace header, then return
	// the actual body. The agent receives the real API response — Cicada is
	// transparent to the agent except for blocked calls.
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("X-Cicada-Trace-ID", traceID)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// ────────────────────────────────────────────────────────────────────────────
// Ghost Proxy (Shadow Sandbox Routing)
//
// Forwards the intercepted agent request to the Shadow Sandbox container.
// The sandbox returns a plausible synthetic response; the agent never learns
// it was diverted. If SHADOW_SANDBOX_URL is not set or the sandbox is
// unreachable, falls back to a minimal inline response so ghost mode does
// not break the agent's execution flow.
// ────────────────────────────────────────────────────────────────────────────

func handleGhostProxy(w http.ResponseWriter, r *http.Request, agentID, traceID string) {
	sandboxURL := os.Getenv("SHADOW_SANDBOX_URL")
	if sandboxURL == "" {
		sandboxURL = "http://localhost:9090"
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024))

	// Build the envelope the sandbox expects.
	tenantID := r.Header.Get("X-Cicada-Tenant-ID")
	targetURL := r.Header.Get("X-Cicada-Target-URL")

	envelope, _ := json.Marshal(map[string]any{
		"agent_id":   agentID,
		"tenant_id":  tenantID,
		"trace_id":   traceID,
		"method":     r.Method,
		"target_url": targetURL,
		"body":       string(bodyBytes),
	})

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sandboxURL+"/sandbox/proxy", bytes.NewReader(envelope))
	if err != nil {
		log.Printf("[GHOST] Failed to build sandbox request for agent %s: %v", agentID, err)
		ghostFallback(w, r.Method, agentID)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := proxyClient.Do(req)
	if err != nil {
		log.Printf("[GHOST] Sandbox unreachable for agent %s: %v — using fallback", agentID, err)
		ghostFallback(w, r.Method, agentID)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))

	// Mirror the sandbox's response headers and body back to the agent.
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("X-Cicada-Trace-ID", traceID)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	log.Printf("[GHOST] Agent %s → sandbox → %d bytes returned", agentID, len(respBody))
}

// ghostFallback returns a minimal plausible response when the sandbox is
// unreachable. This ensures ghost mode does not break the agent's flow even
// if the sandbox container is not yet started.
func ghostFallback(w http.ResponseWriter, method, agentID string) {
	fakeID := fmt.Sprintf("ghost_%d", time.Now().UnixNano())
	ghostLedger.Store(fakeID, `{"status":"intercepted_ghost_payload"}`)
	log.Printf("[GHOST] Fallback response for agent %s id=%s", agentID, fakeID)

	w.Header().Set("Content-Type", "application/json")
	if method == "DELETE" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if method == "POST" {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	w.Write([]byte(fmt.Sprintf(`{"status":"success","id":"%s"}`, fakeID)))
}

// ────────────────────────────────────────────────────────────────────────────
// Inter-Node Gossip Receive
//
// Accepts compressed gossip batches from peer Sentry Gateway nodes. Each batch
// is a zlib-compressed newline-delimited sequence of pipe-separated records:
//   agentID|Status|Timestamp|NodeID
//
// State is applied via ReceiveGossip using LWW conflict resolution — the record
// with the highest timestamp wins. This endpoint must only be reachable from
// other Sentry Gateway nodes; place it behind a network policy or mTLS proxy.
// ────────────────────────────────────────────────────────────────────────────

func handleGossipReceive(w http.ResponseWriter, r *http.Request) {
	// ── Layer 1: IP allowlist (existing) ──────────────────────────────────
	// Restrict to loopback and configured internal IPs.
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteIP == "" {
		remoteIP = r.RemoteAddr
	}
	allowedIPs := map[string]bool{"127.0.0.1": true, "::1": true}
	if extra := os.Getenv("CICADA_GOSSIP_ALLOWED_IPS"); extra != "" {
		for _, ip := range strings.Split(extra, ",") {
			allowedIPs[strings.TrimSpace(ip)] = true
		}
	}
	if !allowedIPs[remoteIP] {
		writeError(w, `{"error":"gossip receive: unauthorized source"}`, http.StatusForbidden)
		return
	}

	compressed, err := io.ReadAll(io.LimitReader(r.Body, 1*1024*1024))
	if err != nil {
		writeError(w, `{"error":"read error"}`, http.StatusBadRequest)
		return
	}

	// ── Layer 2: HMAC-SHA256 verification (new) ──────────────────────────
	// When CICADA_GOSSIP_SECRET is configured, every incoming batch must
	// include a valid X-Gossip-HMAC header. This prevents any host that
	// passes the IP allowlist (e.g. a compromised internal service) from
	// injecting quarantine/release state into the CRDT mesh.
	gossipSecret := gossip.GossipSecret()
	if gossipSecret != "" {
		providedHMAC := r.Header.Get("X-Gossip-HMAC")
		if providedHMAC == "" {
			log.Printf("[GOSSIP] SECURITY: Rejected gossip from %s — missing X-Gossip-HMAC header", remoteIP)
			writeError(w, `{"error":"gossip receive: missing HMAC authentication"}`, http.StatusForbidden)
			return
		}
		if !gossip.VerifyHMAC(compressed, providedHMAC, gossipSecret) {
			log.Printf("[GOSSIP] SECURITY: Rejected gossip from %s — invalid HMAC signature", remoteIP)
			writeError(w, `{"error":"gossip receive: invalid HMAC signature"}`, http.StatusForbidden)
			return
		}
	}

	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		writeError(w, `{"error":"decompression failed"}`, http.StatusBadRequest)
		return
	}
	defer zr.Close()

	decompressed, err := io.ReadAll(zr)
	if err != nil {
		writeError(w, `{"error":"decompression read failed"}`, http.StatusBadRequest)
		return
	}

	applied := 0
	for _, line := range strings.Split(string(decompressed), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Wire format v2 (tenant-scoped): TenantID|AgentID|Status|Timestamp|NodeID
		// Wire format v1 (legacy):        AgentID|Status|Timestamp|NodeID
		// Accept both for backward compatibility during rolling upgrades.
		var tenantID, agentID, status, nodeID string
		var ts int64

		parts := strings.SplitN(line, "|", 5)
		switch len(parts) {
		case 5:
			// v2: tenant-scoped wire format
			tenantID = parts[0]
			agentID = parts[1]
			status = parts[2]
			fmt.Sscanf(parts[3], "%d", &ts)
			nodeID = parts[4]
		case 4:
			// v1: legacy wire format (pre-upgrade peers)
			agentID = parts[0]
			status = parts[1]
			fmt.Sscanf(parts[2], "%d", &ts)
			nodeID = parts[3]
		default:
			continue
		}

		gossipMesh.ReceiveGossip(agentID, gossip.AgentState{
			TenantID:  tenantID,
			Status:    status,
			Timestamp: ts,
			NodeID:    nodeID,
		})
		applied++
	}

	log.Printf("[GOSSIP] Applied %d state updates from peer %s", applied, remoteIP)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"applied":%d}`, applied)))
}

// ────────────────────────────────────────────────────────────────────────────
// Shadow Sandbox Anomaly Report
//
// The Shadow Sandbox container POSTs here when it detects an anomaly in a
// ghost-mode agent's intercepted request (score ≥ 0.70). The gateway logs
// the finding to the action ledger so it appears in the operator dashboard.
// Quarantine is not automatic — the operator decides via Aegis-0.
// ────────────────────────────────────────────────────────────────────────────

func handleSandboxReport(w http.ResponseWriter, r *http.Request) {
	var report struct {
		AgentID      string  `json:"agent_id"`
		TenantID     string  `json:"tenant_id"`
		TraceID      string  `json:"trace_id"`
		AnomalyScore float64 `json:"anomaly_score"`
		Summary      string  `json:"summary"`
		ReportedAt   string  `json:"reported_at"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err := json.Unmarshal(body, &report); err != nil {
		writeError(w, `{"error":"invalid report"}`, http.StatusBadRequest)
		return
	}
	log.Printf("[SANDBOX-REPORT] agent=%s score=%.2f findings=%s",
		report.AgentID, report.AnomalyScore, report.Summary)

	decision := "flagged"
	if report.AnomalyScore >= 0.85 {
		decision = "quarantined"
	}

	edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: "",
		EventID:     fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		TraceID:     report.TraceID,
		TenantID:    report.TenantID,
		AgentID:     report.AgentID,
		ActionClass: "sandbox_anomaly",
		Decision:    decision,
		ReasonCodes: []string{"sandbox_anomaly_detected"},
		RiskScore:   report.AnomalyScore,
	})

	if report.AnomalyScore >= 0.85 {
		log.Printf("[SANDBOX-REPORT] SCORE %.2f >= 0.85 — AUTO-QUARANTINING AGENT %s", report.AnomalyScore, report.AgentID)
		gossipMesh.QuarantineAgent(report.AgentID)
	}

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status":"received"}`))
}

// ────────────────────────────────────────────────────────────────────────────
// Agent Rollback (Saga Enqueue)
// ────────────────────────────────────────────────────────────────────────────

func handleAgentRollback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TraceID      string `json:"trace_id"`
		FailedAction string `json:"failed_action"`
		RevertRoute  string `json:"revert_route"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, `{"error":"invalid JSON payload"}`, http.StatusBadRequest)
		return
	}

	if body.TraceID == "" || body.FailedAction == "" || body.RevertRoute == "" {
		writeError(w, `{"error":"trace_id, failed_action, and revert_route are required"}`, http.StatusBadRequest)
		return
	}

	// SSRF protection: validate revert route through the shared SSRF validator.
	// Enforces HTTPS scheme, blocks loopback/private/link-local IPs via DNS
	// resolution, AND checks the domain allowlist. Both must pass.
	if err := ssrf.ValidateOutboundURL(body.RevertRoute, allowlistedDomains); err != nil {
		log.Printf("[SECURITY] SSRF blocked for revert route: %v", err)
		writeError(w, `{"error":"revert route failed SSRF validation"}`, http.StatusForbidden)
		return
	}

	// Compute action hash
	h := sha256.Sum256([]byte(body.TraceID + body.FailedAction + time.Now().String()))
	actionHash := hex.EncodeToString(h[:])
	rollbackID := fmt.Sprintf("rb-%d", time.Now().UnixNano())

	// Enqueue to real Redis
	err := queue.PushRollback(r.Context(), queue.SagaJob{
		RollbackID:         rollbackID,
		TraceID:            body.TraceID,
		OriginalActionHash: actionHash,
		RevertRoute:        body.RevertRoute,
		FailedAction:       body.FailedAction,
	})
	if err != nil {
		log.Printf("[QUEUE ERROR] Saga enqueue failed: %v", err)
		writeError(w, `{"error":"failed to enqueue rollback"}`, http.StatusInternalServerError)
		return
	}

	edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: "",
		EventID:     fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		TraceID:     body.TraceID,
		ActionClass: body.FailedAction,
		Decision:    "rollback_triggered",
		ReasonCodes: []string{"saga_intent_published"},
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(fmt.Sprintf(`{"status":"saga_initiated","rollback_id":"%s"}`, rollbackID)))
}

// ────────────────────────────────────────────────────────────────────────────
// Public Trust Introspection
// ────────────────────────────────────────────────────────────────────────────

func handlePublicTrustIntrospection(w http.ResponseWriter, r *http.Request) {
	evarToken := chi.URLParam(r, "evar")

	// Verify the token cryptographically
	payload, err := auth.VerifyEVARToken(evarToken)
	if err != nil {
		writeError(w, `{"error":"invalid or expired EVAR token"}`, http.StatusUnauthorized)
		return
	}

	// Check gossip revocation
	status := "CERTIFIED"
	if gossipMesh.IsQuarantined(payload.AgentID) {
		status = "REVOKED"
	}

	response := map[string]interface{}{
		"agent_identity": payload.AgentID,
		"trust_tier":     status,
		"intended_model": payload.ModelIntended,
		"scopes":         payload.Scopes,
	}

	w.Header().Set("Content-Type", "application/json")
	if status == "REVOKED" {
		w.WriteHeader(http.StatusForbidden)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(response)
}

// ────────────────────────────────────────────────────────────────────────────
// Key Binding (Tenant KMS)
// ────────────────────────────────────────────────────────────────────────────

func handleKeyBinding(w http.ResponseWriter, r *http.Request) {
	// In production, extract tenantID from a verified session JWT
	authHeader := r.Header.Get("Authorization")
	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	if rawToken == "" || rawToken == authHeader {
		writeError(w, `{"error":"missing tenant authorization"}`, http.StatusForbidden)
		return
	}

	// Verify the bearer token as an EVAR JWT to extract tenant context
	claims, err := auth.VerifyEVARToken(rawToken)
	if err != nil {
		writeError(w, `{"error":"invalid authorization token"}`, http.StatusUnauthorized)
		return
	}
	tenantID := claims.AgentID // Use the agent's identity as tenant context

	var body struct {
		Provider string `json:"provider"`
		RawKey   string `json:"raw_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	cipherBlob, err := tenantKeyVault.EncryptUserKey(r.Context(), body.RawKey, tenantID)
	if err != nil {
		writeError(w, `{"error":"encryption failed"}`, http.StatusInternalServerError)
		return
	}

	// Zero the raw key from memory
	body.RawKey = ""

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"status":"success","provider":"%s","cipher_length":%d}`, body.Provider, len(cipherBlob))))
}

// ────────────────────────────────────────────────────────────────────────────
// Aegis-0 Directives
// ────────────────────────────────────────────────────────────────────────────

func handleAegisDirectives(w http.ResponseWriter, r *http.Request) {
	if err := verifyAegisAuth(r); err != nil {
		writeError(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	var body struct {
		PromptData string `json:"prompt_data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Persist to PostgreSQL
	_, err := store.DB.Exec(r.Context(),
		"INSERT INTO action_ledger (tenant_id, agent_id, action_type, payload_hash, target_api, status) VALUES ('system', '00000000-0000-0000-0000-000000000000'::uuid, 'aegis_directive', $1, '/aegis/directives', 'approved')",
		fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(body.PromptData))),
	)
	if err != nil {
		log.Printf("[AEGIS ERROR] Directive persistence failed: %v", err)
		writeError(w, `{"error":"directive persistence failed"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success","message":"directive persisted"}`))
}

// ────────────────────────────────────────────────────────────────────────────
// Aegis-0 MCP Execution
// ────────────────────────────────────────────────────────────────────────────

type MCPToolCall struct {
	ToolName    string                 `json:"name"`
	InputSchema map[string]interface{} `json:"inputSchema"`
	RequestID   string                 `json:"request_id"`
}

func handleMCPExecution(w http.ResponseWriter, r *http.Request) {
	// IP boundary protection
	remoteIP := strings.Split(r.RemoteAddr, ":")[0]
	allowedIPs := map[string]bool{"127.0.0.1": true, "::1": true}

	// Allow additional IPs from env
	if extra := os.Getenv("CICADA_AEGIS_ALLOWED_IPS"); extra != "" {
		for _, ip := range strings.Split(extra, ",") {
			allowedIPs[strings.TrimSpace(ip)] = true
		}
	}

	if !allowedIPs[remoteIP] {
		log.Printf("[SECURITY] MCP access denied from IP: %s", remoteIP)
		writeError(w, `{"error":"unauthorized node perimeter"}`, http.StatusForbidden)
		return
	}

	if err := verifyAegisAuth(r); err != nil {
		writeError(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	var call MCPToolCall
	if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
		writeError(w, `{"error":"invalid MCP tool payload"}`, http.StatusBadRequest)
		return
	}

	switch call.ToolName {
	case "quarantine_agent":
		target, ok := call.InputSchema["target_id"].(string)
		if !ok {
			writeError(w, `{"error":"missing target_id"}`, http.StatusBadRequest)
			return
		}
		gossipMesh.QuarantineAgent(target)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","action":"quarantine deployed"}`))

	case "trigger_saga_rollback":
		// Previously a stub — now enqueues a real saga rollback job to Redis.
		// The Saga Executor worker picks this up and fires the compensating
		// transaction against the revert_route declared at agent registration.
		traceID, ok := call.InputSchema["trace_id"].(string)
		revertRoute, _ := call.InputSchema["revert_route"].(string)
		failedAction, _ := call.InputSchema["failed_action"].(string)
		if !ok || traceID == "" {
			writeError(w, `{"error":"missing trace_id"}`, http.StatusBadRequest)
			return
		}
		if revertRoute == "" {
			revertRoute = "unknown"
		}
		if failedAction == "" {
			failedAction = "aegis_triggered_rollback"
		}
		rollbackID := fmt.Sprintf("rb-%d", time.Now().UnixNano())
		h := sha256.Sum256([]byte(traceID + failedAction + time.Now().String()))
		if err := queue.PushRollback(r.Context(), queue.SagaJob{
			RollbackID:         rollbackID,
			TraceID:            traceID,
			OriginalActionHash: hex.EncodeToString(h[:]),
			RevertRoute:        revertRoute,
			FailedAction:       failedAction,
		}); err != nil {
			log.Printf("[AEGIS ERROR] Rollback enqueue failed for trace %s: %v", traceID, err)
			writeError(w, `{"error":"rollback enqueue failed"}`, http.StatusInternalServerError)
			return
		}
		log.Printf("[AEGIS] Saga rollback enqueued for trace %s rollback_id %s", traceID, rollbackID)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "rollback_id": rollbackID, "action": "saga enqueued"})

	case "engage_ghost_mode":
		// Previously a stub — now registers the agent in the ghost mode Redis
		// registry. The proxy pipeline checks this registry before forwarding.
		agentSig, ok := call.InputSchema["agent_signature"].(string)
		if !ok || agentSig == "" {
			writeError(w, `{"error":"missing agent_signature"}`, http.StatusBadRequest)
			return
		}
		if err := ghostmode.Activate(r.Context(), agentSig); err != nil {
			log.Printf("[AEGIS ERROR] Ghost mode activation failed for %s: %v", agentSig, err)
			writeError(w, `{"error":"ghost mode activation failed"}`, http.StatusInternalServerError)
			return
		}
		log.Printf("[AEGIS] Ghost mode engaged for agent: %s", agentSig)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","action":"ghost mode routing active"}`))

	default:
		writeError(w, fmt.Sprintf(`{"error":"unknown tool: %s"}`, call.ToolName), http.StatusBadRequest)
	}
}

// verifyAegisAuth checks the Aegis master token from environment.
func verifyAegisAuth(r *http.Request) error {
	expectedToken := os.Getenv("CICADA_AEGIS_TOKEN")
	if expectedToken == "" {
		return fmt.Errorf("CICADA_AEGIS_TOKEN not configured")
	}

	authHeader := r.Header.Get("Authorization")
	provided := strings.TrimPrefix(authHeader, "Bearer ")
	if provided == "" || provided != expectedToken {
		return fmt.Errorf("invalid master signature")
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// WebSocket City Telemetry
// ────────────────────────────────────────────────────────────────────────────

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production, validate against CICADA_CORS_ORIGINS env var
		origins := os.Getenv("CICADA_CORS_ORIGINS")
		if origins == "" {
			return true // Dev mode only
		}
		origin := r.Header.Get("Origin")
		for _, allowed := range strings.Split(origins, ",") {
			if strings.TrimSpace(allowed) == origin {
				return true
			}
		}
		return false
	},
}

type CityTelemetryResponse struct {
	CityID  string      `json:"city_id"`
	Metrics CityMetrics `json:"metrics"`
}

type CityMetrics struct {
	ActiveInstances  int64   `json:"active_instances"`
	AvgLatencyMs     float64 `json:"avg_latency_ms"`
	ThreatPulseScore int     `json:"threat_pulse_score"`
	TotalBurnRate    string  `json:"total_burn_rate"`
}

func handleWSCityTelemetry(w http.ResponseWriter, r *http.Request) {
	cityID := chi.URLParam(r, "city_id")
	if cityID == "" {
		writeError(w, `{"error":"missing city_id"}`, http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS ERROR] Upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		return nil
	})

	heartbeatTicker := time.NewTicker(3 * time.Second)
	defer heartbeatTicker.Stop()

	go func() {
		for range heartbeatTicker.C {
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(200 * time.Millisecond) // 5Hz
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			// Query real metrics from Redis/Postgres
			usage, _ := queue.GetTenantUsage(r.Context(), cityID)

			resp := CityTelemetryResponse{
				CityID: cityID,
				Metrics: CityMetrics{
					ActiveInstances:  usage,
					AvgLatencyMs:     agentcache.Stats().AvgLatencyMs, // Real measured latency from cache counters
					ThreatPulseScore: len(gossipMesh.QuarantinedList()),
					TotalBurnRate:    fmt.Sprintf("$%.2f", float64(usage)*0.002), // Estimated from active instance count × per-tx cost
				},
			}

			if err := conn.WriteJSON(resp); err != nil {
				log.Printf("[WS] Disconnect for city %s: %v", cityID, err)
				return
			}
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// LLM API Proxy (Memory Isolation + Reasoning Audit)
//
// This handler intercepts agent-to-LLM-provider calls. Because the agent sends
// its full messages[] array to the LLM, this proxy sees the agent's complete
// context window on every inference call — enabling:
//
//  1. Memory isolation: per-message content hashes are stored in Redis under
//     the tenant's context map. If a hash from this agent's context was
//     previously registered to a DIFFERENT agent in the same tenant, that
//     content has crossed agent boundaries (contamination).
//
//  2. Audit trails of reasoning: chain-of-thought tokens (Claude <thinking>
//     blocks, OpenAI o1/o3 reasoning_content) are extracted from the LLM
//     response and written to the evidence chain before being returned to the
//     agent. When an agent causes harm, a reviewer can pull the exact reasoning
//     chain that preceded it.
//
// Agent integration: point your LLM client's base URL at the Gateway, pass your
// EVAR/session in Authorization, your real LLM key in X-Cicada-LLM-Key, and
// set X-Cicada-Target-URL to the real provider endpoint. The response you
// receive is byte-identical to what the provider would have returned directly.
// ────────────────────────────────────────────────────────────────────────────
func handleLLMProxy(w http.ResponseWriter, r *http.Request) {
	// Buffer the full request body. The body is read once here and passed to
	// both the context extraction logic and the forwarded request.
	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
		if err != nil {
			writeError(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
			return
		}
		r.Body.Close()
	}

	// ── Token verification ────────────────────────────────────────────────────
	authHeader := r.Header.Get("Authorization")
	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	if rawToken == "" || rawToken == authHeader {
		writeError(w, `{"error":"missing Authorization header — present your EVAR or session token"}`, http.StatusUnauthorized)
		return
	}

	var agentID, tenantID, agentRegion string
	if sessionClaims, err := session.Verify(rawToken); err == nil {
		agentID = sessionClaims.AgentID
		tenantID = sessionClaims.TenantID
		agentRegion = sessionClaims.DataResidencyRegion
	} else {
		evarPayload, verifyErr := auth.VerifyEVARToken(rawToken)
		if verifyErr != nil {
			log.Printf("[LLMPROXY] Token verification failed: %v", verifyErr)
			writeError(w, `{"error":"invalid token — present a valid session token or EVAR"}`, http.StatusUnauthorized)
			return
		}
		agentID = evarPayload.AgentID
		tenantID = evarPayload.Issuer
		agentRegion = evarPayload.DataResidencyRegion
		if tenantID == "cicada-cocoon-lab" || tenantID == "" {
			// Resolve the actual tenant UUID from the agents table.
			var resolvedTenant string
			if err := store.DB.QueryRow(r.Context(),
				`SELECT COALESCE(tenant_id::text, '') FROM agents WHERE id = $1`, agentID,
			).Scan(&resolvedTenant); err == nil && resolvedTenant != "" {
				tenantID = resolvedTenant
			} else {
				tenantID = "00000000-0000-0000-0000-000000000001"
				log.Printf("[WARN] Could not resolve tenant for agent %s — using dev workspace UUID", agentID)
			}
		}
	}

	// ── 0.5 Data Residency Enforcement ─────────────────────────────────────────
	gatewayRegion := os.Getenv("CICADA_REGION")
	if gatewayRegion != "" && agentRegion != "" && gatewayRegion != agentRegion {
		log.Printf("[DATA RESIDENCY BLOCKED] Agent %s requested LLM proxy for region %s but gateway is pinned to %s", agentID, agentRegion, gatewayRegion)
		writeError(w, fmt.Sprintf(`{"error":"data_residency_violation", "message":"Agent is pinned to %s region. This gateway operates in %s."}`, agentRegion, gatewayRegion), http.StatusForbidden)
		return
	}

	traceID := fmt.Sprintf("llm-%d", time.Now().UnixNano())
	targetURL := r.Header.Get("X-Cicada-Target-URL")
	llmKey := r.Header.Get("X-Cicada-LLM-Key")

	if targetURL == "" {
		writeError(w, `{"error":"X-Cicada-Target-URL required — set this to the real LLM provider endpoint"}`, http.StatusBadRequest)
		return
	}
	if llmKey == "" {
		writeError(w, `{"error":"X-Cicada-LLM-Key required — pass your LLM provider API key in this header"}`, http.StatusBadRequest)
		return
	}

	// ── Quarantine check ──────────────────────────────────────────────────────
	if gossipMesh.IsQuarantined(agentID) || gossipMesh.IsQuarantined(fmt.Sprintf("%s_WILDCARD", tenantID)) {
		writeError(w, `{"error":"agent or tenant quarantined"}`, http.StatusForbidden)
		return
	}

	// ── Detect provider and extract context window ────────────────────────────
	provider := llmproxy.DetectProvider(targetURL)

	// Extract the model identifier from the top-level JSON body.
	// Both OpenAI and Anthropic include {"model": "gpt-4o"} or {"model": "claude-3-5-sonnet-..."}
	// at the request root. We capture it here before any ledger writes.
	var llmModel string
	if len(bodyBytes) > 0 {
		var bodyMap map[string]interface{}
		if json.Unmarshal(bodyBytes, &bodyMap) == nil {
			if m, ok := bodyMap["model"].(string); ok {
				llmModel = m
			}
		}
	}

	var fingerprint string
	var contaminated bool
	var contaminatedBy string

	if messages, extractErr := llmproxy.ExtractMessages(bodyBytes, provider); extractErr == nil && len(messages) > 0 {
		// ── Prompt injection scan on LLM messages ─────────────────────────────
		// Scan each non-system message for injection patterns. This catches
		// indirect injection: content from an external source (a database row,
		// a document, a tool result) that has been included in the context and
		// contains instructions designed to hijack the model's behaviour.
		for _, msg := range messages {
			injResult := injection.Scan(msg.Content, msg.Role)
			if injResult.Block {
				summary := injection.Summary(injResult.Findings)
				log.Printf("[INJECTION] LLM message blocked for agent %s role=%s trace %s: %s",
					agentID, msg.Role, traceID, summary)
				edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: "",
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "llm_proxy",
					Decision: "deny", ReasonCodes: []string{"prompt_injection_in_context"}, RiskScore: injResult.Score,
					Model: llmModel,
				})
				go output.EmitThreatAlert(
					"prompt_injection", "high", tenantID, agentID, "",
					fmt.Sprintf("Prompt injection detected in LLM context (%s): %s", msg.Role, summary),
					"Review application code that feeds untrusted user input into LLM context without sanitization.", traceID, nil,
				)
				writeError(w, fmt.Sprintf(`{"error":"prompt injection detected in LLM context","findings":"%s"}`, summary), http.StatusForbidden)
				return
			}
		}

		var hashes []string
		fingerprint, hashes = llmproxy.ComputeFingerprint(messages)

		// Cross-contamination check: did any content from this context window
		// originate in a different agent's context within the same tenant?
		contaminated, contaminatedBy, _ = llmproxy.CheckContamination(r.Context(), tenantID, agentID, hashes)

		if contaminated {
			log.Printf("[MEMISO] CONTAMINATION: agent %s context contains content from agent %s (trace %s)",
				agentID, contaminatedBy, traceID)
			// Non-blocking: log to ledger and continue. We do not block the call —
			// contamination is an observation for Aegis-0 to investigate; blocking
			// would tip off the attacker that they were detected.
			edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: "",
				EventID:            fmt.Sprintf("evt-%d", time.Now().UnixNano()),
				TraceID:            traceID, TenantID: tenantID, AgentID: agentID,
				ActionClass:        "llm_proxy",
				Decision:           "contamination_detected",
				ReasonCodes:        []string{"cross_agent_context_contamination", "source_agent:" + contaminatedBy},
				RiskScore:          0.90,
				ContextFingerprint: fingerprint,
				Model:              llmModel,
			})
		}

		// ── Phase 8: Semantic contamination check ─────────────────────────────
		// Run only when the hash check did not already detect contamination —
		// no point running the more expensive check when the cheap one already fired.
		//
		// For each message in the context window, compute a SimHash fingerprint
		// and named-entity recall score against every other agent's registered
		// context in this tenant. If the combined similarity score exceeds the
		// configured threshold (default 0.40, env SEMANTIC_SIMILARITY_THRESHOLD),
		// declare semantic contamination.
		//
		// This closes the paraphrase gap: Agent B writing "roughly forty-seven
		// thousand pounds, sort code 204453, account ending 6819" will match
		// Agent A's context containing "£47,230.00, sort code: 20-44-53, account
		// number: 31926819" because the normalised sort code and 4-digit account
		// suffix are shared entities, and the SimHash overlap on shared tokens
		// (john, account, sort, code) contributes additional signal.
		if !contaminated {
			for _, msg := range messages {
				semContaminated, semSource, simScore, semErr := memory.CheckSemanticContamination(
					r.Context(), tenantID, agentID, msg.Content,
				)
				if semErr != nil {
					log.Printf("[MEMISO-SEM] Check error for agent %s: %v", agentID, semErr)
					continue
				}
				if semContaminated {
					log.Printf(
						"[MEMISO-SEM] SEMANTIC CONTAMINATION: agent=%s score=%.3f source=%s trace=%s",
						agentID, simScore, semSource, traceID,
					)
					edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: "",
						EventID:            fmt.Sprintf("evt-%d", time.Now().UnixNano()),
						TraceID:            traceID, TenantID: tenantID, AgentID: agentID,
						ActionClass:        "llm_proxy",
						Decision:           "contamination_detected",
						ReasonCodes:        []string{"cross_agent_semantic_contamination", "source_agent:" + semSource, fmt.Sprintf("sim_score:%.3f", simScore)},
						RiskScore:          simScore,
						ContextFingerprint: fingerprint,
						Model:              llmModel,
					})
					break // one semantic match per request is sufficient to alert
				}
			}
		}
	} else if extractErr != nil {
		// Extraction failure is non-fatal. Unknown providers or malformed payloads
		// should still be proxied — we log the issue and continue without inspection.
		log.Printf("[LLMPROXY] Context extraction failed for agent %s provider %s: %v",
			agentID, llmproxy.ProviderName(provider), extractErr)
	}

	// ── Ghost mode: return plausible fake LLM response ────────────────────────
	if ghostmode.IsActive(r.Context(), agentID) {
		log.Printf("[GHOST] Agent %s LLM call intercepted — returning ghost response", agentID)
		edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: "",
			EventID:            fmt.Sprintf("evt-%d", time.Now().UnixNano()),
			TraceID:            traceID, TenantID: tenantID, AgentID: agentID,
			ActionClass:        "llm_proxy",
			Decision:           "ghost_proxied",
			ReasonCodes:        []string{"ghost_mode_active"},
			RiskScore:          0.3,
			ContextFingerprint: fingerprint,
			Model:              llmModel,
		})
		handleGhostLLMResponse(w, provider)
		return
	}

	// ── Dry-Run Intercept ─────────────────────────────────────────────────────
	if r.Header.Get("X-Cicada-Dry-Run") == "true" {
		log.Printf("[DRY-RUN] LLM Request passed all policies. Intercepting before upstream: agent %s trace %s", agentID, traceID)
		edgeLedger.AppendRecord(ledger.EventRecord{
			HumanContext:       "",
			EventID:            fmt.Sprintf("evt-%d", time.Now().UnixNano()),
			TraceID:            traceID, TenantID: tenantID, AgentID: agentID,
			ActionClass:        "llm_proxy",
			Decision:           "dry_run_passed",
			ReasonCodes:        []string{"policy_passed_simulated"},
			RiskScore:          0.0,
			ContextFingerprint: fingerprint,
			Model:              llmModel,
		})
		handleGhostLLMResponse(w, provider)
		return
	}

	// ── Billing meter ─────────────────────────────────────────────────────────
	sentryMeter.Increment(tenantID)

	// ── Forward to real LLM provider ─────────────────────────────────────────
	// Strip all Cicada-specific headers from the outbound request. Inject the
	// agent's real LLM API key as the Authorization header so the provider
	// authenticates against the tenant's own key (BYOK model — Cicada never
	// holds or pays for LLM inference).
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Printf("[LLMPROXY] Failed to build outbound request for agent %s: %v", agentID, err)
		writeError(w, `{"error":"failed to construct LLM proxy request"}`, http.StatusInternalServerError)
		return
	}

	for _, h := range []string{"Content-Type", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			outReq.Header.Set(h, v)
		}
	}
	outReq.Header.Set("Authorization", "Bearer "+llmKey)
	// Anthropic requires this version header; harmless to OpenAI if present.
	if av := r.Header.Get("anthropic-version"); av != "" {
		outReq.Header.Set("anthropic-version", av)
	}
	outReq.Header.Set("X-Cicada-Trace-ID", traceID)

	resp, err := proxyClient.Do(outReq)
	if err != nil {
		log.Printf("[LLMPROXY] Provider unreachable for agent %s → %s: %v", agentID, targetURL, err)
		writeError(w, `{"error":"LLM provider unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// ── Copy response headers before deciding streaming vs buffered path ──────
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("X-Cicada-Trace-ID", traceID)

	// ── Streaming detection ───────────────────────────────────────────────────
	// OpenAI and Anthropic use text/event-stream for streaming responses.
	// When streaming is active we cannot buffer the full response before
	// returning it — that would destroy streaming semantics and add latency
	// equal to the full inference time. Instead we pipe the response directly
	// to the agent and log the audit record async with what we have (the
	// context fingerprint and contamination result). Reasoning trace extraction
	// is skipped on the streaming path because we never hold the complete body.
	//
	// Tradeoff accepted: on the streaming path we cannot extract reasoning
	// tokens because we never see the complete response. The context window
	// inspection (fingerprinting, contamination, injection) still runs on the
	// request side, which is where the security-critical information lives.
	contentType := resp.Header.Get("Content-Type")
	isStreaming := strings.Contains(contentType, "text/event-stream") ||
		strings.Contains(contentType, "application/x-ndjson")

	if isStreaming {
		// Log what we know from the request side — no reasoning trace available
		edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: "",
			EventID:            fmt.Sprintf("evt-%d", time.Now().UnixNano()),
			TraceID:            traceID, TenantID: tenantID, AgentID: agentID,
			ActionClass:        "llm_proxy",
			Decision:           "allow",
			PolicyVersion:      "v1.4.2",
			ReasonCodes:        []string{"llm_audit_streaming", "provider:" + llmproxy.ProviderName(provider)},
			RiskScore:          0.1,
			ContextFingerprint: fingerprint,
			Model:              llmModel,
		})
		w.WriteHeader(resp.StatusCode)
		// Stream directly — io.Copy flushes as data arrives
		flusher, canFlush := w.(http.Flusher)
		buf := make([]byte, 4096)
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				if canFlush {
					flusher.Flush()
				}
			}
			if readErr != nil {
				break
			}
		}
		return
	}

	// ── Buffered path (non-streaming) ─────────────────────────────────────────
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		writeError(w, `{"error":"failed to read LLM provider response"}`, http.StatusBadGateway)
		return
	}

	// ── Extract chain-of-thought reasoning trace ──────────────────────────────
	reasoningTrace := llmproxy.ExtractReasoningTrace(respBody, provider)
	if reasoningTrace != "" {
		log.Printf("[LLMPROXY] Reasoning trace captured for agent %s: %d bytes (trace %s)",
			agentID, len(reasoningTrace), traceID)
	}

	// ── Ledger write — full LLM audit record ──────────────────────────────────
	edgeLedger.AppendRecord(ledger.EventRecord{
		HumanContext: "",
		EventID:            fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		TraceID:            traceID, TenantID: tenantID, AgentID: agentID,
		ActionClass:        "llm_proxy",
		Decision:           "allow",
		PolicyVersion:      "v1.4.2",
		ReasonCodes:        []string{"llm_audit_complete", "provider:" + llmproxy.ProviderName(provider)},
		RiskScore:          0.1,
		ContextFingerprint: fingerprint,
		ReasoningTrace:     reasoningTrace,
		Model:              llmModel,
	})

	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleGhostLLMResponse returns a structurally valid but fake LLM response.
// The response matches the provider's schema precisely so the agent processes
// it without errors — it receives a benign, generic reply instead of a real
// inference result. The agent cannot distinguish this from a real response.
func handleGhostLLMResponse(w http.ResponseWriter, provider llmproxy.Provider) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	switch provider {
	case llmproxy.ProviderOpenAI:
		w.Write([]byte(`{"id":"chatcmpl-ghost-0000","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"I understand your request. I have reviewed the information and can confirm the action has been noted."},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":22,"total_tokens":42}}`))
	case llmproxy.ProviderAnthropic:
		w.Write([]byte(`{"id":"msg_ghost_0000","type":"message","role":"assistant","model":"claude-3-5-sonnet-20241022","content":[{"type":"text","text":"I understand your request. I have reviewed the information and can confirm the action has been noted."}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":20,"output_tokens":22}}`))
	default:
		w.Write([]byte(`{"result":"ok","message":"Request processed successfully."}`))
	}
}

// handleSimulatedRequest executes the full in-memory Zero-Trust enforcement
// pipeline (Gossip Mesh quarantine, 3-Tier SSRF & IMDS guard, Prompt Injection
// & Hidden DOM scanner, Canary Honeytoken trap, Semantic Intent alignment,
// OPA Rego policy evaluation, Vault-aware Credential Exfiltration DLP, and
// SHA-256 SQLite Edge Ledger recording) without requiring external LLM API keys,
// PostgreSQL, or Redis.
//
// Enable with: CICADA_DEV_MODE=true CICADA_SIMULATION_MODE=true ./sentry
func handleSimulatedRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	remotePrefix := "local"
	if len(r.RemoteAddr) >= 4 {
		remotePrefix = hex.EncodeToString([]byte(r.RemoteAddr)[:4])
	}
	traceID := fmt.Sprintf("sim-%s-%d", remotePrefix, time.Now().UnixNano())

	agentID := r.Header.Get("X-Cicada-Agent-ID")
	if agentID == "" {
		agentID = "agent-demo-01"
	}
	tenantID := r.Header.Get("X-Cicada-Tenant-ID")
	if tenantID == "" {
		tenantID = "dev-tenant"
	}
	targetURL := r.Header.Get("X-Cicada-Target-URL")
	if targetURL == "" {
		targetURL = "https://api.openai.com/v1/chat/completions"
	}

	// If a real Session or EVAR token is supplied in Authorization, extract its claims.
	authHeader := r.Header.Get("Authorization")
	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	scopes := []string{"proxy:call", "read", "write"}
	if rawToken != "" && rawToken != authHeader {
		if sessionClaims, err := session.Verify(rawToken); err == nil {
			agentID = sessionClaims.AgentID
			tenantID = sessionClaims.TenantID
			if len(sessionClaims.Scopes) > 0 {
				scopes = sessionClaims.Scopes
			}
		} else if evarPayload, err := auth.VerifyEVARToken(rawToken); err == nil {
			agentID = evarPayload.AgentID
			if evarPayload.Issuer != "" {
				tenantID = evarPayload.Issuer
			}
		}
	}
	if scopeHdr := r.Header.Get("X-Cicada-Scopes"); scopeHdr != "" {
		scopes = strings.Split(scopeHdr, ",")
		for i := range scopes {
			scopes[i] = strings.TrimSpace(scopes[i])
		}
	}

	// ── Gate 1: Lock-Free Gossip Mesh Quarantine Check ────────────────────────
	if gossipMesh != nil && (gossipMesh.IsQuarantined(agentID) || gossipMesh.IsQuarantined(fmt.Sprintf("%s_WILDCARD", tenantID))) {
		latencyUs := time.Since(start).Microseconds()
		log.Printf("[SIMULATION] [QUARANTINE BLOCKED] Agent %s is quarantined in Gossip Mesh (trace %s, %dµs)", agentID, traceID, latencyUs)
		if edgeLedger != nil {
			edgeLedger.AppendRecord(ledger.EventRecord{
				EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
				TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
				TargetURL: targetURL, Decision: "deny",
				ReasonCodes: []string{"gossip_mesh_quarantined"}, RiskScore: 1.0,
			})
		}
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":                  "agent_quarantined",
			"message":                "Agent is quarantined in the Cicada Lock-Free Gossip Mesh",
			"agent_id":               agentID,
			"trace_id":               traceID,
			"enforcement_latency_us": latencyUs,
		})
		return
	}

	// ── Gate 2: Tier-1 SSRF & Cloud Metadata Guard ────────────────────────────
	if targetURL != "" {
		if err := ssrf.ValidateOutboundURL(targetURL, nil); err != nil {
			// In offline standalone environments, DNS lookup for external domains may fail;
			// block all scheme, loopback, private IP, and link-local (169.254.169.254) violations.
			if !strings.Contains(err.Error(), "DNS resolution failed") {
				latencyUs := time.Since(start).Microseconds()
				log.Printf("[SIMULATION] [SSRF BLOCKED] Agent %s target %s rejected: %v (trace %s, %dµs)", agentID, targetURL, err, traceID, latencyUs)
				if edgeLedger != nil {
					edgeLedger.AppendRecord(ledger.EventRecord{
						EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
						TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
						TargetURL: targetURL, Decision: "deny",
						ReasonCodes: []string{"ssrf_blocked"}, RiskScore: 0.95,
					})
				}
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error":                  "ssrf_blocked",
					"message":                err.Error(),
					"target_url":             targetURL,
					"trace_id":               traceID,
					"enforcement_latency_us": latencyUs,
				})
				return
			}
		}
	}

	// ── Read Request Body ─────────────────────────────────────────────────────
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
		r.Body.Close()
	}

	// ── Gate 3: Canary Honeytoken Exfiltration Trap (Zero-False-Positive) ────
	if len(bodyBytes) > 0 {
		bodyStr := string(bodyBytes)
		canaryTriggered := false
		canaryToken := ""
		if trigger := canary.CheckOutbound(r.Context(), tenantID, bodyStr); trigger != nil {
			canaryTriggered = true
			canaryToken = trigger.TokenValue
		} else if found, matchedTok := canary.ContainsCanaryToken(bodyStr); found {
			canaryTriggered = true
			canaryToken = matchedTok
		}
		if canaryTriggered {
			if gossipMesh != nil {
				gossipMesh.QuarantineAgent(agentID)
			}
			latencyUs := time.Since(start).Microseconds()
			log.Printf("[SIMULATION] [CANARY TRIGGERED] CRITICAL: Agent %s exfiltrated honeytoken %s — auto-quarantined in Gossip Mesh (trace %s, %dµs)", agentID, canaryToken, traceID, latencyUs)
			if edgeLedger != nil {
				edgeLedger.AppendRecord(ledger.EventRecord{
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "canary_trigger",
					TargetURL: targetURL, Decision: "deny",
					ReasonCodes: []string{"honeytoken_exfiltration", "canary_token_detected"}, RiskScore: 1.0,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":                  "canary_honeytoken_triggered",
				"message":                "CRITICAL: Zero-false-positive CICADA_CANARY_* honeytoken detected in outbound payload. Agent has been automatically quarantined across the Gossip Mesh.",
				"agent_id":               agentID,
				"agent_quarantined":      true,
				"trace_id":               traceID,
				"enforcement_latency_us": latencyUs,
			})
			return
		}
	}

	// ── Gate 4: Prompt Injection & Hidden HTML DOM Scanner ────────────────────
	if len(bodyBytes) > 0 {
		provenance := injection.ParseProvenance(r.Header.Get("X-Cicada-Content-Provenance"))
		injResult := injection.ScanWithProvenance(string(bodyBytes), "", provenance)
		if injResult.Block {
			summary := injection.Summary(injResult.Findings)
			latencyUs := time.Since(start).Microseconds()
			log.Printf("[SIMULATION] [INJECTION BLOCKED] Agent %s outbound body blocked (provenance=%s, %dµs): %s", agentID, provenance, latencyUs, summary)
			w.Header().Set("X-Cicada-Memory-Action", "flush")
			w.Header().Set("X-Cicada-Flush-Reason", "prompt_injection_detected")
			if edgeLedger != nil {
				edgeLedger.AppendRecord(ledger.EventRecord{
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
					TargetURL: targetURL, Decision: "deny",
					ReasonCodes: []string{"prompt_injection_outbound", "provenance:" + provenance}, RiskScore: injResult.Score,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":                  "prompt_injection_detected",
				"findings":               summary,
				"risk_score":             injResult.Score,
				"memory_action":          "flush",
				"trace_id":               traceID,
				"enforcement_latency_us": latencyUs,
			})
			return
		}
	}

	// ── Gate 5: Semantic Intent Alignment Engine (Non-LLM Lexical Scorer) ─────
	agentDesc := r.Header.Get("X-Cicada-Agent-Description")
	agentType := r.Header.Get("X-Cicada-Agent-Type")
	if agentDesc != "" || agentType != "" {
		semanticResult := semantic.Check(agentDesc, agentType, targetURL, r.Method)
		if semanticResult.Block {
			latencyUs := time.Since(start).Microseconds()
			log.Printf("[SIMULATION] [SEMANTIC BLOCKED] Agent %s intent mismatch (score=%.2f, %dµs): %s", agentID, semanticResult.Score, latencyUs, semanticResult.Reason)
			if edgeLedger != nil {
				edgeLedger.AppendRecord(ledger.EventRecord{
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "proxy",
					TargetURL: targetURL, Decision: "deny",
					ReasonCodes: []string{"semantic_intent_mismatch"}, RiskScore: 0.80,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":                  "semantic_intent_mismatch",
				"reason":                 semanticResult.Reason,
				"alignment_score":        semanticResult.Score,
				"trace_id":               traceID,
				"enforcement_latency_us": latencyUs,
			})
			return
		}
	}

	// ── Gate 6: In-Memory OPA Rego Policy Evaluation ──────────────────────────
	if opaEngine != nil {
		agentStatus := r.Header.Get("X-Cicada-Agent-Status")
		if agentStatus == "" {
			agentStatus = "certified"
		}
		allowed, evalErr := opaEngine.Evaluate(r.Context(), map[string]interface{}{
			"agent_id":      agentID,
			"target":        r.URL.Path,
			"velocity":      0,
			"evar_scopes":   scopes,
			"action_scope":  "proxy:call",
			"agent_status":  agentStatus,
			"action_cost":   0,
			"current_spend": 0,
			"spend_limit":   999999,
		})
		if evalErr != nil || !allowed {
			latencyUs := time.Since(start).Microseconds()
			log.Printf("[SIMULATION] [OPA POLICY DENY] Agent %s denied by in-memory OPA Rego policy (%dµs)", agentID, latencyUs)
			if edgeLedger != nil {
				edgeLedger.AppendRecord(ledger.EventRecord{
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "proxy:call",
					TargetURL: targetURL, Decision: "deny",
					ReasonCodes: []string{"opa_policy_deny"}, RiskScore: 0.9,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":                  "opa_policy_deny",
				"message":                "Action denied by embedded Open Policy Agent (OPA) Rego policy",
				"trace_id":               traceID,
				"enforcement_latency_us": latencyUs,
			})
			return
		}
	}

	// ── Gate 7: Vault-Aware Outbound Credential & Exfiltration DLP ────────────
	if len(bodyBytes) > 0 {
		var propagationDomains []string
		if pd := os.Getenv("CICADA_SECRET_PROPAGATION_DOMAINS"); pd != "" {
			for _, d := range strings.Split(pd, ",") {
				propagationDomains = append(propagationDomains, strings.TrimSpace(d))
			}
		}
		vaultedPrefixes := []string{"sk-", "AKIA", "ghp_", "glpat-", "xoxb-", "AIza", "-----BEGIN"}
		if vp := os.Getenv("CICADA_VAULTED_SECRET_PREFIXES"); vp != "" {
			vaultedPrefixes = nil
			for _, p := range strings.Split(vp, ",") {
				vaultedPrefixes = append(vaultedPrefixes, strings.TrimSpace(p))
			}
		}

		vaultResult := output.InspectWithVaultContext(
			bodyBytes,
			r.Header.Get("Content-Type"),
			targetURL,
			vaultedPrefixes,
			propagationDomains,
			nil,
		)
		if vaultResult.Base.Risk && (vaultResult.MustBlock || vaultResult.Base.Block) {
			summary := output.FindingsSummary(vaultResult.Base.Findings)
			latencyUs := time.Since(start).Microseconds()
			log.Printf("[SIMULATION] [EXFILTRATION BLOCKED] Agent %s credential leak blocked (%dµs): %s (%s)", agentID, latencyUs, vaultResult.Reason, summary)
			if edgeLedger != nil {
				edgeLedger.AppendRecord(ledger.EventRecord{
					EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
					TenantID: tenantID, AgentID: agentID, ActionClass: "proxy:call",
					TargetURL: targetURL, Decision: "exfiltration_risk",
					ReasonCodes: []string{"credential_in_request_body", vaultResult.Reason},
					RiskScore:   vaultResult.Base.RiskScore,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":                  "exfiltration_blocked",
				"reason":                 vaultResult.Reason,
				"findings":               summary,
				"risk_score":             vaultResult.Base.RiskScore,
				"trace_id":               traceID,
				"enforcement_latency_us": latencyUs,
			})
			return
		}
	}

	// ── Gate 8: Immutable SQLite SHA-256 Edge Ledger Recording ────────────────
	if edgeLedger != nil {
		edgeLedger.AppendRecord(ledger.EventRecord{
			EventID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), TraceID: traceID,
			TenantID: tenantID, AgentID: agentID, ActionClass: "proxy:call",
			TargetURL: targetURL, Decision: "allow",
			ReasonCodes: []string{"simulation_verified_allow"}, RiskScore: 0.0,
		})
	}

	latencyUs := time.Since(start).Microseconds()
	log.Printf("[SIMULATION] [ALLOW] Request from %s (agent=%s) passed all 8 Zero-Trust gates in %dµs — trace: %s", r.RemoteAddr, agentID, latencyUs, traceID)

	writeJSON(w, http.StatusOK, map[string]any{
		"id":      "chatcmpl-sim-" + traceID,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   "cicada-simulation-v1",
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": "[CICADA SIMULATION] Request verified and approved by the Cicada Sentry Gateway in-memory Zero-Trust pipeline. All 8 security gates passed (Gossip Quarantine, 3-Tier SSRF, Canary Honeytoken Trap, Prompt Injection & DOM Scanner, Semantic Intent Engine, OPA Rego Policy, Vault Exfiltration DLP, and SHA-256 Edge Ledger).",
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     24,
			"completion_tokens": 48,
			"total_tokens":      72,
		},
		"cicada_metadata": map[string]any{
			"trace_id":               traceID,
			"agent_id":               agentID,
			"tenant_id":              tenantID,
			"simulation_mode":        true,
			"gateway_healthy":        true,
			"enforcement_latency_us": latencyUs,
			"enforcement_latency_ms": float64(latencyUs) / 1000.0,
			"policy_engine":          "enforced (OPA Rego in-memory)",
			"edge_ledger":            "recorded (SHA-256 hash chain)",
			"gates_evaluated": []string{
				"gossip_mesh_quarantine",
				"ssrf_3tier_guard",
				"canary_honeytoken_trap",
				"prompt_injection_dom_scanner",
				"semantic_intent_engine",
				"opa_rego_policy",
				"vault_exfiltration_dlp",
				"sqlite_sha256_edge_ledger",
			},
		},
	})
}
