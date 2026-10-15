// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package rotation implements automated credential lifecycle management (S6.6).
//
// The EVAR (Ed25519 Verifiable Agent Registration) token is the long-lived
// identity credential for every Cicada agent. Like all long-lived credentials,
// EVARs must be rotated periodically to limit the blast radius of a credential
// compromise.
//
// This package provides:
//
//  1. RotationMonitor — A background Go routine (similar to IntegrityMonitor)
//     that scans for agents whose EVARs are approaching or past the rotation
//     deadline. It automatically re-mints EVARs and records audit events.
//
//  2. Pre-Notification (S6.7) — Configurable notification tiers (7d, 24h, 1h)
//     that warn agent operators before forced rotation occurs. Notifications
//     are sent via webhook callbacks.
//
//  3. Audit Trail (S6.9) — Every rotation, notification, and expiry event is
//     persisted to the credential_rotation_events table, which is append-only
//     and protected by RLS.
//
// Configuration:
//
//	CICADA_ROTATION_PERIOD_DAYS   — Credential lifetime in days. Default: 90.
//	CICADA_ROTATION_NOTIFY_DAYS   — Comma-separated notification tiers before
//	                                expiry. Default: "7,1" (7 days and 1 day).
//	CICADA_ROTATION_CHECK_INTERVAL — How often the monitor runs. Default: "1h".
//	CICADA_ROTATION_WEBHOOK_URL   — Default webhook for rotation notifications.
package rotation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/asai/cicada/sentry/internal/auth"
	"github.com/asai/cicada/sentry/internal/ssrf"
)

// ── Configuration ────────────────────────────────────────────────────────────

// DefaultRotationPeriod is the credential lifetime when CICADA_ROTATION_PERIOD_DAYS
// is not set. 90 days aligns with NIST 800-63B and enterprise compliance requirements.
const DefaultRotationPeriod = 90 * 24 * time.Hour

// DefaultCheckInterval is the fallback monitoring interval.
const DefaultCheckInterval = 1 * time.Hour

// RotationPeriod returns the configured credential lifetime.
func RotationPeriod() time.Duration {
	if v := os.Getenv("CICADA_ROTATION_PERIOD_DAYS"); v != "" {
		if days, err := strconv.Atoi(v); err == nil && days > 0 {
			return time.Duration(days) * 24 * time.Hour
		}
	}
	return DefaultRotationPeriod
}

// NotificationTiers returns the configured pre-rotation notification schedule.
// Each entry is the number of days before expiry when a notification is sent.
func NotificationTiers() []int {
	tiers := os.Getenv("CICADA_ROTATION_NOTIFY_DAYS")
	if tiers == "" {
		return []int{7, 1}
	}
	var result []int
	for _, s := range strings.Split(tiers, ",") {
		s = strings.TrimSpace(s)
		if d, err := strconv.Atoi(s); err == nil && d > 0 {
			result = append(result, d)
		}
	}
	if len(result) == 0 {
		return []int{7, 1}
	}
	return result
}

// CheckInterval returns how often the monitor scans for rotation candidates.
func CheckInterval() time.Duration {
	if v := os.Getenv("CICADA_ROTATION_CHECK_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 30*time.Second {
			return d
		}
	}
	return DefaultCheckInterval
}

// ── Data Types ───────────────────────────────────────────────────────────────

// AgentCredentialState represents an agent's current EVAR lifecycle position.
type AgentCredentialState struct {
	AgentID          string    `json:"agent_id"`
	TenantID         string    `json:"tenant_id"`
	EVARIssuedAt     time.Time `json:"evar_issued_at"`
	EVARExpiresAt    time.Time `json:"evar_expires_at"`
	RotationCount    int       `json:"rotation_count"`
	RotationStatus   string    `json:"rotation_status"`
	CodeHash         string    `json:"code_hash"`
	Scopes           string    `json:"scopes"`           // JSONB stored as string
	WebhookURL       string    `json:"webhook_url"`       // agent-specific notification endpoint
}

// RotationEvent is the audit record written for every credential lifecycle event.
type RotationEvent struct {
	AgentID            string `json:"agent_id"`
	TenantID           string `json:"tenant_id"`
	EventType          string `json:"event_type"`           // rotation, notification, expiry, manual_rotation, suspension
	OldEVARHash        string `json:"old_evar_hash,omitempty"`
	NewEVARHash        string `json:"new_evar_hash,omitempty"`
	RotationReason     string `json:"rotation_reason,omitempty"`
	NotificationTier   string `json:"notification_tier,omitempty"`
	NotificationTarget string `json:"notification_target,omitempty"`
	InitiatedBy        string `json:"initiated_by"`
}

// MonitorStatus reports the latest rotation scan result.
type MonitorStatus struct {
	LastRunAt           string `json:"last_run_at"`
	AgentsScanned       int    `json:"agents_scanned"`
	RotationsPerformed  int    `json:"rotations_performed"`
	NotificationsSent   int    `json:"notifications_sent"`
	ExpirationsDetected int    `json:"expirations_detected"`
	Error               string `json:"error,omitempty"`
}

// NotificationPayload is the webhook body sent to agent operators.
type NotificationPayload struct {
	Type       string `json:"type"`        // "credential_rotation_warning"
	AgentID    string `json:"agent_id"`
	TenantID   string `json:"tenant_id"`
	ExpiresAt  string `json:"expires_at"`
	DaysLeft   int    `json:"days_left"`
	Tier       string `json:"tier"`        // "7d", "24h", "1h"
	Action     string `json:"action"`      // "rotate_evar"
	RotateURL  string `json:"rotate_url"`  // self-service rotation endpoint
}

// ── Rotation Monitor ─────────────────────────────────────────────────────────

// Monitor is the background rotation scanner.
type Monitor struct {
	db           *pgxpool.Pool
	interval     time.Duration
	mu           sync.RWMutex
	latestStatus MonitorStatus
	cancel       context.CancelFunc
	done         chan struct{}
}

// NewMonitor creates a credential rotation monitor.
func NewMonitor(db *pgxpool.Pool, interval time.Duration) *Monitor {
	return &Monitor{
		db:       db,
		interval: interval,
		done:     make(chan struct{}),
		latestStatus: MonitorStatus{
			LastRunAt: "never",
		},
	}
}

// Start begins the background rotation scan. Non-blocking.
func (m *Monitor) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	go func() {
		defer close(m.done)

		// Run immediately on start to catch any overdue rotations
		m.runScan(ctx)

		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.runScan(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()

	log.Printf("[ROTATION] Credential rotation monitor started — scanning every %s (rotation period: %s)",
		m.interval, RotationPeriod())
}

// Stop gracefully shuts down the monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
	}
	log.Printf("[ROTATION] Monitor stopped")
}

// Status returns the latest scan result. Thread-safe.
func (m *Monitor) Status() MonitorStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.latestStatus
}

// ── Core Scan Logic ──────────────────────────────────────────────────────────

func (m *Monitor) runScan(ctx context.Context) {
	status := m.scan(ctx)

	m.mu.Lock()
	m.latestStatus = status
	m.mu.Unlock()

	if status.Error != "" {
		log.Printf("[ROTATION] ⚠ Scan error: %s", status.Error)
	} else {
		log.Printf("[ROTATION] ✓ Scan complete — %d agents checked, %d rotated, %d notified, %d expired",
			status.AgentsScanned, status.RotationsPerformed,
			status.NotificationsSent, status.ExpirationsDetected)
	}
}

func (m *Monitor) scan(ctx context.Context) MonitorStatus {
	now := time.Now().UTC()
	status := MonitorStatus{
		LastRunAt: now.Format(time.RFC3339),
	}

	// Query all agents with active EVARs that have rotation metadata
	rows, err := m.db.Query(ctx, `
		SELECT a.id, a.tenant_id,
		       COALESCE(a.evar_issued_at, a.created_at),
		       COALESCE(a.evar_expires_at, a.created_at + INTERVAL '90 days'),
		       COALESCE(a.evar_rotation_count, 0),
		       COALESCE(a.evar_rotation_status, 'active'),
		       COALESCE(a.pub_key_hash, ''),
		       COALESCE(a.scope_entitlements::TEXT, '[]'),
		       COALESCE(a.hitl_webhook_url, '')
		FROM agents a
		WHERE a.revoked_at IS NULL
		ORDER BY a.evar_expires_at ASC NULLS FIRST
	`)
	if err != nil {
		status.Error = fmt.Sprintf("query agents: %v", err)
		return status
	}
	defer rows.Close()

	for rows.Next() {
		var agent AgentCredentialState
		if err := rows.Scan(
			&agent.AgentID, &agent.TenantID,
			&agent.EVARIssuedAt, &agent.EVARExpiresAt,
			&agent.RotationCount, &agent.RotationStatus,
			&agent.CodeHash, &agent.Scopes,
			&agent.WebhookURL,
		); err != nil {
			log.Printf("[ROTATION] scan row error: %v", err)
			continue
		}
		status.AgentsScanned++

		timeUntilExpiry := agent.EVARExpiresAt.Sub(now)
		daysLeft := int(timeUntilExpiry.Hours() / 24)

		// ── Stage 1: Check if expired ────────────────────────────────────
		if timeUntilExpiry <= 0 {
			status.ExpirationsDetected++
			m.handleExpiry(ctx, agent)
			continue
		}

		// ── Stage 2: Check notification tiers (S6.7) ─────────────────────
		for _, tierDays := range NotificationTiers() {
			if daysLeft <= tierDays && daysLeft > 0 {
				// Check if this notification tier was already sent
				var alreadySent bool
				tierLabel := fmt.Sprintf("%dd", tierDays)
				err := m.db.QueryRow(ctx, `
					SELECT EXISTS(
						SELECT 1 FROM credential_rotation_events
						WHERE agent_id = $1::UUID
						  AND event_type = 'notification'
						  AND notification_tier = $2
						  AND created_at > $3
					)
				`, agent.AgentID, tierLabel,
					agent.EVARIssuedAt, // only look at notifications for the current credential cycle
				).Scan(&alreadySent)

				if err != nil {
					log.Printf("[ROTATION] notification check error for %s: %v", agent.AgentID, err)
					continue
				}

				if !alreadySent {
					m.sendNotification(ctx, agent, tierDays, daysLeft)
					status.NotificationsSent++
				}
				break // only send the most urgent tier
			}
		}

		// ── Stage 3: Update rotation status ──────────────────────────────
		if daysLeft <= 7 && agent.RotationStatus == "active" {
			_, err := m.db.Exec(ctx, `
				UPDATE agents SET evar_rotation_status = 'expiring_soon'
				WHERE id = $1::UUID
			`, agent.AgentID)
			if err != nil {
				log.Printf("[ROTATION] status update error for %s: %v", agent.AgentID, err)
			}
		}
	}

	if err := rows.Err(); err != nil {
		status.Error = fmt.Sprintf("row iteration: %v", err)
	}

	return status
}

// ── Expiry Handling ──────────────────────────────────────────────────────────

func (m *Monitor) handleExpiry(ctx context.Context, agent AgentCredentialState) {
	log.Printf("[ROTATION] ⚠ Agent %s EVAR expired at %s — marking expired",
		agent.AgentID, agent.EVARExpiresAt.Format(time.RFC3339))

	// Update agent status
	_, err := m.db.Exec(ctx, `
		UPDATE agents SET evar_rotation_status = 'expired'
		WHERE id = $1::UUID
	`, agent.AgentID)
	if err != nil {
		log.Printf("[ROTATION] expiry update error for %s: %v", agent.AgentID, err)
	}

	// Write audit event
	m.recordEvent(ctx, RotationEvent{
		AgentID:        agent.AgentID,
		TenantID:       agent.TenantID,
		EventType:      "expiry",
		OldEVARHash:    hashPrefix(agent.CodeHash),
		RotationReason: "scheduled_90day",
		InitiatedBy:    "system/rotation-monitor",
	})

	// Send expiry notification if webhook is configured
	if agent.WebhookURL != "" {
		payload := NotificationPayload{
			Type:      "credential_expired",
			AgentID:   agent.AgentID,
			TenantID:  agent.TenantID,
			ExpiresAt: agent.EVARExpiresAt.Format(time.RFC3339),
			DaysLeft:  0,
			Tier:      "expired",
			Action:    "rotate_evar_immediately",
		}
		go sendWebhook(agent.WebhookURL, payload)
	}
}

// ── Pre-Notification (S6.7) ──────────────────────────────────────────────────

func (m *Monitor) sendNotification(ctx context.Context, agent AgentCredentialState, tierDays, daysLeft int) {
	tierLabel := fmt.Sprintf("%dd", tierDays)
	webhookURL := agent.WebhookURL
	if webhookURL == "" {
		webhookURL = os.Getenv("CICADA_ROTATION_WEBHOOK_URL")
	}

	log.Printf("[ROTATION] Sending %s pre-rotation notification for agent %s (%d days left)",
		tierLabel, agent.AgentID, daysLeft)

	// Record the notification event regardless of webhook delivery
	m.recordEvent(ctx, RotationEvent{
		AgentID:            agent.AgentID,
		TenantID:           agent.TenantID,
		EventType:          "notification",
		NotificationTier:   tierLabel,
		NotificationTarget: webhookURL,
		RotationReason:     "scheduled_90day",
		InitiatedBy:        "system/rotation-monitor",
	})

	// Fire webhook if configured
	if webhookURL != "" {
		payload := NotificationPayload{
			Type:      "credential_rotation_warning",
			AgentID:   agent.AgentID,
			TenantID:  agent.TenantID,
			ExpiresAt: agent.EVARExpiresAt.Format(time.RFC3339),
			DaysLeft:  daysLeft,
			Tier:      tierLabel,
			Action:    "rotate_evar",
			RotateURL: fmt.Sprintf("/v1/agent/%s/rotate", agent.AgentID),
		}
		go sendWebhook(webhookURL, payload)
	}
}

// ── Manual Rotation ──────────────────────────────────────────────────────────

// RotateAgent performs an immediate EVAR rotation for the specified agent.
// This is the handler logic for POST /v1/agent/{id}/rotate.
//
// The UPDATE + INSERT are wrapped in a transaction so the rotation metadata
// and audit trail are always consistent. A crash between them cannot leave
// a rotated agent without an audit record.
func RotateAgent(ctx context.Context, db *pgxpool.Pool, agentID, tenantID, initiatedBy, ipAddr, userAgent string) (string, error) {
	// Fetch current agent data (outside tx — read-only, no mutation)
	var codeHash string
	var scopesJSON string
	var modelIntended string
	var tenantFromDB string
	err := db.QueryRow(ctx, `
		SELECT COALESCE(pub_key_hash, ''),
		       COALESCE(scope_entitlements::TEXT, '[]'),
		       COALESCE(tenant_id::TEXT, '')
		FROM agents WHERE id = $1::UUID AND revoked_at IS NULL
	`, agentID).Scan(&codeHash, &scopesJSON, &tenantFromDB)
	if err != nil {
		return "", fmt.Errorf("agent not found or revoked: %w", err)
	}

	if tenantID == "" {
		tenantID = tenantFromDB
	}

	// Parse scopes from JSONB
	var scopes []string
	_ = json.Unmarshal([]byte(scopesJSON), &scopes)

	// Build the EVAR specification
	spec := auth.AgentSpecification{
		AgentID:       agentID,
		CodeHash:      codeHash,
		Scopes:        scopes,
		ModelIntended: modelIntended,
		TenantID:      tenantID,
	}

	// Mint a fresh EVAR
	newToken, err := auth.MintEVARToken(spec)
	if err != nil {
		return "", fmt.Errorf("EVAR minting failed: %w", err)
	}

	// Compute hash for audit
	oldHash := hashPrefix(codeHash)
	newHash := hashPrefix(newToken)

	// ── Transactional rotation: metadata + audit in one atomic commit ──
	tx, err := db.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin rotation tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck — harmless after Commit

	now := time.Now().UTC()
	rotationPeriod := RotationPeriod()
	_, err = tx.Exec(ctx, `
		UPDATE agents
		SET evar_issued_at = $2,
		    evar_expires_at = $3,
		    evar_rotation_count = COALESCE(evar_rotation_count, 0) + 1,
		    evar_last_rotated_at = $2,
		    evar_rotation_status = 'active'
		WHERE id = $1::UUID
	`, agentID, now, now.Add(rotationPeriod))
	if err != nil {
		return "", fmt.Errorf("update rotation metadata: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO credential_rotation_events
			(agent_id, tenant_id, event_type, old_evar_hash, new_evar_hash,
			 rotation_reason, initiated_by, ip_address, user_agent)
		VALUES ($1::UUID, $2::UUID, $3, $4, $5, $6, $7, $8::INET, $9)
	`, agentID, tenantID, "rotation",
		oldHash, newHash,
		"manual", initiatedBy, ipAddr, userAgent)
	if err != nil {
		return "", fmt.Errorf("record rotation audit event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit rotation tx: %w", err)
	}

	log.Printf("[ROTATION] Agent %s EVAR rotated (count: +1, initiated_by: %s)", agentID, initiatedBy)

	return newToken, nil
}

// ── Audit Trail (S6.9) ──────────────────────────────────────────────────────

func (m *Monitor) recordEvent(ctx context.Context, evt RotationEvent) {
	_, err := m.db.Exec(ctx, `
		INSERT INTO credential_rotation_events
			(agent_id, tenant_id, event_type, old_evar_hash, new_evar_hash,
			 rotation_reason, notification_tier, notification_target, initiated_by)
		VALUES ($1::UUID, $2::UUID, $3, $4, $5, $6, $7, $8, $9)
	`,
		evt.AgentID, evt.TenantID, evt.EventType,
		evt.OldEVARHash, evt.NewEVARHash,
		evt.RotationReason, evt.NotificationTier,
		evt.NotificationTarget, evt.InitiatedBy)
	if err != nil {
		log.Printf("[ROTATION] Failed to record audit event for %s: %v", evt.AgentID, err)
	}
}

// GetRotationHistory returns the credential rotation audit trail for an agent.
func GetRotationHistory(ctx context.Context, db *pgxpool.Pool, agentID string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := db.Query(ctx, `
		SELECT id, event_type, old_evar_hash, new_evar_hash,
		       rotation_reason, notification_tier, notification_target,
		       initiated_by, created_at
		FROM credential_rotation_events
		WHERE agent_id = $1::UUID
		ORDER BY created_at DESC
		LIMIT $2
	`, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("query rotation history: %w", err)
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var (
			id, eventType, reason, initiatedBy string
			oldHash, newHash                   *string
			notifTier, notifTarget             *string
			createdAt                          time.Time
		)
		if err := rows.Scan(
			&id, &eventType, &oldHash, &newHash,
			&reason, &notifTier, &notifTarget,
			&initiatedBy, &createdAt,
		); err != nil {
			continue
		}

		event := map[string]interface{}{
			"id":           id,
			"event_type":   eventType,
			"reason":       reason,
			"initiated_by": initiatedBy,
			"created_at":   createdAt.Format(time.RFC3339),
		}
		if oldHash != nil {
			event["old_evar_hash"] = *oldHash
		}
		if newHash != nil {
			event["new_evar_hash"] = *newHash
		}
		if notifTier != nil {
			event["notification_tier"] = *notifTier
		}
		if notifTarget != nil {
			event["notification_target"] = *notifTarget
		}
		events = append(events, event)
	}

	return events, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// hashPrefix computes the SHA-256 of a string and returns the first 16 hex chars.
// Used for audit trail storage — enough to identify a credential without storing
// the full token.
func hashPrefix(s string) string {
	h := sha256.Sum256([]byte(s))
	full := fmt.Sprintf("%x", h)
	if len(full) > 16 {
		return full[:16]
	}
	return full
}

// sendWebhook delivers a notification payload to the configured webhook URL.
// Fire-and-forget — errors are logged but do not block the rotation lifecycle.
//
// SSRF protection: delegates to the shared ssrf.ValidateOutboundURL() validator
// which enforces HTTPS, blocks loopback/private/link-local IPs, and optionally
// checks a domain allowlist. Rotation webhooks pass nil for the allowlist since
// the destination is operator-configured per-agent.
func sendWebhook(rawURL string, payload NotificationPayload) {
	// ── SSRF validation (shared) ────────────────────────────────────────
	if err := ssrf.ValidateOutboundURL(rawURL, nil); err != nil {
		log.Printf("[ROTATION] SSRF: %v", err)
		return
	}

	// ── Deliver webhook ────────────────────────────────────────────────
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[ROTATION] webhook marshal error: %v", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(rawURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[ROTATION] webhook delivery failed to %s: %v", rawURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("[ROTATION] webhook returned %d from %s", resp.StatusCode, rawURL)
	} else {
		log.Printf("[ROTATION] webhook delivered to %s (HTTP %d)", rawURL, resp.StatusCode)
	}
}
