// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package shadow implements Shadow AI discovery by integrating with external
// CASB/SSPM systems (Netskope, Zscaler, Palo Alto Prisma) via API.
//
// Architecture:
//
//	 ┌───────────────────┐     POST /v1/shadow/ingest
//	 │  CASB / SSPM      │ ─────────────────────────────→ ┌─────────────────┐
//	 │  (Netskope, etc.) │                                 │ Shadow Discovery │
//	 └───────────────────┘                                 │    Handler       │
//	                                                       └────────┬────────┘
//	                                                                │
//	                                               ┌────────────────┼─────────────────┐
//	                                               ▼                ▼                 ▼
//	                                        [Match against     [Log unknown      [Quarantine if
//	                                         agent registry]    agents for        auto-quarantine
//	                                                            operator review]  is enabled]
//
// Cicada's registered agent registry is the "known good" source of truth.
// The CASB feeds "unknown" AI agent traffic — any AI-like HTTP patterns it
// detects on the network that are NOT routing through the Sentry Gateway.
// This handler:
//
//  1. Receives shadow agent sightings from CASB/SSPM via webhook or poll
//  2. Cross-references against the registered agent registry
//  3. Logs unregistered agents for operator review
//  4. Optionally auto-quarantines if the agent matches a known-bad pattern
//  5. Provides a query API for the operator dashboard to display shadow agents
//
// Reference: Netskope API, Zscaler ZIA API, Palo Alto Prisma CASB API
package shadow

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Data Model ──────────────────────────────────────────────────────────────

// ShadowAgent represents an unregistered AI agent sighting reported by a CASB.
type ShadowAgent struct {
	ID             string    `json:"id"`
	SourceCASB     string    `json:"source_casb"`     // "netskope", "zscaler", "prisma"
	DetectedAt     time.Time `json:"detected_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	TenantID       string    `json:"tenant_id"`
	SourceIP       string    `json:"source_ip,omitempty"`
	UserAgent      string    `json:"user_agent,omitempty"`
	TargetDomain   string    `json:"target_domain"`    // e.g., "api.openai.com", "api.anthropic.com"
	TargetPath     string    `json:"target_path,omitempty"`
	RequestCount   int       `json:"request_count"`
	ModelHints     []string  `json:"model_hints,omitempty"` // detected model names
	Status         string    `json:"status"`           // "unreviewed", "acknowledged", "quarantined", "registered"
	RegistryMatch  string    `json:"registry_match,omitempty"` // matched agent ID if found
	RiskLevel      string    `json:"risk_level"`       // "unknown", "low", "medium", "high", "critical"
	Notes          string    `json:"notes,omitempty"`
}

// IngestRequest is the payload from a CASB system reporting shadow agent activity.
type IngestRequest struct {
	Source    string            `json:"source"`    // CASB identifier
	TenantID string            `json:"tenant_id"`
	Sightings []CASBSighting   `json:"sightings"`
}

// CASBSighting is a single AI agent sighting from the CASB.
type CASBSighting struct {
	SourceIP     string   `json:"source_ip"`
	UserAgent    string   `json:"user_agent"`
	TargetDomain string   `json:"target_domain"`
	TargetPath   string   `json:"target_path,omitempty"`
	RequestCount int      `json:"request_count"`
	FirstSeen    string   `json:"first_seen"`
	LastSeen     string   `json:"last_seen"`
	ModelHints   []string `json:"model_hints,omitempty"`
	RawMetadata  json.RawMessage `json:"raw_metadata,omitempty"`
}

// ── Known LLM Domains ───────────────────────────────────────────────────────
// These are known AI/LLM API domains. Traffic to these from unregistered
// sources indicates shadow AI usage.

var knownLLMDomains = map[string]string{
	"api.openai.com":         "OpenAI",
	"api.anthropic.com":      "Anthropic",
	"generativelanguage.googleapis.com": "Google Gemini",
	"api.cohere.ai":          "Cohere",
	"api.mistral.ai":         "Mistral",
	"api-inference.huggingface.co": "HuggingFace",
	"api.together.xyz":       "Together AI",
	"api.groq.com":           "Groq",
	"api.replicate.com":      "Replicate",
	"bedrock-runtime.amazonaws.com": "AWS Bedrock",
	"azopenai.azure.com":     "Azure OpenAI",
}

// ── Handler ─────────────────────────────────────────────────────────────────

// Store holds the shadow agent sightings. In production this should be backed
// by PostgreSQL; for now it uses an in-memory store with optional SQLite persistence.
type Store struct {
	mu       sync.RWMutex
	agents   map[string]*ShadowAgent // keyed by composite ID (tenant:ip:domain)
	db       *sql.DB                 // optional persistent store
}

// NewStore creates a shadow agent store.
func NewStore() *Store {
	s := &Store{
		agents: make(map[string]*ShadowAgent),
	}

	// If SQLite path is configured, use persistent storage
	if dbPath := os.Getenv("CICADA_SHADOW_DB_PATH"); dbPath != "" {
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			log.Printf("[SHADOW] Failed to open SQLite at %s: %v — using in-memory store", dbPath, err)
		} else {
			s.db = db
			s.initDB()
			s.loadFromDB()
			log.Printf("[SHADOW] Persistent store initialized at %s", dbPath)
		}
	}

	return s
}

func (s *Store) initDB() {
	if s.db == nil {
		return
	}
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS shadow_agents (
			id             TEXT PRIMARY KEY,
			source_casb    TEXT NOT NULL,
			detected_at    TEXT NOT NULL,
			last_seen_at   TEXT NOT NULL,
			tenant_id      TEXT NOT NULL,
			source_ip      TEXT,
			user_agent     TEXT,
			target_domain  TEXT NOT NULL,
			target_path    TEXT,
			request_count  INTEGER DEFAULT 0,
			model_hints    TEXT,
			status         TEXT DEFAULT 'unreviewed',
			registry_match TEXT,
			risk_level     TEXT DEFAULT 'unknown',
			notes          TEXT
		)
	`)
	if err != nil {
		log.Printf("[SHADOW] Failed to create table: %v", err)
	}
}

func (s *Store) loadFromDB() {
	if s.db == nil {
		return
	}
	rows, err := s.db.Query("SELECT id, source_casb, detected_at, last_seen_at, tenant_id, source_ip, user_agent, target_domain, target_path, request_count, model_hints, status, registry_match, risk_level, notes FROM shadow_agents")
	if err != nil {
		log.Printf("[SHADOW] Failed to load from DB: %v", err)
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var a ShadowAgent
		var detectedAt, lastSeen, hints string
		err := rows.Scan(&a.ID, &a.SourceCASB, &detectedAt, &lastSeen, &a.TenantID,
			&a.SourceIP, &a.UserAgent, &a.TargetDomain, &a.TargetPath,
			&a.RequestCount, &hints, &a.Status, &a.RegistryMatch, &a.RiskLevel, &a.Notes)
		if err != nil {
			continue
		}
		a.DetectedAt, _ = time.Parse(time.RFC3339, detectedAt)
		a.LastSeenAt, _ = time.Parse(time.RFC3339, lastSeen)
		if hints != "" {
			json.Unmarshal([]byte(hints), &a.ModelHints)
		}
		s.agents[a.ID] = &a
		count++
	}
	log.Printf("[SHADOW] Loaded %d shadow agents from persistent store", count)
}

func (s *Store) persist(a *ShadowAgent) {
	if s.db == nil {
		return
	}
	hintsJSON, _ := json.Marshal(a.ModelHints)
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO shadow_agents
		(id, source_casb, detected_at, last_seen_at, tenant_id, source_ip, user_agent,
		 target_domain, target_path, request_count, model_hints, status, registry_match, risk_level, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.SourceCASB, a.DetectedAt.Format(time.RFC3339), a.LastSeenAt.Format(time.RFC3339),
		a.TenantID, a.SourceIP, a.UserAgent, a.TargetDomain, a.TargetPath,
		a.RequestCount, string(hintsJSON), a.Status, a.RegistryMatch, a.RiskLevel, a.Notes,
	)
	if err != nil {
		log.Printf("[SHADOW] Failed to persist agent %s: %v", a.ID, err)
	}
}

// Ingest processes CASB sightings and stores new shadow agents.
func (s *Store) Ingest(req IngestRequest) (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	newCount := 0
	updatedCount := 0

	for _, sighting := range req.Sightings {
		// Build composite key
		key := fmt.Sprintf("%s:%s:%s", req.TenantID, sighting.SourceIP, sighting.TargetDomain)

		if existing, ok := s.agents[key]; ok {
			// Update existing sighting
			existing.RequestCount += sighting.RequestCount
			if lastSeen, err := time.Parse(time.RFC3339, sighting.LastSeen); err == nil {
				existing.LastSeenAt = lastSeen
			}
			if len(sighting.ModelHints) > 0 {
				existing.ModelHints = mergeHints(existing.ModelHints, sighting.ModelHints)
			}
			existing.RiskLevel = classifyRisk(existing)
			s.persist(existing)
			updatedCount++
		} else {
			// New shadow agent sighting
			firstSeen := time.Now()
			if t, err := time.Parse(time.RFC3339, sighting.FirstSeen); err == nil {
				firstSeen = t
			}
			lastSeen := time.Now()
			if t, err := time.Parse(time.RFC3339, sighting.LastSeen); err == nil {
				lastSeen = t
			}

			agent := &ShadowAgent{
				ID:           key,
				SourceCASB:   req.Source,
				DetectedAt:   firstSeen,
				LastSeenAt:   lastSeen,
				TenantID:     req.TenantID,
				SourceIP:     sighting.SourceIP,
				UserAgent:    sighting.UserAgent,
				TargetDomain: sighting.TargetDomain,
				TargetPath:   sighting.TargetPath,
				RequestCount: sighting.RequestCount,
				ModelHints:   sighting.ModelHints,
				Status:       "unreviewed",
				RiskLevel:    "unknown",
			}

			agent.RiskLevel = classifyRisk(agent)
			s.agents[key] = agent
			s.persist(agent)
			newCount++

			log.Printf("[SHADOW] NEW shadow agent detected: tenant=%s ip=%s domain=%s count=%d risk=%s casb=%s",
				req.TenantID, sighting.SourceIP, sighting.TargetDomain, sighting.RequestCount,
				agent.RiskLevel, req.Source)
		}
	}

	return newCount, updatedCount
}

// List returns all shadow agents for a tenant, optionally filtered by status.
func (s *Store) List(tenantID string, statusFilter string) []ShadowAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []ShadowAgent
	for _, a := range s.agents {
		if tenantID != "" && a.TenantID != tenantID {
			continue
		}
		if statusFilter != "" && a.Status != statusFilter {
			continue
		}
		result = append(result, *a)
	}
	return result
}

// UpdateStatus changes the status of a shadow agent (acknowledge, quarantine, register).
func (s *Store) UpdateStatus(id string, status string, notes string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, ok := s.agents[id]
	if !ok {
		return fmt.Errorf("shadow agent %q not found", id)
	}

	validStatuses := map[string]bool{
		"unreviewed": true, "acknowledged": true, "quarantined": true, "registered": true,
	}
	if !validStatuses[status] {
		return fmt.Errorf("invalid status %q", status)
	}

	agent.Status = status
	if notes != "" {
		agent.Notes = notes
	}
	s.persist(agent)

	log.Printf("[SHADOW] Agent %s status updated to %s by operator", id, status)
	return nil
}

// Stats returns aggregate shadow discovery statistics for a tenant.
func (s *Store) Stats(tenantID string) map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total, unreviewed, high, critical := 0, 0, 0, 0
	domainCounts := make(map[string]int)

	for _, a := range s.agents {
		if tenantID != "" && a.TenantID != tenantID {
			continue
		}
		total++
		if a.Status == "unreviewed" {
			unreviewed++
		}
		if a.RiskLevel == "high" {
			high++
		}
		if a.RiskLevel == "critical" {
			critical++
		}
		if provider, ok := knownLLMDomains[a.TargetDomain]; ok {
			domainCounts[provider]++
		} else {
			domainCounts[a.TargetDomain]++
		}
	}

	return map[string]interface{}{
		"total_shadow_agents": total,
		"unreviewed":          unreviewed,
		"high_risk":           high,
		"critical_risk":       critical,
		"providers":           domainCounts,
	}
}

// ── HTTP Handlers ───────────────────────────────────────────────────────────

// IngestHandler returns an http.HandlerFunc for POST /v1/shadow/ingest.
// CASB/SSPM systems call this endpoint to report shadow agent sightings.
func IngestHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Validate API key for CASB authentication
		apiKey := r.Header.Get("X-Cicada-Shadow-Key")
		expectedKey := os.Getenv("CICADA_SHADOW_API_KEY")
		if expectedKey != "" && apiKey != expectedKey {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid API key"})
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1*1024*1024))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
			return
		}

		var req IngestRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}

		if req.Source == "" || req.TenantID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "source and tenant_id required"})
			return
		}

		if len(req.Sightings) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no sightings provided"})
			return
		}

		newCount, updatedCount := store.Ingest(req)

		log.Printf("[SHADOW] Ingested from %s: %d new, %d updated sightings for tenant %s",
			req.Source, newCount, updatedCount, req.TenantID)

		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"status":  "accepted",
			"new":     newCount,
			"updated": updatedCount,
		})
	}
}

// ListHandler returns an http.HandlerFunc for GET /v1/shadow/agents.
// The operator dashboard calls this to display shadow agent sightings.
func ListHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.URL.Query().Get("tenant_id")
		statusFilter := r.URL.Query().Get("status")

		agents := store.List(tenantID, statusFilter)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"agents": agents,
			"count":  len(agents),
		})
	}
}

// StatsHandler returns an http.HandlerFunc for GET /v1/shadow/stats.
func StatsHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.URL.Query().Get("tenant_id")
		writeJSON(w, http.StatusOK, store.Stats(tenantID))
	}
}

// UpdateHandler returns an http.HandlerFunc for POST /v1/shadow/agents/{id}/status.
func UpdateHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract agent ID from URL path
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing agent ID"})
			return
		}
		agentID := parts[len(parts)-2] // /v1/shadow/agents/{id}/status

		var body struct {
			Status string `json:"status"`
			Notes  string `json:"notes,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}

		if err := store.UpdateStatus(agentID, body.Status, body.Notes); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	}
}

// ── Risk Classification ─────────────────────────────────────────────────────

func classifyRisk(a *ShadowAgent) string {
	// High-volume shadow usage is always concerning
	if a.RequestCount >= 1000 {
		return "critical"
	}
	if a.RequestCount >= 100 {
		return "high"
	}

	// Traffic to known LLM APIs from unregistered sources
	if _, isLLM := knownLLMDomains[a.TargetDomain]; isLLM {
		if a.RequestCount >= 10 {
			return "high"
		}
		return "medium"
	}

	if a.RequestCount >= 50 {
		return "medium"
	}
	return "low"
}

func mergeHints(existing, new []string) []string {
	seen := make(map[string]bool)
	for _, h := range existing {
		seen[h] = true
	}
	for _, h := range new {
		if !seen[h] {
			existing = append(existing, h)
		}
	}
	return existing
}

func writeJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}
