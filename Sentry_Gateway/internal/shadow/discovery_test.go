// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── Store Unit Tests ────────────────────────────────────────────────────────

func TestNewStore_InMemory(t *testing.T) {
	store := NewStore()
	if store == nil {
		t.Fatal("NewStore returned nil")
	}
	if store.agents == nil {
		t.Fatal("agents map not initialised")
	}
	if store.db != nil {
		t.Fatal("expected no DB connection when CICADA_SHADOW_DB_PATH is unset")
	}
}

func TestIngest_NewSighting(t *testing.T) {
	store := NewStore()
	req := IngestRequest{
		Source:   "netskope",
		TenantID: "tenant-001",
		Sightings: []CASBSighting{
			{
				SourceIP:     "10.0.0.42",
				UserAgent:    "python-requests/2.31.0",
				TargetDomain: "api.openai.com",
				TargetPath:   "/v1/chat/completions",
				RequestCount: 15,
				FirstSeen:    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
				LastSeen:     time.Now().Format(time.RFC3339),
				ModelHints:   []string{"gpt-4"},
			},
		},
	}

	newCount, updatedCount := store.Ingest(req)
	if newCount != 1 {
		t.Fatalf("expected 1 new agent, got %d", newCount)
	}
	if updatedCount != 0 {
		t.Fatalf("expected 0 updated, got %d", updatedCount)
	}

	// Verify agent was stored
	agents := store.List("tenant-001", "")
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent in store, got %d", len(agents))
	}
	if agents[0].TargetDomain != "api.openai.com" {
		t.Errorf("expected domain api.openai.com, got %s", agents[0].TargetDomain)
	}
	if agents[0].Status != "unreviewed" {
		t.Errorf("expected status unreviewed, got %s", agents[0].Status)
	}
	if agents[0].SourceCASB != "netskope" {
		t.Errorf("expected source netskope, got %s", agents[0].SourceCASB)
	}
}

func TestIngest_DuplicateIsIdempotent(t *testing.T) {
	store := NewStore()
	sighting := CASBSighting{
		SourceIP:     "10.0.0.42",
		TargetDomain: "api.openai.com",
		RequestCount: 10,
		FirstSeen:    time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
		LastSeen:     time.Now().Format(time.RFC3339),
	}
	req := IngestRequest{
		Source:    "netskope",
		TenantID: "tenant-001",
		Sightings: []CASBSighting{sighting},
	}

	// First ingest
	newCount, _ := store.Ingest(req)
	if newCount != 1 {
		t.Fatalf("first ingest: expected 1 new, got %d", newCount)
	}

	// Second ingest — same IP + domain = update, not duplicate
	newCount2, updatedCount := store.Ingest(req)
	if newCount2 != 0 {
		t.Fatalf("second ingest: expected 0 new, got %d", newCount2)
	}
	if updatedCount != 1 {
		t.Fatalf("second ingest: expected 1 updated, got %d", updatedCount)
	}

	// Should still have exactly 1 agent
	agents := store.List("tenant-001", "")
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent after duplicate ingest, got %d", len(agents))
	}
	// Request count should accumulate
	if agents[0].RequestCount != 20 {
		t.Errorf("expected accumulated request count 20, got %d", agents[0].RequestCount)
	}
}

func TestIngest_MergesModelHints(t *testing.T) {
	store := NewStore()
	base := IngestRequest{
		Source:   "zscaler",
		TenantID: "tenant-002",
		Sightings: []CASBSighting{
			{
				SourceIP:     "10.0.1.1",
				TargetDomain: "api.anthropic.com",
				RequestCount: 5,
				FirstSeen:    time.Now().Format(time.RFC3339),
				LastSeen:     time.Now().Format(time.RFC3339),
				ModelHints:   []string{"claude-3"},
			},
		},
	}
	store.Ingest(base)

	// Second ingest with different model hint
	base.Sightings[0].ModelHints = []string{"claude-3", "claude-opus"}
	store.Ingest(base)

	agents := store.List("tenant-002", "")
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if len(agents[0].ModelHints) != 2 {
		t.Errorf("expected 2 merged model hints, got %d: %v", len(agents[0].ModelHints), agents[0].ModelHints)
	}
}

func TestList_FiltersByTenant(t *testing.T) {
	store := NewStore()
	// Ingest for two different tenants
	store.Ingest(IngestRequest{
		Source: "netskope", TenantID: "tenant-A",
		Sightings: []CASBSighting{{SourceIP: "10.0.0.1", TargetDomain: "api.openai.com", RequestCount: 5, FirstSeen: time.Now().Format(time.RFC3339), LastSeen: time.Now().Format(time.RFC3339)}},
	})
	store.Ingest(IngestRequest{
		Source: "netskope", TenantID: "tenant-B",
		Sightings: []CASBSighting{{SourceIP: "10.0.0.2", TargetDomain: "api.anthropic.com", RequestCount: 3, FirstSeen: time.Now().Format(time.RFC3339), LastSeen: time.Now().Format(time.RFC3339)}},
	})

	listA := store.List("tenant-A", "")
	if len(listA) != 1 {
		t.Fatalf("expected 1 agent for tenant-A, got %d", len(listA))
	}
	listB := store.List("tenant-B", "")
	if len(listB) != 1 {
		t.Fatalf("expected 1 agent for tenant-B, got %d", len(listB))
	}

	// Empty tenant = all agents
	listAll := store.List("", "")
	if len(listAll) != 2 {
		t.Fatalf("expected 2 total agents, got %d", len(listAll))
	}
}

func TestList_FiltersByStatus(t *testing.T) {
	store := NewStore()
	store.Ingest(IngestRequest{
		Source: "prisma", TenantID: "tenant-C",
		Sightings: []CASBSighting{
			{SourceIP: "10.0.0.10", TargetDomain: "api.openai.com", RequestCount: 5, FirstSeen: time.Now().Format(time.RFC3339), LastSeen: time.Now().Format(time.RFC3339)},
			{SourceIP: "10.0.0.11", TargetDomain: "api.mistral.ai", RequestCount: 3, FirstSeen: time.Now().Format(time.RFC3339), LastSeen: time.Now().Format(time.RFC3339)},
		},
	})

	// Both should start as "unreviewed"
	unreviewed := store.List("tenant-C", "unreviewed")
	if len(unreviewed) != 2 {
		t.Fatalf("expected 2 unreviewed, got %d", len(unreviewed))
	}

	// Acknowledge one
	agents := store.List("tenant-C", "")
	store.UpdateStatus(agents[0].ID, "acknowledged", "reviewed by operator")

	unreviewed = store.List("tenant-C", "unreviewed")
	if len(unreviewed) != 1 {
		t.Fatalf("expected 1 unreviewed after acknowledge, got %d", len(unreviewed))
	}
}

func TestUpdateStatus_ValidTransitions(t *testing.T) {
	store := NewStore()
	store.Ingest(IngestRequest{
		Source: "netskope", TenantID: "tenant-X",
		Sightings: []CASBSighting{{SourceIP: "10.0.0.99", TargetDomain: "api.groq.com", RequestCount: 7, FirstSeen: time.Now().Format(time.RFC3339), LastSeen: time.Now().Format(time.RFC3339)}},
	})

	agents := store.List("tenant-X", "")
	id := agents[0].ID

	// Valid transitions
	for _, status := range []string{"acknowledged", "quarantined", "registered"} {
		if err := store.UpdateStatus(id, status, "test transition"); err != nil {
			t.Errorf("UpdateStatus(%q) failed: %v", status, err)
		}
		updated := store.List("tenant-X", "")
		if updated[0].Status != status {
			t.Errorf("expected status %q, got %q", status, updated[0].Status)
		}
	}
}

func TestUpdateStatus_InvalidStatus(t *testing.T) {
	store := NewStore()
	store.Ingest(IngestRequest{
		Source: "netskope", TenantID: "tenant-Y",
		Sightings: []CASBSighting{{SourceIP: "10.0.0.50", TargetDomain: "api.cohere.ai", RequestCount: 2, FirstSeen: time.Now().Format(time.RFC3339), LastSeen: time.Now().Format(time.RFC3339)}},
	})
	agents := store.List("tenant-Y", "")

	err := store.UpdateStatus(agents[0].ID, "invalid_status", "")
	if err == nil {
		t.Fatal("expected error for invalid status, got nil")
	}
}

func TestUpdateStatus_NotFound(t *testing.T) {
	store := NewStore()
	err := store.UpdateStatus("nonexistent:agent:id", "acknowledged", "")
	if err == nil {
		t.Fatal("expected error for nonexistent agent, got nil")
	}
}

func TestUpdateStatus_SetsNotes(t *testing.T) {
	store := NewStore()
	store.Ingest(IngestRequest{
		Source: "netskope", TenantID: "tenant-Z",
		Sightings: []CASBSighting{{SourceIP: "10.0.0.77", TargetDomain: "api.replicate.com", RequestCount: 1, FirstSeen: time.Now().Format(time.RFC3339), LastSeen: time.Now().Format(time.RFC3339)}},
	})
	agents := store.List("tenant-Z", "")

	store.UpdateStatus(agents[0].ID, "quarantined", "suspected data exfiltration via Replicate")
	agents = store.List("tenant-Z", "")
	if agents[0].Notes != "suspected data exfiltration via Replicate" {
		t.Errorf("expected notes to be set, got %q", agents[0].Notes)
	}
}

// ── Risk Classification Tests ───────────────────────────────────────────────

func TestClassifyRisk_Critical(t *testing.T) {
	agent := &ShadowAgent{RequestCount: 1000, TargetDomain: "api.openai.com"}
	risk := classifyRisk(agent)
	if risk != "critical" {
		t.Errorf("expected critical for 1000 requests, got %s", risk)
	}
}

func TestClassifyRisk_High_VolumeThreshold(t *testing.T) {
	agent := &ShadowAgent{RequestCount: 100, TargetDomain: "unknown-domain.com"}
	risk := classifyRisk(agent)
	if risk != "high" {
		t.Errorf("expected high for 100 requests, got %s", risk)
	}
}

func TestClassifyRisk_High_KnownLLM(t *testing.T) {
	agent := &ShadowAgent{RequestCount: 10, TargetDomain: "api.anthropic.com"}
	risk := classifyRisk(agent)
	if risk != "high" {
		t.Errorf("expected high for 10 requests to known LLM, got %s", risk)
	}
}

func TestClassifyRisk_Medium_KnownLLMLowVolume(t *testing.T) {
	agent := &ShadowAgent{RequestCount: 5, TargetDomain: "api.mistral.ai"}
	risk := classifyRisk(agent)
	if risk != "medium" {
		t.Errorf("expected medium for 5 requests to known LLM, got %s", risk)
	}
}

func TestClassifyRisk_Low(t *testing.T) {
	agent := &ShadowAgent{RequestCount: 3, TargetDomain: "unknown-api.example.com"}
	risk := classifyRisk(agent)
	if risk != "low" {
		t.Errorf("expected low for 3 requests to unknown domain, got %s", risk)
	}
}

// ── Known LLM Domain Fingerprints ───────────────────────────────────────────

func TestKnownLLMDomains_AllPresent(t *testing.T) {
	expected := map[string]string{
		"api.openai.com":                     "OpenAI",
		"api.anthropic.com":                  "Anthropic",
		"generativelanguage.googleapis.com":  "Google Gemini",
		"api.cohere.ai":                      "Cohere",
		"api.mistral.ai":                     "Mistral",
		"api-inference.huggingface.co":       "HuggingFace",
		"api.together.xyz":                   "Together AI",
		"api.groq.com":                       "Groq",
		"api.replicate.com":                  "Replicate",
		"bedrock-runtime.amazonaws.com":      "AWS Bedrock",
		"azopenai.azure.com":                "Azure OpenAI",
	}

	if len(knownLLMDomains) != len(expected) {
		t.Fatalf("expected %d known LLM domains, got %d", len(expected), len(knownLLMDomains))
	}

	for domain, provider := range expected {
		if got, ok := knownLLMDomains[domain]; !ok {
			t.Errorf("missing domain %s", domain)
		} else if got != provider {
			t.Errorf("domain %s: expected provider %q, got %q", domain, provider, got)
		}
	}
}

// ── Stats Tests ─────────────────────────────────────────────────────────────

func TestStats_AggregatesCorrectly(t *testing.T) {
	store := NewStore()
	now := time.Now().Format(time.RFC3339)

	// 3 agents: 1 critical (1000 req), 1 high (100 req to LLM), 1 low
	store.Ingest(IngestRequest{
		Source: "netskope", TenantID: "tenant-stats",
		Sightings: []CASBSighting{
			{SourceIP: "10.0.0.1", TargetDomain: "api.openai.com", RequestCount: 1000, FirstSeen: now, LastSeen: now},
			{SourceIP: "10.0.0.2", TargetDomain: "api.anthropic.com", RequestCount: 100, FirstSeen: now, LastSeen: now},
			{SourceIP: "10.0.0.3", TargetDomain: "custom.example.com", RequestCount: 2, FirstSeen: now, LastSeen: now},
		},
	})

	stats := store.Stats("tenant-stats")

	if stats["total_shadow_agents"] != 3 {
		t.Errorf("expected total 3, got %v", stats["total_shadow_agents"])
	}
	if stats["unreviewed"] != 3 {
		t.Errorf("expected 3 unreviewed, got %v", stats["unreviewed"])
	}
	if stats["critical_risk"] != 1 {
		t.Errorf("expected 1 critical, got %v", stats["critical_risk"])
	}
	if stats["high_risk"] != 1 {
		t.Errorf("expected 1 high, got %v", stats["high_risk"])
	}

	providers := stats["providers"].(map[string]int)
	if providers["OpenAI"] != 1 {
		t.Errorf("expected OpenAI count 1, got %d", providers["OpenAI"])
	}
}

// ── HTTP Handler Tests ──────────────────────────────────────────────────────

func TestIngestHandler_Success(t *testing.T) {
	store := NewStore()
	handler := IngestHandler(store)

	payload := IngestRequest{
		Source:   "netskope",
		TenantID: "tenant-http",
		Sightings: []CASBSighting{
			{SourceIP: "10.0.0.1", TargetDomain: "api.openai.com", RequestCount: 5, FirstSeen: time.Now().Format(time.RFC3339), LastSeen: time.Now().Format(time.RFC3339)},
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/shadow/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["new"].(float64) != 1 {
		t.Errorf("expected new=1, got %v", resp["new"])
	}
}

func TestIngestHandler_MissingSource(t *testing.T) {
	store := NewStore()
	handler := IngestHandler(store)

	payload := IngestRequest{TenantID: "tenant-bad", Sightings: []CASBSighting{{SourceIP: "10.0.0.1", TargetDomain: "x.com", RequestCount: 1, FirstSeen: time.Now().Format(time.RFC3339), LastSeen: time.Now().Format(time.RFC3339)}}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/shadow/ingest", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing source, got %d", rr.Code)
	}
}

func TestIngestHandler_NoSightings(t *testing.T) {
	store := NewStore()
	handler := IngestHandler(store)

	payload := IngestRequest{Source: "netskope", TenantID: "tenant-empty", Sightings: []CASBSighting{}}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/shadow/ingest", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty sightings, got %d", rr.Code)
	}
}

func TestIngestHandler_InvalidJSON(t *testing.T) {
	store := NewStore()
	handler := IngestHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/v1/shadow/ingest", bytes.NewReader([]byte("not json")))
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestListHandler_ReturnsAgents(t *testing.T) {
	store := NewStore()
	store.Ingest(IngestRequest{
		Source: "netskope", TenantID: "tenant-list",
		Sightings: []CASBSighting{{SourceIP: "10.0.0.1", TargetDomain: "api.openai.com", RequestCount: 5, FirstSeen: time.Now().Format(time.RFC3339), LastSeen: time.Now().Format(time.RFC3339)}},
	})

	handler := ListHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/shadow/agents?tenant_id=tenant-list", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["count"].(float64) != 1 {
		t.Errorf("expected count=1, got %v", resp["count"])
	}
}

func TestStatsHandler_ReturnsAggregates(t *testing.T) {
	store := NewStore()
	now := time.Now().Format(time.RFC3339)
	store.Ingest(IngestRequest{
		Source: "zscaler", TenantID: "tenant-stats-http",
		Sightings: []CASBSighting{
			{SourceIP: "10.0.0.1", TargetDomain: "api.openai.com", RequestCount: 200, FirstSeen: now, LastSeen: now},
			{SourceIP: "10.0.0.2", TargetDomain: "api.groq.com", RequestCount: 3, FirstSeen: now, LastSeen: now},
		},
	})

	handler := StatsHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/shadow/stats?tenant_id=tenant-stats-http", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var stats map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &stats)
	if stats["total_shadow_agents"].(float64) != 2 {
		t.Errorf("expected total=2, got %v", stats["total_shadow_agents"])
	}
}

// ── MergeHints Tests ────────────────────────────────────────────────────────

func TestMergeHints_DeduplicatesCorrectly(t *testing.T) {
	existing := []string{"gpt-4", "gpt-3.5"}
	newHints := []string{"gpt-4", "gpt-4o"}

	merged := mergeHints(existing, newHints)
	if len(merged) != 3 {
		t.Errorf("expected 3 merged hints, got %d: %v", len(merged), merged)
	}

	seen := make(map[string]bool)
	for _, h := range merged {
		if seen[h] {
			t.Errorf("duplicate hint found: %s", h)
		}
		seen[h] = true
	}
}
