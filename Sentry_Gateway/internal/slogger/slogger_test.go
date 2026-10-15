// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package slogger

import (
	"bytes"
	"encoding/json"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// captureJSON captures structured log output into a buffer for assertion.
func captureJSON(t *testing.T, fn func()) []map[string]interface{} {
	t.Helper()

	var buf bytes.Buffer

	// Build a JSON handler that writes to the buffer.
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler).With(slog.String("service", service))
	slog.SetDefault(logger)

	// Also redirect stdlib log through the buffer.
	log.SetFlags(0)
	log.SetOutput(&slogBridge{logger: logger})

	fn()

	// Parse all JSON lines from the buffer.
	var entries []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON log line: %s — %v", line, err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func TestInfo(t *testing.T) {
	entries := captureJSON(t, func() {
		Info("request processed", "agent_id", "ag-001", "status", "ok")
	})

	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}
	e := entries[0]

	if e["msg"] != "request processed" {
		t.Errorf("msg = %v, want 'request processed'", e["msg"])
	}
	if e["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", e["level"])
	}
	if e["service"] != service {
		t.Errorf("service = %v, want %s", e["service"], service)
	}
	if e["agent_id"] != "ag-001" {
		t.Errorf("agent_id = %v, want 'ag-001'", e["agent_id"])
	}
	if e["status"] != "ok" {
		t.Errorf("status = %v, want 'ok'", e["status"])
	}
	if _, ok := e["time"]; !ok {
		t.Error("expected 'time' field in JSON output")
	}
}

func TestError(t *testing.T) {
	entries := captureJSON(t, func() {
		Error("pipeline failed", "err", "timeout", "trace_id", "tr-123")
	})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0]["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR", entries[0]["level"])
	}
	if entries[0]["trace_id"] != "tr-123" {
		t.Errorf("trace_id = %v, want 'tr-123'", entries[0]["trace_id"])
	}
}

func TestWarn(t *testing.T) {
	entries := captureJSON(t, func() {
		Warn("rate limit approaching", "agent_id", "ag-002")
	})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0]["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", entries[0]["level"])
	}
}

func TestDebug(t *testing.T) {
	entries := captureJSON(t, func() {
		Debug("cache hit", "key", "policy:ag-001")
	})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0]["level"] != "DEBUG" {
		t.Errorf("level = %v, want DEBUG", entries[0]["level"])
	}
}

func TestWithTrace(t *testing.T) {
	entries := captureJSON(t, func() {
		l := WithTrace("trace-abc-123")
		l.Info("pipeline complete", "agent_id", "ag-001")
	})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0]["trace_id"] != "trace-abc-123" {
		t.Errorf("trace_id = %v, want 'trace-abc-123'", entries[0]["trace_id"])
	}
	if entries[0]["agent_id"] != "ag-001" {
		t.Errorf("agent_id = %v, want 'ag-001'", entries[0]["agent_id"])
	}
}

func TestWithAgent(t *testing.T) {
	entries := captureJSON(t, func() {
		l := WithAgent("ag-billing", "tenant-99")
		l.Info("session issued")
	})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0]["agent_id"] != "ag-billing" {
		t.Errorf("agent_id = %v, want 'ag-billing'", entries[0]["agent_id"])
	}
	if entries[0]["tenant_id"] != "tenant-99" {
		t.Errorf("tenant_id = %v, want 'tenant-99'", entries[0]["tenant_id"])
	}
}

func TestStdlibBridge(t *testing.T) {
	entries := captureJSON(t, func() {
		// This simulates existing log.Printf calls being redirected.
		log.Printf("[GATEWAY] Server starting on port %d", 8080)
	})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !strings.Contains(entries[0]["msg"].(string), "Server starting on port 8080") {
		t.Errorf("msg should contain original log.Printf text, got: %v", entries[0]["msg"])
	}
	if entries[0]["source"] != "stdlib" {
		t.Errorf("source = %v, want 'stdlib'", entries[0]["source"])
	}
	if entries[0]["service"] != service {
		t.Errorf("service = %v, want %s", entries[0]["service"], service)
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"WARN", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"", slog.LevelInfo},        // default
		{"garbage", slog.LevelInfo}, // unknown defaults to info
	}

	for _, tt := range tests {
		got := parseLevel(tt.input)
		if got != tt.want {
			t.Errorf("parseLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestInit(t *testing.T) {
	// Ensure Init doesn't panic.
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("LOG_FORMAT", "json")
	Init()

	// Verify the logger works after Init.
	entries := captureJSON(t, func() {
		Info("init test")
	})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after Init, got %d", len(entries))
	}

	// Clean up.
	os.Unsetenv("LOG_LEVEL")
	os.Unsetenv("LOG_FORMAT")
}

func TestInitTextFormat(t *testing.T) {
	os.Setenv("LOG_FORMAT", "text")
	Init() // Should not panic with text format.
	os.Unsetenv("LOG_FORMAT")
}
