// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package slogger provides structured JSON logging for the Cicada Sentry Gateway.
//
// All log output is machine-parseable JSON with mandatory fields:
//
//	{
//	  "time":    "2026-05-10T14:00:00.000Z",
//	  "level":   "INFO",
//	  "msg":     "Request processed",
//	  "service": "cicada-sentry",
//	  ...additional key-value pairs...
//	}
//
// Usage:
//
//	slogger.Init()                     // call once in main()
//	slogger.Info("msg", "key", value)  // structured key-value pairs
//	slogger.Error("failed", "err", err, "agent", agentID)
//	slogger.WithTrace(traceID).Info("pipeline complete", "agent", agentID)
//
// The Init function also redirects the stdlib `log` package so that any
// existing log.Printf calls are captured as structured JSON rather than
// unformatted text. This enables incremental migration — old log.Printf
// calls still work, they just get wrapped in JSON automatically.
package slogger

import (
	"context"
	"log"
	"log/slog"
	"os"
	"time"
)

// service is the constant service name baked into every log line.
const service = "cicada-sentry"

// startTime records when the process started (for uptime computation).
var startTime = time.Now()

// Init configures the global structured logger with JSON output to stdout.
// It also redirects the stdlib log package through slog so existing
// log.Printf calls are captured as structured JSON.
//
// Environment variables:
//   - LOG_LEVEL: debug, info, warn, error (default: info)
//   - LOG_FORMAT: json, text (default: json). Use text for local dev.
func Init() {
	level := parseLevel(os.Getenv("LOG_LEVEL"))

	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: level}

	if os.Getenv("LOG_FORMAT") == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	// Wrap with the service attribute so every log line has it.
	logger := slog.New(handler).With(slog.String("service", service))
	slog.SetDefault(logger)

	// Redirect stdlib log.Printf through slog. This captures ALL existing
	// log.Printf / log.Println calls as structured INFO messages.
	log.SetFlags(0) // Remove timestamps — slog adds its own.
	log.SetOutput(&slogBridge{logger: logger})
}

// ── Convenience functions ─────────────────────────────────────────────────

// Info logs at INFO level with structured key-value pairs.
func Info(msg string, args ...any) {
	slog.Info(msg, args...)
}

// Warn logs at WARN level with structured key-value pairs.
func Warn(msg string, args ...any) {
	slog.Warn(msg, args...)
}

// Error logs at ERROR level with structured key-value pairs.
func Error(msg string, args ...any) {
	slog.Error(msg, args...)
}

// Debug logs at DEBUG level with structured key-value pairs.
func Debug(msg string, args ...any) {
	slog.Debug(msg, args...)
}

// Fatal logs at ERROR level and exits. Use sparingly — only for
// irrecoverable startup failures.
func Fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

// WithTrace returns a logger with the trace_id pre-attached. Use this
// for per-request logging where every log line should carry the trace.
func WithTrace(traceID string) *slog.Logger {
	return slog.Default().With(slog.String("trace_id", traceID))
}

// WithAgent returns a logger with both agent_id and tenant_id pre-attached.
func WithAgent(agentID, tenantID string) *slog.Logger {
	return slog.Default().With(
		slog.String("agent_id", agentID),
		slog.String("tenant_id", tenantID),
	)
}

// WithContext returns a logger enriched from a context (for future
// OpenTelemetry trace propagation).
func WithContext(ctx context.Context) *slog.Logger {
	// Placeholder — when OTel is integrated, extract trace/span IDs here.
	_ = ctx
	return slog.Default()
}

// ── slogBridge redirects stdlib log.Writer to slog ────────────────────────

type slogBridge struct {
	logger *slog.Logger
}

// Write implements io.Writer for the stdlib log package.
// Each log.Printf call writes to this, which we parse and forward to slog.
func (b *slogBridge) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Trim trailing newline that log.Printf adds.
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	b.logger.Info(msg, slog.String("source", "stdlib"))
	return len(p), nil
}

// ── Helpers ───────────────────────────────────────────────────────────────

func parseLevel(s string) slog.Level {
	switch s {
	case "debug", "DEBUG":
		return slog.LevelDebug
	case "warn", "WARN", "warning", "WARNING":
		return slog.LevelWarn
	case "error", "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
