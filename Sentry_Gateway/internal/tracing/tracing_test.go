// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func TestInit(t *testing.T) {
	// Default init uses stdout exporter.
	ctx := context.Background()
	if err := Init(ctx); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	defer Shutdown(ctx)

	// Verify a global TracerProvider was set (not the no-op default).
	provider := otel.GetTracerProvider()
	if _, ok := provider.(*sdktrace.TracerProvider); !ok {
		t.Errorf("expected *sdktrace.TracerProvider, got %T", provider)
	}
}

func TestInitWithOTLPExporter(t *testing.T) {
	// Set OTLP exporter — Init should not fail even without a real collector,
	// because the exporter is lazy (batched, connects on first export).
	os.Setenv("OTEL_EXPORTER", "otlp")
	os.Setenv("OTEL_ENDPOINT", "localhost:4317")
	defer os.Unsetenv("OTEL_EXPORTER")
	defer os.Unsetenv("OTEL_ENDPOINT")

	ctx := context.Background()
	if err := Init(ctx); err != nil {
		t.Fatalf("Init(otlp) failed: %v", err)
	}
	defer Shutdown(ctx)
}

func TestInitCustomServiceName(t *testing.T) {
	os.Setenv("OTEL_SERVICE_NAME", "test-gateway")
	defer os.Unsetenv("OTEL_SERVICE_NAME")

	ctx := context.Background()
	if err := Init(ctx); err != nil {
		t.Fatalf("Init() with custom service name failed: %v", err)
	}
	defer Shutdown(ctx)
}

func TestInitCustomSampleRate(t *testing.T) {
	os.Setenv("OTEL_SAMPLE_RATE", "0.5")
	defer os.Unsetenv("OTEL_SAMPLE_RATE")

	ctx := context.Background()
	if err := Init(ctx); err != nil {
		t.Fatalf("Init() with sample rate failed: %v", err)
	}
	defer Shutdown(ctx)
}

func TestTracer(t *testing.T) {
	ctx := context.Background()
	if err := Init(ctx); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	defer Shutdown(ctx)

	tracer := Tracer("test-component")
	if tracer == nil {
		t.Fatal("Tracer() returned nil")
	}
}

func TestSpanFromCtx(t *testing.T) {
	ctx := context.Background()
	if err := Init(ctx); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	defer Shutdown(ctx)

	// Without a span, should return a no-op span.
	span := SpanFromCtx(ctx)
	if span == nil {
		t.Fatal("SpanFromCtx() returned nil for background context")
	}

	// With a real span, should return it.
	tracer := Tracer("test")
	ctx2, span2 := tracer.Start(ctx, "test-span")
	defer span2.End()

	got := SpanFromCtx(ctx2)
	if got.SpanContext().TraceID() != span2.SpanContext().TraceID() {
		t.Errorf("SpanFromCtx trace ID mismatch: %v != %v",
			got.SpanContext().TraceID(), span2.SpanContext().TraceID())
	}
}

func TestMiddleware(t *testing.T) {
	ctx := context.Background()
	if err := Init(ctx); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	defer Shutdown(ctx)

	// Inner handler that verifies the context has a span.
	var capturedSpan trace.Span
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSpan = SpanFromCtx(r.Context())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK")) //nolint:errcheck
	})

	handler := Middleware(inner)

	req := httptest.NewRequest("GET", "/api/v1/agents", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// ── Verify response ──
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// ── Verify X-Trace-ID header was injected ──
	traceIDHeader := rec.Header().Get("X-Trace-ID")
	if traceIDHeader == "" {
		t.Error("expected X-Trace-ID response header, got empty")
	}
	if len(traceIDHeader) != 32 {
		t.Errorf("expected 32-char trace ID, got %d chars: %s", len(traceIDHeader), traceIDHeader)
	}

	// ── Verify span was created ──
	if capturedSpan == nil {
		t.Fatal("expected span in request context, got nil")
	}
	if !capturedSpan.SpanContext().IsValid() {
		t.Error("expected valid span context")
	}
}

func TestMiddlewareTraceparentPropagation(t *testing.T) {
	ctx := context.Background()
	if err := Init(ctx); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	defer Shutdown(ctx)

	// Simulate an incoming request WITH a traceparent header (from Core API or Portal).
	incomingTraceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	incomingParentID := "00f067aa0ba902b7"
	traceparent := "00-" + incomingTraceID + "-" + incomingParentID + "-01"

	var capturedSpan trace.Span
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSpan = SpanFromCtx(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(inner)
	req := httptest.NewRequest("POST", "/v1/evaluate", nil)
	req.Header.Set("Traceparent", traceparent)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// The span should have inherited the incoming trace ID.
	gotTraceID := capturedSpan.SpanContext().TraceID().String()
	if gotTraceID != incomingTraceID {
		t.Errorf("expected propagated trace ID %s, got %s", incomingTraceID, gotTraceID)
	}

	// The X-Trace-ID response header should match.
	headerTraceID := rec.Header().Get("X-Trace-ID")
	if headerTraceID != incomingTraceID {
		t.Errorf("X-Trace-ID header should match propagated trace: %s != %s", headerTraceID, incomingTraceID)
	}
}

func TestMiddleware5xxRecordsError(t *testing.T) {
	ctx := context.Background()
	if err := Init(ctx); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	defer Shutdown(ctx)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	handler := Middleware(inner)
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}

	// Verify X-Trace-ID is still present even on errors.
	if rec.Header().Get("X-Trace-ID") == "" {
		t.Error("X-Trace-ID should be present even on 500 responses")
	}
}

func TestShutdownIdempotent(t *testing.T) {
	ctx := context.Background()

	// Shutdown before Init — should not panic.
	Shutdown(ctx)

	// Init, then double shutdown.
	if err := Init(ctx); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	Shutdown(ctx)
	Shutdown(ctx) // Should not panic.
}

func TestStatusWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK}

	// Write without explicit WriteHeader — should default to 200.
	sw.Write([]byte("hello")) //nolint:errcheck
	if sw.status != http.StatusOK {
		t.Errorf("expected 200, got %d", sw.status)
	}

	// Explicit WriteHeader.
	rec2 := httptest.NewRecorder()
	sw2 := &statusWriter{ResponseWriter: rec2, status: http.StatusOK}
	sw2.WriteHeader(http.StatusNotFound)
	if sw2.status != http.StatusNotFound {
		t.Errorf("expected 404, got %d", sw2.status)
	}

	// Double WriteHeader — should not overwrite.
	sw2.WriteHeader(http.StatusBadGateway)
	if sw2.status != http.StatusNotFound {
		t.Errorf("expected 404 (first write), got %d", sw2.status)
	}
}

func TestW3CPropagatorSet(t *testing.T) {
	ctx := context.Background()
	if err := Init(ctx); err != nil {
		t.Fatalf("Init() failed: %v", err)
	}
	defer Shutdown(ctx)

	propagator := otel.GetTextMapPropagator()
	if propagator == nil {
		t.Fatal("expected non-nil propagator after Init()")
	}

	// Verify it handles traceparent field.
	fields := propagator.Fields()
	found := false
	for _, f := range fields {
		if f == "traceparent" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'traceparent' in propagator fields, got %v", fields)
	}
}

func TestEnvOrDefault(t *testing.T) {
	tests := []struct {
		key, envVal, fallback, want string
	}{
		{"TEST_KEY_1", "custom", "default", "custom"},
		{"TEST_KEY_2", "", "default", "default"},
	}

	for _, tt := range tests {
		if tt.envVal != "" {
			os.Setenv(tt.key, tt.envVal)
			defer os.Unsetenv(tt.key)
		}
		got := envOrDefault(tt.key, tt.fallback)
		if got != tt.want {
			t.Errorf("envOrDefault(%q, %q) = %q, want %q", tt.key, tt.fallback, got, tt.want)
		}
	}
}
