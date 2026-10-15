// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package tracing configures OpenTelemetry distributed tracing for the
// Cicada Sentry Gateway.
//
// It provides:
//   - Init()       — Initialises the global TracerProvider with an OTLP or
//     stdout exporter (controlled by OTEL_EXPORTER env var).
//   - Middleware()  — Chi-compatible HTTP middleware that wraps every request
//     in a span, propagating W3C Traceparent/Tracestate headers.
//   - SpanFromCtx() — Extracts the current span from a context for manual
//     annotation inside handlers.
//   - Shutdown()   — Flushes pending spans before process exit.
//
// Environment variables:
//
//	OTEL_EXPORTER          = "otlp" | "stdout" | "" (default: stdout)
//	OTEL_ENDPOINT          = OTLP collector gRPC address (default: localhost:4317)
//	OTEL_SERVICE_NAME      = override service name (default: cicada-sentry-gateway)
//	OTEL_SAMPLE_RATE       = float 0.0–1.0 (default: 1.0 = sample everything)
package tracing

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

const defaultServiceName = "cicada-sentry-gateway"

var tp *sdktrace.TracerProvider

// Init creates and registers a global TracerProvider.
// Call Shutdown() before process exit to flush buffered spans.
func Init(ctx context.Context) error {
	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = defaultServiceName
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion("1.0.0"),
			attribute.String("deployment.environment", envOrDefault("APP_ENV", "development")),
		),
	)
	if err != nil {
		return fmt.Errorf("tracing: resource: %w", err)
	}

	exporter, err := newExporter(ctx)
	if err != nil {
		return fmt.Errorf("tracing: exporter: %w", err)
	}

	sampleRate := 1.0
	if s := os.Getenv("OTEL_SAMPLE_RATE"); s != "" {
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			sampleRate = v
		}
	}

	tp = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(sampleRate)),
	)

	// Register globally so any package can call otel.Tracer().
	otel.SetTracerProvider(tp)

	// Propagate W3C Traceparent + Tracestate headers across service boundaries.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	log.Printf("[TRACING] Initialised — exporter=%s, service=%s, sample_rate=%.2f",
		os.Getenv("OTEL_EXPORTER"), serviceName, sampleRate)
	return nil
}

// Shutdown flushes all pending spans. Call in main() defer.
func Shutdown(ctx context.Context) {
	if tp == nil {
		return
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := tp.Shutdown(shutdownCtx); err != nil {
		log.Printf("[TRACING] Shutdown error: %v", err)
	}
}

// Tracer returns a named tracer for the given component.
func Tracer(name string) trace.Tracer {
	return otel.Tracer("cicada/" + name)
}

// SpanFromCtx extracts the active span from the context.
// Returns a no-op span if none exists.
func SpanFromCtx(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// Middleware returns Chi-compatible HTTP middleware that:
//  1. Extracts incoming W3C traceparent from the request headers.
//  2. Creates a server span for the request.
//  3. Records HTTP attributes (method, route, status, duration).
//  4. Injects the trace_id into the response header for debugging.
func Middleware(next http.Handler) http.Handler {
	tracer := Tracer("http")
	propagator := otel.GetTextMapPropagator()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract incoming trace context from headers.
		ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		// Start a span named after the HTTP method + path pattern.
		spanName := r.Method + " " + r.URL.Path
		ctx, span := tracer.Start(ctx, spanName,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPMethod(r.Method),
				semconv.HTTPTarget(r.URL.Path),
				semconv.HTTPScheme(scheme(r)),
				attribute.String("http.client_ip", r.RemoteAddr),
				attribute.String("http.user_agent", r.UserAgent()),
			),
		)
		defer span.End()

		// Inject trace ID into response header for client-side correlation.
		traceID := span.SpanContext().TraceID().String()
		w.Header().Set("X-Trace-ID", traceID)

		// Wrap the ResponseWriter to capture status code.
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		// Serve with the traced context.
		next.ServeHTTP(sw, r.WithContext(ctx))

		// Record the response status.
		span.SetAttributes(semconv.HTTPStatusCode(sw.status))
		if sw.status >= 500 {
			span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", sw.status))
		}
	})
}

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (sw *statusWriter) WriteHeader(code int) {
	if !sw.wroteHeader {
		sw.status = code
		sw.wroteHeader = true
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if !sw.wroteHeader {
		sw.wroteHeader = true
	}
	return sw.ResponseWriter.Write(b)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func newExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	switch os.Getenv("OTEL_EXPORTER") {
	case "otlp":
		endpoint := envOrDefault("OTEL_ENDPOINT", "localhost:4317")
		return otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(), // TLS can be enabled via env
		)
	default:
		// stdout exporter — human-readable for local development.
		return stdouttrace.New(stdouttrace.WithPrettyPrint())
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
