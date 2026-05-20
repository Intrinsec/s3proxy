/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

/*
Package tracing wires OpenTelemetry trace export for the s3proxy process.

Setup installs a global TracerProvider that uses the OTLP HTTP exporter and a
W3C TraceContext propagator. When the OTEL_EXPORTER_OTLP_ENDPOINT environment
variable is unset the function returns a no-op shutdown and leaves the default
noop provider in place, so running without a collector remains cheap.
*/
package tracing

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// TracerName is the instrumentation scope used by handlers when creating spans.
const TracerName = "github.com/intrinsec/s3proxy"

// ShutdownFunc flushes and shuts down the tracer provider. It is always safe to call.
type ShutdownFunc func(context.Context) error

// Setup configures a global TracerProvider exporting via OTLP/HTTP. It is a
// no-op when the OTEL_EXPORTER_OTLP_ENDPOINT environment variable is empty.
func Setup(ctx context.Context, serviceName, serviceVersion string) (ShutdownFunc, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}

// SpanContextHandler wraps an slog.Handler so log records emitted with a context
// carrying an active span include trace_id and span_id attributes. Logs emitted
// outside of a span pass through unchanged.
type SpanContextHandler struct {
	slog.Handler
}

// NewSpanContextHandler wraps h so Handle injects trace metadata.
func NewSpanContextHandler(h slog.Handler) *SpanContextHandler {
	return &SpanContextHandler{Handler: h}
}

// Handle injects trace_id and span_id attributes when a span is present on the record's context.
func (h *SpanContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return h.Handler.Handle(ctx, r)
}

// WithAttrs returns a handler preserving the trace-injection wrapper.
func (h *SpanContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SpanContextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

// WithGroup returns a handler preserving the trace-injection wrapper.
func (h *SpanContextHandler) WithGroup(name string) slog.Handler {
	return &SpanContextHandler{Handler: h.Handler.WithGroup(name)}
}
