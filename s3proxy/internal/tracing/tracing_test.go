/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package tracing

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestSetupWithoutEndpointReturnsNoopShutdown(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")

	shutdown, err := Setup(context.Background(), "test", "0.0.0")
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	require.NoError(t, shutdown(context.Background()))
}

func TestSpanContextHandlerInjectsTraceAndSpanID(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			t.Logf("tracer provider shutdown: %v", err)
		}
	})
	otel.SetTracerProvider(tp)

	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(NewSpanContextHandler(inner))

	ctx, span := tp.Tracer("test").Start(context.Background(), "op")
	defer span.End()

	logger.InfoContext(ctx, "hello")

	var record map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &record))
	assert.Equal(t, "hello", record["msg"])
	assert.Equal(t, span.SpanContext().TraceID().String(), record["trace_id"])
	assert.Equal(t, span.SpanContext().SpanID().String(), record["span_id"])
}

func TestSpanContextHandlerPassThroughWithoutSpan(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	logger := slog.New(NewSpanContextHandler(inner))

	logger.InfoContext(context.Background(), "no-span")

	var record map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimRight(buf.Bytes(), "\n"), &record))
	_, hasTrace := record["trace_id"]
	assert.False(t, hasTrace, "trace_id should not be emitted without an active span")
}

func TestSpanContextHandlerPreservesWithAttrsAndWithGroup(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := NewSpanContextHandler(inner)

	// WithAttrs and WithGroup must return a wrapper so the injection still fires.
	attrs := handler.WithAttrs([]slog.Attr{slog.String("k", "v")})
	_, okAttrs := attrs.(*SpanContextHandler)
	assert.True(t, okAttrs)

	group := handler.WithGroup("grp")
	_, okGroup := group.(*SpanContextHandler)
	assert.True(t, okGroup)
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
