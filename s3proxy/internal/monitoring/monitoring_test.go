/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package monitoring

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouteLabel(t *testing.T) {
	cases := map[string]string{
		"/healthz":        "/healthz",
		"/readyz":         "/readyz",
		"/metrics":        "/metrics",
		"/bucket/key":     "/:bucket/:key",
		"/bucket/key/sub": "/:bucket/:key",
		"/":               "other",
		"":                "other",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, want, RouteLabel(in))
		})
	}
}

func TestInstrumentRecordsRequest(t *testing.T) {
	m := New()
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	m.Instrument(inner).ServeHTTP(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	exposition := scrape(t, m)
	assert.Contains(t, exposition, `http_requests_total{method="GET",path="/healthz",status="202"} 1`)
}

func TestInstrumentRecoversPanicIntoCrashCounter(t *testing.T) {
	m := New()
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	})

	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	rec := httptest.NewRecorder()
	m.Instrument(inner).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, scrape(t, m), "service_crashes_total 1")
}

func TestHandlerExposesRegisteredMetrics(t *testing.T) {
	m := New()
	m.ThrottledTotal.Inc()
	m.EncryptDuration.Observe(0.01)

	body := scrape(t, m)
	assert.True(t, strings.Contains(body, "s3proxy_throttled_total"))
	assert.True(t, strings.Contains(body, "s3proxy_encrypt_duration_seconds"))
}

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	return rec.Body.String()
}
