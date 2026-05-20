/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

/*
Package monitoring exposes Prometheus metrics for the s3proxy process.

Metrics is intentionally constructed per server (not package-global) so tests
can build independent registries; a local registry is used by default to avoid
polluting prometheus.DefaultRegisterer.
*/
package monitoring

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsPath is the HTTP path where metrics are exposed.
const MetricsPath = "/metrics"

// Metrics bundles Prometheus collectors exposed by the proxy.
type Metrics struct {
	registry *prometheus.Registry

	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	ErrorsTotal         *prometheus.CounterVec
	ServiceCrashesTotal prometheus.Counter

	EncryptDuration prometheus.Histogram
	DecryptDuration prometheus.Histogram
	UpstreamErrors  prometheus.Counter
	ThrottledTotal  prometheus.Counter
}

// New constructs a Metrics bundle backed by a dedicated Registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewGoCollector())

	m := &Metrics{
		registry: reg,
		HTTPRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Count of HTTP requests received by s3proxy, labeled by method, normalised path and status.",
		}, []string{"method", "path", "status"}),
		HTTPRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency observed by s3proxy.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "path"}),
		ErrorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "errors_total",
			Help: "Count of s3proxy error events, labeled by error class.",
		}, []string{"type"}),
		ServiceCrashesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "service_crashes_total",
			Help: "Count of in-process handler panics that were recovered.",
		}),
		EncryptDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "s3proxy_encrypt_duration_seconds",
			Help:    "Time spent encrypting PutObject bodies.",
			Buckets: prometheus.DefBuckets,
		}),
		DecryptDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "s3proxy_decrypt_duration_seconds",
			Help:    "Time spent decrypting GetObject bodies.",
			Buckets: prometheus.DefBuckets,
		}),
		UpstreamErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "s3proxy_upstream_errors_total",
			Help: "Count of errors interacting with the upstream S3 endpoint.",
		}),
		ThrottledTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "s3proxy_throttled_total",
			Help: "Count of requests rejected by the throttling middleware.",
		}),
	}

	reg.MustRegister(
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.ErrorsTotal,
		m.ServiceCrashesTotal,
		m.EncryptDuration,
		m.DecryptDuration,
		m.UpstreamErrors,
		m.ThrottledTotal,
	)

	return m
}

// Registry returns the underlying prometheus Registry. Used by tests.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// Handler returns an http.Handler serving the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Registry: m.registry})
}

// RouteLabel normalises the request path for low-cardinality Prometheus labels.
//
// Object paths like "/my-bucket/path/to/key" collapse to "/:bucket/:key", while
// named endpoints are preserved verbatim.
func RouteLabel(path string) string {
	switch path {
	case "/healthz", "/readyz", MetricsPath:
		return path
	}
	if strings.Count(path, "/") >= 2 && strings.HasPrefix(path, "/") {
		return "/:bucket/:key"
	}
	return "other"
}

// Instrument wraps next with counters and a latency histogram. The status code is
// captured via a lightweight ResponseWriter wrapper.
func (m *Metrics) Instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := RouteLabel(r.URL.Path)

		sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		defer func() {
			if rec := recover(); rec != nil {
				m.ServiceCrashesTotal.Inc()
				http.Error(sw, "internal server error", http.StatusInternalServerError)
			}
			duration := time.Since(start).Seconds()
			m.HTTPRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(sw.status)).Inc()
			m.HTTPRequestDuration.WithLabelValues(r.Method, route).Observe(duration)
		}()

		next.ServeHTTP(sw, r)
	})
}

// statusRecorder captures the HTTP status code written by a handler so Instrument
// can publish it as a label.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(status int) {
	if s.wroteHeader {
		return
	}
	s.status = status
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}
