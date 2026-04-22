/*
Copyright (c) Edgeless Systems GmbH
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/

/*
Package main parses command line flags and starts the s3proxy server.
*/
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/intrinsec/s3proxy/internal/config"
	"github.com/intrinsec/s3proxy/internal/monitoring"
	"github.com/intrinsec/s3proxy/internal/router"
	"github.com/intrinsec/s3proxy/internal/tracing"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	// defaultPort is the default port to listen on.
	defaultPort = 4433
	// defaultIP is the default IP to listen on.
	defaultIP = "0.0.0.0"
	// defaultRegion is the default AWS region to use.
	defaultRegion = "eu-west-1"
	// defaultCertLocation is the default location of the TLS certificate.
	defaultCertLocation = "/etc/s3proxy/certs"
	// defaultLogLevel is the default log level.
	defaultLogLevel = 0
	// serviceName identifies the proxy in traces and logs.
	serviceName = "s3proxy"
	// serviceVersion is the build version exposed on OTel traces.
	serviceVersion = "dev"
)

// logLevelVar controls the minimum log level at runtime.
var logLevelVar = new(slog.LevelVar)

func main() {
	log := newLogger()

	flags, err := parseFlags()
	if err != nil {
		fatal(log, "parsing flags", err)
	}

	setLogLevel(flags.logLevel)

	cfg, err := config.Load()
	if err != nil {
		fatal(log, "loading configuration", err)
	}

	if err := cfg.Validate(); err != nil {
		fatal(log, "configuration validation failed", err)
	}

	// Keep the default global Config populated for legacy call sites during the
	// transition to DI-based access.
	if err := config.LoadConfig(); err != nil {
		fatal(log, "populating default config", err)
	}

	if flags.forwardMultipartReqs {
		log.Warn("configured to forward multipart uploads, this may leak data to AWS")
	}

	if cfg.Insecure() {
		log.Warn("S3PROXY_INSECURE=1: upstream S3 traffic will use plaintext HTTP. Do NOT use in production; for local/test/demo purposes only")
	}

	ctx := context.Background()
	shutdownTracing, err := tracing.Setup(ctx, serviceName, serviceVersion)
	if err != nil {
		fatal(log, "setting up tracing", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(shutdownCtx); err != nil {
			log.Error("shutting down tracing", "error", err)
		}
	}()

	if err := runServer(flags, cfg, log); err != nil {
		fatal(log, "running server", err)
	}
}

// newLogger builds a JSON slog.Logger writing to stdout with a common service attribute.
// The handler is wrapped so active trace/span IDs from the request context are emitted alongside log records.
func newLogger() *slog.Logger {
	base := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevelVar})
	return slog.New(tracing.NewSpanContextHandler(base)).With("service", serviceName)
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error(msg, "error", err)
	os.Exit(1)
}

func setLogLevel(level int) {
	switch {
	case level <= -1:
		logLevelVar.Set(slog.LevelDebug)
	case level == 1:
		logLevelVar.Set(slog.LevelWarn)
	case level >= 2:
		logLevelVar.Set(slog.LevelError)
	default:
		logLevelVar.Set(slog.LevelInfo)
	}
}

func runServer(flags cmdFlags, cfg *config.Config, log *slog.Logger) error {
	log.Info("listening", "ip", flags.ip, "port", defaultPort, "region", flags.region)

	metrics := monitoring.New()

	routerInstance, err := router.New(context.Background(), flags.region, flags.forwardMultipartReqs, log, metrics)
	if err != nil {
		return fmt.Errorf("creating router: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle(monitoring.MetricsPath, metrics.Handler())
	mux.HandleFunc("/", routerInstance.Serve)

	var inner http.Handler = mux

	throttling := cfg.ThrottlingRequestsMax()
	if throttling != 0 {
		log.Info("Throttling is enable", "throttling_requestsmax", throttling)
		throttler := router.NewThrottlingMiddleware(throttling, 10*time.Second, metrics)
		base := inner
		// Health checks and /metrics bypass throttling so that liveness/readiness and
		// monitoring stay observable under overload.
		inner = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isHealthCheckRequest(r) || r.URL.Path == monitoring.MetricsPath {
				base.ServeHTTP(w, r)
				return
			}
			throttler.Throttle(base).ServeHTTP(w, r)
		})
	}

	hMdw := otelhttp.NewHandler(metrics.Instrument(inner), "s3proxy.http.serve",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + monitoring.RouteLabel(r.URL.Path)
		}),
	)

	server := http.Server{
		Addr:              fmt.Sprintf("%s:%d", flags.ip, defaultPort),
		Handler:           hMdw,
		ReadHeaderTimeout: 10 * time.Second,
		// Disable HTTP/2. Serving HTTP/2 will cause some clients to use HTTP/2.
		// It seems like AWS S3 does not support HTTP/2.
		// Having HTTP/2 enabled will at least cause the aws-sdk-go V1 copy-object operation to fail.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}

	// i.e. if TLS is enabled.
	if !flags.noTLS {
		cert, err := tls.LoadX509KeyPair(flags.certLocation+"/s3proxy.crt", flags.certLocation+"/s3proxy.key")
		if err != nil {
			return fmt.Errorf("loading TLS certificate: %w", err)
		}

		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// TLSConfig is populated, so we can safely pass empty strings to ListenAndServeTLS.
		if err := server.ListenAndServeTLS("", ""); err != nil {
			return fmt.Errorf("listen and serve TLS: %w", err)
		}
		return nil
	}

	log.Warn("TLS is disabled")
	if err := server.ListenAndServe(); err != nil {
		return fmt.Errorf("listen and serve: %w", err)
	}
	return nil
}

func isHealthCheckRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz")
}

func parseFlags() (cmdFlags, error) {
	noTLS := flag.Bool("no-tls", false, "disable TLS and listen on port 80, otherwise listen on 443")
	ip := flag.String("ip", defaultIP, "ip to listen on")
	region := flag.String("region", defaultRegion, "AWS region in which target bucket is located")
	certLocation := flag.String("cert", defaultCertLocation, "location of TLS certificate")
	forwardMultipartReqs := flag.Bool("allow-multipart", false, "forward multipart requests to the target bucket; beware: this may store unencrypted data on AWS. See the documentation for more information")
	level := flag.Int("level", defaultLogLevel, "log level")

	flag.Parse()

	netIP := net.ParseIP(*ip)
	if netIP == nil {
		return cmdFlags{}, fmt.Errorf("not a valid IPv4 address: %s", *ip)
	}

	return cmdFlags{
		noTLS:                *noTLS,
		ip:                   netIP.String(),
		region:               *region,
		certLocation:         *certLocation,
		forwardMultipartReqs: *forwardMultipartReqs,
		logLevel:             *level,
	}, nil
}

type cmdFlags struct {
	noTLS                bool
	ip                   string
	region               string
	certLocation         string
	forwardMultipartReqs bool
	logLevel             int
}
