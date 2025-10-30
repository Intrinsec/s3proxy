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
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/intrinsec/s3proxy/internal/config"
	"github.com/intrinsec/s3proxy/internal/router"
	logger "github.com/sirupsen/logrus"
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
)

func main() {
	flags, err := parseFlags()
	if err != nil {
		panic(err)
	}

	// logLevel can be made a public variable so logging level can be changed dynamically.
	// TODO (derpsteb): enable once we are on go 1.21.
	// logLevel := new(slog.LevelVar)
	// handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	// logger := slog.New(handler)
	// logLevel.Set(flags.logLevel)

	log := logger.New()
	// log.SetFormatter(&logger.JSONFormatter{})
	switch {
	case flags.logLevel <= -1:
		log.SetLevel(logger.DebugLevel)
	case flags.logLevel == 0:
		log.SetLevel(logger.InfoLevel)
	case flags.logLevel == 1:
		log.SetLevel(logger.WarnLevel)
	case flags.logLevel >= 2:
		log.SetLevel(logger.ErrorLevel)
	default:
		log.SetLevel(logger.InfoLevel)
	}

	if err := config.LoadConfig(); err != nil {
		panic(err)
	}

	// Validate configuration at startup
	if err := config.ValidateConfiguration(); err != nil {
		log.WithError(err).Fatal("configuration validation failed")
	}

	if flags.forwardMultipartReqs {
		log.Warn("configured to forward multipart uploads, this may leak data to AWS")
	}

	if err := runServer(flags, log); err != nil {
		panic(err)
	}
}

func runServer(flags cmdFlags, log *logger.Logger) error {
	log.WithField("ip", flags.ip).WithField("port", defaultPort).WithField("region", flags.region).Info("listening")

	routerInstance, err := router.New(flags.region, flags.forwardMultipartReqs, log)
	if err != nil {
		return fmt.Errorf("creating router: %w", err)
	}

	h := http.HandlerFunc(routerInstance.Serve)
	hMdw := h

	throttling := config.GetThrottlingRequestsMax()
	if throttling != 0 {
		log.WithField("throttling_requestsmax", throttling).Info("Throttling is enable")
		throttler := router.NewThrottlingMiddleware(throttling, 10*time.Second)
		// Explicitly convert h to http.Handler so it can be used with Throttle
		hMdw = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			throttler.Throttle(h).ServeHTTP(w, r)
		})
	}

	server := http.Server{
		Addr:    fmt.Sprintf("%s:%d", flags.ip, defaultPort),
		Handler: hMdw,
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
		return server.ListenAndServeTLS("", "")
	}

	log.Warn("TLS is disabled")
	return server.ListenAndServe()
}

func parseFlags() (cmdFlags, error) {
	noTLS := flag.Bool("no-tls", false, "disable TLS and listen on port 80, otherwise listen on 443")
	ip := flag.String("ip", defaultIP, "ip to listen on")
	region := flag.String("region", defaultRegion, "AWS region in which target bucket is located")
	certLocation := flag.String("cert", defaultCertLocation, "location of TLS certificate")
	kmsEndpoint := flag.String("kms", "key-service.kube-system:9000", "endpoint of the KMS service to get key encryption keys from")
	forwardMultipartReqs := flag.Bool("allow-multipart", false, "forward multipart requests to the target bucket; beware: this may store unencrypted data on AWS. See the documentation for more information")
	level := flag.Int("level", defaultLogLevel, "log level")

	flag.Parse()

	netIP := net.ParseIP(*ip)
	if netIP == nil {
		return cmdFlags{}, fmt.Errorf("not a valid IPv4 address: %s", *ip)
	}

	// TODO(derpsteb): enable once we are on go 1.21.
	// logLevel := new(slog.Level)
	// if err := logLevel.UnmarshalText([]byte(*level)); err != nil {
	// 	return cmdFlags{}, fmt.Errorf("parsing log level: %w", err)
	// }

	return cmdFlags{
		noTLS:                *noTLS,
		ip:                   netIP.String(),
		region:               *region,
		certLocation:         *certLocation,
		kmsEndpoint:          *kmsEndpoint,
		forwardMultipartReqs: *forwardMultipartReqs,
		logLevel:             *level,
	}, nil
}

type cmdFlags struct {
	noTLS                bool
	ip                   string
	region               string
	certLocation         string
	kmsEndpoint          string
	forwardMultipartReqs bool
	// TODO(derpsteb): enable once we are on go 1.21.
	// logLevel slog.Level
	logLevel int
}
