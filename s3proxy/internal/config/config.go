// Package config loads and exposes s3proxy runtime configuration sourced from
// environment variables prefixed with S3PROXY_.
//
// The Config type holds a parsed instance suitable for dependency injection. The
// package-level helpers (LoadConfig, GetHostConfig, …) remain as a thin facade over
// an internal default Config so existing callers keep working; new code should
// prefer explicit *Config injection.
package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
)

// DefaultMultipartTTL is how long an idle buffered multipart session is retained
// before the Cleanup sweep evicts it and removes its on-disk parts.
const DefaultMultipartTTL = 24 * time.Hour

// Config holds every s3proxy runtime setting loaded from the environment.
type Config struct {
	k *koanf.Koanf
}

// Load parses S3PROXY_-prefixed environment variables into a new Config.
func Load() (*Config, error) {
	k := koanf.New(".")
	err := k.Load(env.Provider("S3PROXY_", ".", func(s string) string {
		return strings.ToLower(strings.ReplaceAll(s, "_", "."))
	}), nil)
	if err != nil {
		return nil, fmt.Errorf("loading env config: %w", err)
	}
	return &Config{k: k}, nil
}

// Host returns the S3 backend host. Returns an error when unset.
func (c *Config) Host() (string, error) {
	if !c.k.Exists("s3proxy.host") {
		return "", errors.New("unable to get 'S3PROXY_HOST' env var")
	}
	return c.k.String("s3proxy.host"), nil
}

// DekTagName returns the S3 object-metadata key used to store the encrypted DEK.
// Defaults to "isec" when unset.
func (c *Config) DekTagName() string {
	if !c.k.Exists("s3proxy.dektag.name") {
		return "isec"
	}
	return c.k.String("s3proxy.dektag.name")
}

// KEKVersionTagName returns the S3 object-metadata key used to record which KEK
// derivation version was used to wrap the DEK. Defaults to "<DekTag>-kek-ver".
func (c *Config) KEKVersionTagName() string {
	const key = "s3proxy.dektag.kekver"
	if c.k.Exists(key) {
		return c.k.String(key)
	}
	return c.DekTagName() + "-kek-ver"
}

// EncryptKey returns the raw KEK seed. Returns an error when unset.
func (c *Config) EncryptKey() (string, error) {
	if !c.k.Exists("s3proxy.encrypt.key") {
		return "", errors.New("unable to get 'S3PROXY_ENCRYPT_KEY' env var")
	}
	return c.k.String("s3proxy.encrypt.key"), nil
}

// ThrottlingRequestsMax returns the configured maximum concurrent request count
// (0 = disabled).
func (c *Config) ThrottlingRequestsMax() int {
	return c.k.Int("s3proxy.throttling.requestsmax")
}

// Insecure reports whether upstream S3 traffic should use http:// instead of the
// default https:// (set via S3PROXY_INSECURE=1). Intended for development and
// e2e tests against plaintext MinIO; production deployments should leave this off.
func (c *Config) Insecure() bool {
	return c.k.Bool("s3proxy.insecure")
}

// MaxPutBodySize returns the configured PutObject body cap in bytes. Falls back to
// DefaultMaxPutBodySize when S3PROXY_PUTBODY_MAX is unset, zero, or out of range.
func (c *Config) MaxPutBodySize() int64 {
	const key = "s3proxy.putbody.max"
	if !c.k.Exists(key) {
		return DefaultMaxPutBodySize
	}
	v := c.k.Int64(key)
	if v <= 0 || v > MaxObjectSize {
		return DefaultMaxPutBodySize
	}
	return v
}

// MultipartBufferDir returns the local directory used to buffer multipart upload
// parts (S3PROXY_MULTIPART_BUFFER_DIR). An empty string (the default) leaves
// buffer-mode multipart disabled.
func (c *Config) MultipartBufferDir() string {
	return c.k.String("s3proxy.multipart.buffer.dir")
}

// MultipartMaxSize returns the maximum assembled object size in bytes for a
// buffered multipart upload (S3PROXY_MULTIPART_MAX_SIZE). Falls back to
// MaxObjectSize when unset, non-positive, or larger than MaxObjectSize.
func (c *Config) MultipartMaxSize() int64 {
	const key = "s3proxy.multipart.max.size"
	if !c.k.Exists(key) {
		return MaxObjectSize
	}
	v := c.k.Int64(key)
	if v <= 0 || v > MaxObjectSize {
		return MaxObjectSize
	}
	return v
}

// MultipartTTL returns how long an idle buffered multipart session is retained
// before eviction (S3PROXY_MULTIPART_TTL). Falls back to DefaultMultipartTTL
// when unset, non-positive, or unparseable.
func (c *Config) MultipartTTL() time.Duration {
	const key = "s3proxy.multipart.ttl"
	if !c.k.Exists(key) {
		return DefaultMultipartTTL
	}
	v := c.k.Duration(key)
	if v <= 0 {
		return DefaultMultipartTTL
	}
	return v
}

// DecryptionFallback reports whether GetObject should retry decryption with an
// all-zero KEK when the configured KEK fails (S3PROXY_DECRYPTION_FALLBACK=1).
// Intended for one-shot migrations away from objects written without an
// encryption key; leave off in steady state.
func (c *Config) DecryptionFallback() bool {
	return c.k.Bool("s3proxy.decryption.fallback")
}

// ---------------------------------------------------------------------------
// Package-level compatibility shim. The default Config is populated by
// LoadConfig() and read by the GetX getters so existing call sites that do not
// thread a *Config continue to work.
// ---------------------------------------------------------------------------

//nolint:gochecknoglobals // default config survives the package-global koanf we replaced
var defaultConfig *Config

// LoadConfig loads the default package-level Config from the environment.
// Prefer Load() + explicit *Config injection in new code.
func LoadConfig() error {
	cfg, err := Load()
	if err != nil {
		return err
	}
	defaultConfig = cfg
	return nil
}

// Default returns the package-level Config initialised by LoadConfig. If LoadConfig
// has not been called (typical in tests) an empty Config is returned — getters that
// expose optional values fall back to their documented defaults, and getters that
// require env vars return errors.
func Default() *Config {
	if defaultConfig == nil {
		return &Config{k: koanf.New(".")}
	}
	return defaultConfig
}

// GetHostConfig returns the S3 backend host from the default config.
func GetHostConfig() (string, error) { return Default().Host() }

// GetDekTagName returns the DEK metadata tag from the default config.
func GetDekTagName() string { return Default().DekTagName() }

// GetKEKVersionTagName returns the KEK-version metadata tag from the default config.
func GetKEKVersionTagName() string { return Default().KEKVersionTagName() }

// GetEncryptKey returns the KEK seed from the default config.
func GetEncryptKey() (string, error) { return Default().EncryptKey() }

// GetThrottlingRequestsMax returns the throttling cap from the default config.
func GetThrottlingRequestsMax() int { return Default().ThrottlingRequestsMax() }

// GetMaxPutBodySize returns the PutObject body cap from the default config.
func GetMaxPutBodySize() int64 { return Default().MaxPutBodySize() }

// GetInsecure returns whether upstream S3 traffic should use http:// from the default config.
func GetInsecure() bool { return Default().Insecure() }

// GetDecryptionFallback returns the decryption-fallback flag from the default config.
func GetDecryptionFallback() bool { return Default().DecryptionFallback() }

// GetMultipartBufferDir returns the multipart buffer directory from the default config.
func GetMultipartBufferDir() string { return Default().MultipartBufferDir() }

// GetMultipartMaxSize returns the multipart max object size from the default config.
func GetMultipartMaxSize() int64 { return Default().MultipartMaxSize() }

// GetMultipartTTL returns the multipart session TTL from the default config.
func GetMultipartTTL() time.Duration { return Default().MultipartTTL() }
