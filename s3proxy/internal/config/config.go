package config

import (
	"errors"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/env"
)

var k = koanf.New(".")

func LoadConfig() error {
	// Load environment variables with the `S3PROXY_` prefix and replace `_` with `.`
	return k.Load(env.Provider("S3PROXY_", ".", func(s string) string {
		return strings.ToLower(strings.ReplaceAll(s, "_", "."))
	}), nil)
}

func GetHostConfig() (string, error) {
	// Ensure loading was successful before calling Get
	if !k.Exists("s3proxy.host") {
		return "", errors.New("unable to get 'S3PROXY_HOST' env var")
	}
	return k.String("s3proxy.host"), nil
}

func GetDekTagName() string {
	// If the key "s3proxy.dektag.name" does not exist, return a default value
	if !k.Exists("s3proxy.dektag.name") {
		return "isec"
	}
	return k.String("s3proxy.dektag.name")
}

// GetKEKVersionTagName returns the S3 object-metadata key used to record which KEK
// derivation version was used to wrap the DEK. The tag is written on every new
// encryption; when absent on read, the legacy SHA-256 derivation is assumed.
// Defaults to "<dekTag>-kek-ver".
func GetKEKVersionTagName() string {
	const key = "s3proxy.dektag.kekver"
	if k.Exists(key) {
		return k.String(key)
	}
	return GetDekTagName() + "-kek-ver"
}

func GetEncryptKey() (string, error) {
	// Ensure loading was successful before calling Get
	if !k.Exists("s3proxy.encrypt.key") {
		return "", errors.New("unable to get 'S3PROXY_ENCRYPT_KEY' env var")
	}
	return k.String("s3proxy.encrypt.key"), nil
}

func GetThrottlingRequestsMax() int {
	return k.Int("s3proxy.throttling.requestsmax")
}
