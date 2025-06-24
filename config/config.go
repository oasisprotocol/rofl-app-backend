// Package config provides configuration for the application.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/redis/go-redis/v9"
)

// Config is the main configuration for the application.
type Config struct {
	// Server is the configuration for the server.
	Server *ServerConfig `koanf:"server"`

	// Worker is the configuration for the worker.
	Worker *WorkerConfig `koanf:"worker"`

	// Log is the configuration for the logger.
	Log LogConfig `koanf:"log"`

	// Metrics is the configuration for the metrics.
	Metrics *MetricsConfig `koanf:"metrics"`
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.Server != nil {
		if err := c.Server.Validate(); err != nil {
			return err
		}
	}

	if c.Worker != nil {
		if err := c.Worker.Validate(); err != nil {
			return err
		}
	}

	if err := c.Log.Validate(); err != nil {
		return err
	}

	if c.Metrics != nil {
		if err := c.Metrics.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// ServerConfig is the configuration for the server.
type ServerConfig struct {
	// Endpoint is the address of the server.
	Endpoint string `koanf:"endpoint"`

	// AllowedOrigins is the list of allowed origins for the server.
	AllowedOrigins []string `koanf:"allowed_origins"`

	// RequestTimeout is the timeout for requests to the storage backend.
	// If unset, the default timeout is used.
	RequestTimeout *time.Duration `koanf:"request_timeout"`

	// Auth is the configuration for the authentication.
	Auth *AuthConfig `koanf:"auth"`

	// Redis is the configuration for the Redis client.
	Redis *RedisConfig `koanf:"redis"`

	// GCSConfig is the configuration for the GCS client.
	GCSConfig GCSConfig `koanf:"gcs"`
}

// Validate validates the server configuration.
func (c *ServerConfig) Validate() error {
	if c.Endpoint == "" {
		return errors.New("endpoint is required")
	}
	if c.RequestTimeout != nil && *c.RequestTimeout < 1*time.Second {
		return errors.New("request timeout must be greater than 1 second")
	}
	if c.Auth == nil {
		return errors.New("auth config is required")
	}
	if err := c.Auth.Validate(); err != nil {
		return err
	}
	if c.Redis == nil {
		return errors.New("redis config is required")
	}
	if err := c.Redis.Validate(); err != nil {
		return err
	}
	if err := c.GCSConfig.Validate(); err != nil {
		return err
	}
	return nil
}

// AuthConfig is the configuration for the authentication.
type AuthConfig struct {
	// SIWEDomain is the domain of the SIWE authentication.
	SIWEDomain string `koanf:"siwe_domain"`

	// SIWEChainID is the chain ID of the SIWE authentication.
	// If unset, chain ID is not checked.
	SIWEChainID int `koanf:"siwe_chain_id"`

	// SIWEVersion is the version of the SIWE authentication.
	// If unset, version is not checked.
	SIWEVersion string `koanf:"siwe_version"`

	// JWTSecret is the secret for the JWT token generation.
	JWTSecret string `koanf:"jwt_secret"`

	// RecaptchaSecret is the secret for the recaptcha verification.
	// If unset, recaptcha verification is not performed.
	RecaptchaSecret string `koanf:"recaptcha_secret"`
}

// Validate validates the authentication configuration.
func (c *AuthConfig) Validate() error {
	if c.SIWEDomain == "" {
		return errors.New("siwe domain is required")
	}
	if c.JWTSecret == "" {
		return errors.New("jwt secret is required")
	}
	if len(c.JWTSecret) < 32 {
		return errors.New("jwt secret must be at least 32 characters long")
	}
	return nil
}

// WorkerConfig is the configuration for the worker.
type WorkerConfig struct {
	// Redis is the configuration for the Redis client.
	Redis *RedisConfig `koanf:"redis"`

	// OasisCLIPath is the path to the Oasis CLI.
	OasisCLIPath *string `koanf:"oasis_cli_path"`

	// CacheDir is the directory to use for caching the Oasis CLI artifacts.
	// If unset, a new temporary directory is created on startup.
	CacheDir *string `koanf:"cache_dir"`
}

// Validate validates the worker configuration.
func (c *WorkerConfig) Validate() error {
	if c.Redis == nil {
		return errors.New("redis config is required")
	}
	if err := c.Redis.Validate(); err != nil {
		return err
	}
	return nil
}

// RedisConfig is the configuration for the Redis.
type RedisConfig struct {
	// Endpoint is the address of the Redis.
	Endpoint string `koanf:"endpoint"`
}

// Validate validates the Redis configuration.
func (c *RedisConfig) Validate() error {
	if c.Endpoint == "" {
		return errors.New("endpoint is required")
	}
	if _, err := redis.ParseURL(c.Endpoint); err != nil {
		return fmt.Errorf("invalid redis endpoint url: %w", err)
	}
	return nil
}

// GCSConfig is the configuration for the GCS client.
type GCSConfig struct {
	// Bucket is the name of the GCS bucket.
	Bucket string `koanf:"bucket"`

	// FakeGCSAddress is the address of the GCS server used in local development.
	FakeGCSAddress string `koanf:"fake_gcs_address"`
}

// Validate validates the GCS configuration.
func (c *GCSConfig) Validate() error {
	if c.Bucket == "" {
		return errors.New("bucket is required")
	}
	return nil
}

// LogConfig is the configuration for the logger.
type LogConfig struct {
	// Level is the level of the logger.
	Level string `koanf:"level"`

	// Format is the format of the logger.
	Format string `koanf:"format"`
}

// GetLoggerWithUnwind returns a logger with the source key unwound.
//
// The callDepth is the number of frames to unwind.
func (c *LogConfig) GetLoggerWithUnwind(callDepth int) *slog.Logger {
	level := slog.LevelInfo
	if c.Level != "" {
		// Validate ensures that the level is valid.
		_ = level.UnmarshalText([]byte(c.Level))
	}
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Nothing to unwind.
			if callDepth <= 0 {
				return a
			}
			// Only unwind the source key.
			if a.Key != slog.SourceKey {
				return a
			}

			// Unwind the source key.
			pc := make([]uintptr, 1)
			runtime.Callers(callDepth, pc)
			fs := runtime.CallersFrames([]uintptr{pc[0]})
			f, _ := fs.Next()
			source := &slog.Source{
				Function: f.Function,
				File:     f.File,
				Line:     f.Line,
			}

			return slog.Attr{
				Key:   a.Key,
				Value: slog.AnyValue(source),
			}
		},
	}

	var handler slog.Handler
	switch c.Format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	default:
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

// GetLogger returns the configured logger.
func (c *LogConfig) GetLogger() *slog.Logger {
	return c.GetLoggerWithUnwind(0)
}

// Validate validates the log configuration.
func (c *LogConfig) Validate() error {
	if c.Level != "" {
		var level slog.Level
		if err := level.UnmarshalText([]byte(c.Level)); err != nil {
			return fmt.Errorf("invalid log level: %w", err)
		}
	}
	if c.Format != "" {
		if c.Format != "json" && c.Format != "text" {
			return errors.New("invalid log format")
		}
	}
	return nil
}

// MetricsConfig contains the metrics configuration.
type MetricsConfig struct {
	// PullEndpoint is the address of the Prometheus pull endpoint.
	PullEndpoint string `koanf:"pull_endpoint"`
}

// Validate validates the metrics configuration.
func (c *MetricsConfig) Validate() error {
	if c.PullEndpoint == "" {
		return errors.New("pull endpoint is required")
	}
	return nil
}

func initConfig(p koanf.Provider) (*Config, error) {
	var config Config
	k := koanf.New(".")

	// Load configuration from the yaml config.
	if err := k.Load(p, yaml.Parser()); err != nil {
		return nil, err
	}
	// Load environment variables and merge into the loaded config.
	if err := k.Load(env.ProviderWithValue("", ".", func(key string, value string) (string, interface{}) {
		// `__` is used as a hierarchy delimiter.
		key = strings.ReplaceAll(strings.ToLower(key), "__", ".")

		return key, value
	}), nil); err != nil {
		return nil, err
	}

	// Unmarshal into config.
	if err := k.Unmarshal("", &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// InitConfig initializes configuration from file.
func InitConfig(f string) (*Config, error) {
	config, err := initConfig(file.Provider(f))
	if err != nil {
		return nil, err
	}
	// Validate config.
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}
