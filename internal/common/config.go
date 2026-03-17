// Package common provides shared configuration, logging, and metrics for Legit Flow.
package common

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds the central configuration for the gateway.
type Config struct {
	// Server
	ListenAddr  string `yaml:"listen_addr"`
	MetricsAddr string `yaml:"metrics_addr"`

	// LLM Backend
	LLMBackendURL string `yaml:"llm_backend_url"`

	// Classifier API — pluggable: external (OpenAI/Claude) or local ML endpoint
	ClassifierProvider string `yaml:"classifier_provider"` // "openai", "anthropic", "local", "disabled"
	ClassifierAPIURL   string `yaml:"classifier_api_url"`
	ClassifierAPIKey   string `yaml:"classifier_api_key"` // from env/secret, never in YAML
	ClassifierModel    string `yaml:"classifier_model"`   // e.g. "gpt-4o-mini", "claude-3-haiku", or local model name

	// Policy
	PolicyDir      string `yaml:"policy_dir"`
	PolicyReload   bool   `yaml:"policy_hot_reload"`

	// Audit
	AuditTier1Enabled bool   `yaml:"audit_tier1_enabled"`
	AuditTier2Enabled bool   `yaml:"audit_tier2_enabled"`
	AuditOutputDir    string `yaml:"audit_output_dir"`

	// Output Guard
	HoldbackWindowSize int `yaml:"holdback_window_size"` // number of tokens to buffer

	// Auth
	JWTSecret string `yaml:"jwt_secret"` // from env/secret

	// TLS
	TLSEnabled  bool   `yaml:"tls_enabled"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
}

// DefaultConfig returns a config with sensible defaults for local development.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:         envOrDefault("LEGIT_LISTEN_ADDR", ":8080"),
		MetricsAddr:        envOrDefault("LEGIT_METRICS_ADDR", ":9090"),
		LLMBackendURL:      envOrDefault("LEGIT_LLM_BACKEND_URL", "http://localhost:11434"),
		ClassifierProvider: envOrDefault("LEGIT_CLASSIFIER_PROVIDER", "disabled"),
		ClassifierAPIURL:   envOrDefault("LEGIT_CLASSIFIER_API_URL", ""),
		ClassifierAPIKey:   envOrDefault("LEGIT_CLASSIFIER_API_KEY", ""),
		ClassifierModel:    envOrDefault("LEGIT_CLASSIFIER_MODEL", ""),
		PolicyDir:          envOrDefault("LEGIT_POLICY_DIR", "./policies"),
		PolicyReload:       envOrDefaultBool("LEGIT_POLICY_HOT_RELOAD", true),
		AuditTier1Enabled:  envOrDefaultBool("LEGIT_AUDIT_TIER1", true),
		AuditTier2Enabled:  envOrDefaultBool("LEGIT_AUDIT_TIER2", true),
		AuditOutputDir:     envOrDefault("LEGIT_AUDIT_DIR", "./audit-logs"),
		HoldbackWindowSize: envOrDefaultInt("LEGIT_HOLDBACK_WINDOW", 5),
		JWTSecret:          envOrDefault("LEGIT_JWT_SECRET", "dev-secret-change-me"),
		TLSEnabled:         envOrDefaultBool("LEGIT_TLS_ENABLED", false),
		TLSCertFile:        envOrDefault("LEGIT_TLS_CERT", ""),
		TLSKeyFile:         envOrDefault("LEGIT_TLS_KEY", ""),
	}
}

// Validate checks that required fields are set.
func (c *Config) Validate() error {
	if c.LLMBackendURL == "" {
		return fmt.Errorf("llm_backend_url is required")
	}
	if c.ClassifierProvider != "disabled" && c.ClassifierAPIKey == "" {
		return fmt.Errorf("classifier_api_key is required when classifier is enabled (provider=%s)", c.ClassifierProvider)
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrDefaultBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return strings.EqualFold(v, "true") || v == "1"
}

func envOrDefaultInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
