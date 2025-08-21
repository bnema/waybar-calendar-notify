package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bnema/waybar-calendar-notify/internal/security"
)

// SecureConfig holds security-related configuration options
type SecureConfig struct {
	EnableCertPinning   bool
	TokenEncryption     bool
	MaxTokenAge         time.Duration
	EnableSecureLogging bool
	LogLevel            string
	CSRFTokenLifetime   time.Duration
	RequestTimeout      time.Duration
}

// DefaultSecureConfig returns the default secure configuration
func DefaultSecureConfig() *SecureConfig {
	return &SecureConfig{
		EnableCertPinning:   true,
		TokenEncryption:     true,
		MaxTokenAge:         24 * time.Hour,
		EnableSecureLogging: true,
		LogLevel:            "info",
		CSRFTokenLifetime:   30 * time.Minute,
		RequestTimeout:      30 * time.Second,
	}
}

// LoadSecureConfig loads and validates security configuration
func LoadSecureConfig() (*SecureConfig, error) {
	config := DefaultSecureConfig()

	// Override with environment variables if present

	if pinning := os.Getenv("WAYBAR_CERT_PINNING"); pinning != "" {
		config.EnableCertPinning = strings.ToLower(pinning) == "true"
	}

	if encryption := os.Getenv("WAYBAR_TOKEN_ENCRYPTION"); encryption != "" {
		config.TokenEncryption = strings.ToLower(encryption) == "true"
	}

	if logLevel := os.Getenv("WAYBAR_LOG_LEVEL"); logLevel != "" {
		config.LogLevel = strings.ToLower(logLevel)
	}

	if timeout := os.Getenv("WAYBAR_REQUEST_TIMEOUT"); timeout != "" {
		if duration, err := time.ParseDuration(timeout); err == nil {
			config.RequestTimeout = duration
		}
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// Validate performs comprehensive validation of the security configuration
func (sc *SecureConfig) Validate() error {
	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLogLevels, sc.LogLevel) {
		return security.NewConfigError("LogLevel", sc.LogLevel, 
			fmt.Sprintf("must be one of: %s", strings.Join(validLogLevels, ", ")))
	}

	// Validate timeouts
	if sc.RequestTimeout < 5*time.Second {
		return security.NewConfigError("RequestTimeout", sc.RequestTimeout.String(), 
			"must be at least 5 seconds")
	}

	if sc.RequestTimeout > 5*time.Minute {
		return security.NewConfigError("RequestTimeout", sc.RequestTimeout.String(), 
			"must not exceed 5 minutes")
	}

	if sc.CSRFTokenLifetime < 5*time.Minute {
		return security.NewConfigError("CSRFTokenLifetime", sc.CSRFTokenLifetime.String(), 
			"must be at least 5 minutes")
	}

	if sc.MaxTokenAge < 1*time.Hour {
		return security.NewConfigError("MaxTokenAge", sc.MaxTokenAge.String(), 
			"must be at least 1 hour")
	}

	return nil
}


// GetCertificatePins returns certificate pins for known hosts
func (sc *SecureConfig) GetCertificatePins() map[string]string {
	pins := make(map[string]string)
	
	// Certificate pinning is not required for Google OAuth endpoints
	// as they use standard trusted CAs. This method exists for potential
	// future use with custom endpoints.
	
	return pins
}

// GetSecurityHeaders returns standard security headers for requests
func (sc *SecureConfig) GetSecurityHeaders() map[string]string {
	return map[string]string{
		"User-Agent":                "waybar-calendar-notify/1.0",
		"Accept":                    "application/json",
		"Cache-Control":             "no-cache",
		"X-Requested-With":          "waybar-calendar-notify",
		"Sec-Fetch-Dest":           "empty",
		"Sec-Fetch-Mode":           "cors",
		"Sec-Fetch-Site":           "cross-site",
	}
}

// CreateTLSConfig creates a secure TLS configuration based on the config
func (sc *SecureConfig) CreateTLSConfig() *TLSConfig {
	return &TLSConfig{
		MinVersion:         "1.2",
		EnableCertPinning:  sc.EnableCertPinning,
		CertificatePins:    sc.GetCertificatePins(),
		DisableCompression: true,
		RequireSNI:        true,
	}
}

// Sanitize returns a copy of the config with sensitive values redacted for logging
func (sc *SecureConfig) Sanitize() map[string]interface{} {
	return map[string]interface{}{
		"enable_cert_pinning":   sc.EnableCertPinning,
		"token_encryption":      sc.TokenEncryption,
		"max_token_age":         sc.MaxTokenAge.String(),
		"enable_secure_logging": sc.EnableSecureLogging,
		"log_level":             sc.LogLevel,
		"csrf_token_lifetime":   sc.CSRFTokenLifetime.String(),
		"request_timeout":       sc.RequestTimeout.String(),
	}
}

// contains checks if a slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// TLSConfig represents TLS configuration options
type TLSConfig struct {
	MinVersion         string
	EnableCertPinning  bool
	CertificatePins    map[string]string
	DisableCompression bool
	RequireSNI        bool
}