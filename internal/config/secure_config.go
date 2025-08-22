package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bnema/waybar-calendar-notify/internal/security"
)

// SecureConfig holds security-related configuration options
type SecureConfig struct {
	RelayURL           string
	AllowedRelayHosts  []string
	EnableCertPinning  bool
	TokenEncryption    bool
	MaxTokenAge        time.Duration
	EnableSecureLogging bool
	LogLevel           string
	CSRFTokenLifetime  time.Duration
	RequestTimeout     time.Duration
}

// DefaultSecureConfig returns the default secure configuration
func DefaultSecureConfig() *SecureConfig {
	return &SecureConfig{
		RelayURL:            "https://gcal-oauth-relay.bnema.dev",
		AllowedRelayHosts:   []string{"gcal-oauth-relay.bnema.dev", "localhost"},
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
	if relayURL := os.Getenv("WAYBAR_RELAY_URL"); relayURL != "" {
		config.RelayURL = relayURL
	}

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
	// Validate relay URL
	if err := sc.validateRelayURL(); err != nil {
		return err
	}

	// Validate allowed hosts
	if len(sc.AllowedRelayHosts) == 0 {
		return security.NewConfigError("AllowedRelayHosts", "", "must specify at least one allowed relay host")
	}

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

// validateRelayURL validates the relay URL configuration
func (sc *SecureConfig) validateRelayURL() error {
	if sc.RelayURL == "" {
		return security.NewConfigError("RelayURL", "", "relay URL cannot be empty")
	}

	parsedURL, err := url.Parse(sc.RelayURL)
	if err != nil {
		return security.NewConfigError("RelayURL", sc.RelayURL, "invalid URL format").WithCause(err)
	}

	// Ensure HTTPS in production environments
	if parsedURL.Scheme != "https" && parsedURL.Hostname() != "localhost" {
		return security.NewConfigError("RelayURL", sc.RelayURL, 
			"must use HTTPS for non-localhost hosts")
	}

	// Validate scheme
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return security.NewConfigError("RelayURL", sc.RelayURL, 
			"scheme must be http or https")
	}

	// Check against allowlist
	hostname := parsedURL.Hostname()
	if !sc.isAllowedHost(hostname) {
		return security.NewConfigError("RelayURL", sc.RelayURL, 
			fmt.Sprintf("host '%s' not in allowlist: %v", hostname, sc.AllowedRelayHosts))
	}

	// Validate port if specified
	if port := parsedURL.Port(); port != "" {
		// Only allow standard ports and development ports
		allowedPorts := []string{"80", "443", "8080", "8443", "3000"}
		if !contains(allowedPorts, port) {
			return security.NewConfigError("RelayURL", sc.RelayURL, 
				fmt.Sprintf("port '%s' not allowed", port))
		}
	}

	return nil
}

// isAllowedHost checks if a hostname is in the allowlist
func (sc *SecureConfig) isAllowedHost(hostname string) bool {
	for _, allowed := range sc.AllowedRelayHosts {
		if hostname == allowed {
			return true
		}
		// Allow subdomains of allowed hosts (with caution)
		if strings.HasSuffix(hostname, "."+allowed) {
			return true
		}
	}
	return false
}

// GetRelayURL returns the validated relay URL
func (sc *SecureConfig) GetRelayURL() string {
	return sc.RelayURL
}

// IsDevelopmentMode checks if we're running in development mode
func (sc *SecureConfig) IsDevelopmentMode() bool {
	parsedURL, err := url.Parse(sc.RelayURL)
	if err != nil {
		return false
	}
	return parsedURL.Hostname() == "localhost" || 
		   strings.HasPrefix(parsedURL.Hostname(), "127.") ||
		   parsedURL.Hostname() == "::1"
}

// GetCertificatePins returns certificate pins for known hosts
func (sc *SecureConfig) GetCertificatePins() map[string]string {
	pins := make(map[string]string)
	
	// Only enable pinning for production hosts
	if sc.EnableCertPinning && !sc.IsDevelopmentMode() {
		pins["gcal-oauth-relay.bnema.dev"] = "sha256:REPLACE_WITH_ACTUAL_CERT_FINGERPRINT"
	}
	
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
		"relay_url":            security.RedactString(sc.RelayURL),
		"allowed_relay_hosts":  sc.AllowedRelayHosts,
		"enable_cert_pinning":  sc.EnableCertPinning,
		"token_encryption":     sc.TokenEncryption,
		"max_token_age":        sc.MaxTokenAge.String(),
		"enable_secure_logging": sc.EnableSecureLogging,
		"log_level":            sc.LogLevel,
		"csrf_token_lifetime":  sc.CSRFTokenLifetime.String(),
		"request_timeout":      sc.RequestTimeout.String(),
		"development_mode":     sc.IsDevelopmentMode(),
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