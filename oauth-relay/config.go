package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	GoogleClientID     string
	GoogleClientSecret string
	RedirectURI        string
	Port              string
	LogLevel          string
	Environment       string
	SessionSecret     string
	MaxSessionsPerIP  int
	MaxTotalSessions  int
	RateLimitRequests int
	RateLimitBurst    int
	RateLimitWindow   time.Duration
	SessionTimeout    time.Duration
	AppName           string
	Region            string
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		Port:              getEnvOrDefault("PORT", "8080"),
		LogLevel:          getEnvOrDefault("LOG_LEVEL", "info"),
		Environment:       getEnvOrDefault("ENVIRONMENT", "production"),
		MaxSessionsPerIP:  getEnvIntOrDefault("MAX_SESSIONS_PER_IP", 5),
		MaxTotalSessions:  getEnvIntOrDefault("MAX_TOTAL_SESSIONS", 1000),
		RateLimitRequests: getEnvIntOrDefault("RATE_LIMIT_REQUESTS", 10),
		RateLimitBurst:    getEnvIntOrDefault("RATE_LIMIT_BURST", 20),
		RateLimitWindow:   getEnvDurationOrDefault("RATE_LIMIT_WINDOW", time.Hour),
		SessionTimeout:    getEnvDurationOrDefault("SESSION_TIMEOUT", 5*time.Minute),
		AppName:           os.Getenv("APP"),
		Region:            getEnvOrDefault("REGION", "osc-fr1"),
	}

	// Validate port
	if err := cfg.validatePort(); err != nil {
		return nil, fmt.Errorf("port validation failed: %w", err)
	}

	// Validate log level
	if err := cfg.validateLogLevel(); err != nil {
		return nil, fmt.Errorf("log level validation failed: %w", err)
	}

	// Validate OAuth credentials
	cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	
	if err := cfg.validateOAuthCredentials(); err != nil {
		return nil, fmt.Errorf("OAuth validation failed: %w", err)
	}

	// Auto-detect or validate redirect URI
	cfg.RedirectURI = os.Getenv("REDIRECT_URI")
	if cfg.RedirectURI == "" {
		cfg.RedirectURI = cfg.autoDetectRedirectURI()
	}
	
	if err := cfg.validateRedirectURI(); err != nil {
		return nil, fmt.Errorf("redirect URI validation failed: %w", err)
	}

	// Generate or validate session secret
	cfg.SessionSecret = os.Getenv("SESSION_SECRET")
	if cfg.SessionSecret == "" {
		cfg.SessionSecret = generateSecureToken(32)
		if cfg.Environment == "production" {
			slog.Warn("SESSION_SECRET not set in production - using generated secret (not persistent across restarts)")
		}
	} else if err := cfg.validateSessionSecret(); err != nil {
		return nil, fmt.Errorf("session secret validation failed: %w", err)
	}

	// Validate numeric limits
	if err := cfg.validateLimits(); err != nil {
		return nil, fmt.Errorf("limits validation failed: %w", err)
	}

	return cfg, nil
}

func (c *Config) validatePort() error {
	port, err := strconv.Atoi(c.Port)
	if err != nil {
		return fmt.Errorf("invalid port number: %s", c.Port)
	}
	
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got: %d", port)
	}
	
	// Check for privileged ports in production
	if c.Environment == "production" && port < 1024 {
		return fmt.Errorf("privileged port %d not recommended for production", port)
	}
	
	return nil
}

func (c *Config) validateLogLevel() error {
	validLevels := []string{"debug", "info", "warn", "error"}
	for _, level := range validLevels {
		if c.LogLevel == level {
			return nil
		}
	}
	return fmt.Errorf("invalid log level: %s (valid: %v)", c.LogLevel, validLevels)
}

func (c *Config) validateOAuthCredentials() error {
	if c.GoogleClientID == "" {
		return fmt.Errorf("GOOGLE_CLIENT_ID is required")
	}
	
	if c.GoogleClientSecret == "" {
		return fmt.Errorf("GOOGLE_CLIENT_SECRET is required")
	}
	
	// Validate Google OAuth client ID format
	clientIDRegex := regexp.MustCompile(`^\d+-[a-z0-9]+\.apps\.googleusercontent\.com$`)
	if !clientIDRegex.MatchString(c.GoogleClientID) {
		return fmt.Errorf("GOOGLE_CLIENT_ID has invalid format (should be *.apps.googleusercontent.com)")
	}
	
	// Basic client secret validation
	if len(c.GoogleClientSecret) < 20 {
		return fmt.Errorf("GOOGLE_CLIENT_SECRET appears invalid (too short)")
	}
	
	// Check for suspicious patterns in client secret
	if strings.Contains(c.GoogleClientSecret, " ") {
		return fmt.Errorf("GOOGLE_CLIENT_SECRET contains invalid characters")
	}
	
	return nil
}

func (c *Config) autoDetectRedirectURI() string {
	if c.AppName != "" {
		// Scalingo deployment
		return fmt.Sprintf("https://%s.%s.scalingo.io/auth/callback", c.AppName, c.Region)
	}
	
	// Local development
	scheme := "http"
	if c.Environment == "production" {
		scheme = "https"
	}
	
	return fmt.Sprintf("%s://localhost:%s/auth/callback", scheme, c.Port)
}

func (c *Config) validateRedirectURI() error {
	u, err := url.Parse(c.RedirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect URI format: %w", err)
	}
	
	// Validate scheme
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("redirect URI must use http or https scheme, got: %s", u.Scheme)
	}
	
	// In production, require HTTPS unless localhost
	if c.Environment == "production" && u.Scheme != "https" {
		if !isLocalhost(u.Hostname()) {
			return fmt.Errorf("redirect URI must use HTTPS in production (unless localhost)")
		}
	}
	
	// Validate hostname
	if u.Hostname() == "" {
		return fmt.Errorf("redirect URI must have a valid hostname")
	}
	
	// Validate path
	if !strings.HasSuffix(u.Path, "/auth/callback") {
		return fmt.Errorf("redirect URI must end with /auth/callback, got path: %s", u.Path)
	}
	
	// Check for suspicious query parameters
	if u.RawQuery != "" {
		return fmt.Errorf("redirect URI should not contain query parameters")
	}
	
	// Check for fragments
	if u.Fragment != "" {
		return fmt.Errorf("redirect URI should not contain fragments")
	}
	
	return nil
}

func (c *Config) validateSessionSecret() error {
	if len(c.SessionSecret) < 32 {
		return fmt.Errorf("session secret must be at least 32 characters long")
	}
	
	// Check entropy (rough estimation)
	if !hasGoodEntropy(c.SessionSecret) {
		return fmt.Errorf("session secret has poor entropy")
	}
	
	return nil
}

func (c *Config) validateLimits() error {
	if c.MaxSessionsPerIP < 1 || c.MaxSessionsPerIP > 100 {
		return fmt.Errorf("max sessions per IP must be between 1 and 100, got: %d", c.MaxSessionsPerIP)
	}
	
	if c.MaxTotalSessions < c.MaxSessionsPerIP || c.MaxTotalSessions > 100000 {
		return fmt.Errorf("max total sessions must be between %d and 100000, got: %d", 
			c.MaxSessionsPerIP, c.MaxTotalSessions)
	}
	
	if c.RateLimitRequests < 1 || c.RateLimitRequests > 10000 {
		return fmt.Errorf("rate limit requests must be between 1 and 10000, got: %d", c.RateLimitRequests)
	}
	
	if c.RateLimitBurst < c.RateLimitRequests {
		return fmt.Errorf("rate limit burst (%d) must be >= requests (%d)", 
			c.RateLimitBurst, c.RateLimitRequests)
	}
	
	if c.SessionTimeout < time.Minute || c.SessionTimeout > 24*time.Hour {
		return fmt.Errorf("session timeout must be between 1 minute and 24 hours, got: %v", c.SessionTimeout)
	}
	
	return nil
}


func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
		slog.Warn("invalid integer value for environment variable", "key", key, "value", value, "using_default", defaultValue)
	}
	return defaultValue
}

func getEnvDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
		slog.Warn("invalid duration value for environment variable", "key", key, "value", value, "using_default", defaultValue)
	}
	return defaultValue
}

func isLocalhost(hostname string) bool {
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return true
	}
	
	// Check if it's a private IP
	if ip := net.ParseIP(hostname); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	
	return false
}

func hasGoodEntropy(s string) bool {
	// Simple entropy check - look for variety in characters
	seen := make(map[rune]bool)
	for _, r := range s {
		seen[r] = true
	}
	
	// Require at least 16 unique characters in a 32+ char secret
	return len(seen) >= 16
}

func generateSecureToken(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("failed to generate secure token: %v", err))
	}
	return hex.EncodeToString(bytes)
}