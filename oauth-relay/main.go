// +scalingo install ./oauth-relay
// +scalingo goVersion go1.24

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var (
	healthCheck = flag.Bool("health", false, "perform health check and exit")
	version     = "dev" // Set via ldflags during build
)

func main() {
	flag.Parse()

	// Handle health check flag for distroless container
	if *healthCheck {
		if err := performHealthCheck(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Load and validate configuration
	cfg, err := LoadConfig()
	if err != nil {
		slog.Error("configuration failed", "error", err)
		os.Exit(1)
	}

	// Setup structured logging with slog
	logLevel := parseLogLevel(cfg.LogLevel)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	slog.Info("starting OAuth relay service",
		"version", version,
		"port", cfg.Port,
		"environment", cfg.Environment,
		"redirect_uri", cfg.RedirectURI,
		"session_timeout", cfg.SessionTimeout.String(),
		"rate_limit", fmt.Sprintf("%d/%s (burst: %d)",
			cfg.RateLimitRequests, cfg.RateLimitWindow, cfg.RateLimitBurst),
	)

	// Parse templates
	templates, err := template.ParseGlob(filepath.Join("templates", "*.html"))
	if err != nil {
		slog.Error("failed to parse templates", "error", err)
		os.Exit(1)
	}

	// Initialize service with validated configuration
	service := &RelayService{
		clientID:     cfg.GoogleClientID,
		clientSecret: cfg.GoogleClientSecret,
		redirectURI:  cfg.RedirectURI,
		sessions:     NewSessionStore(cfg),
		config:       cfg,
		templates:    templates,
	}

	// Setup routes
	mux := http.NewServeMux()

	// Health check endpoint (with health-specific middleware)
	mux.HandleFunc("GET /health", withMiddleware(
		service.handleHealth,
		healthCheckMiddleware(),
		requestLogger(),
	))

	// Root endpoint
	mux.HandleFunc("GET /", withMiddleware(
		service.handleRoot,
		securityHeaders(),
		requestLogger(),
	))

	// OAuth2 endpoints with comprehensive security middleware
	mux.HandleFunc("GET /auth/init", withMiddleware(
		service.handleAuthInit,
		securityHeaders(),
		advancedRateLimiter(cfg),
		corsMiddleware(),
		requestLogger(),
	))

	mux.HandleFunc("GET /auth/callback", withMiddleware(
		service.handleCallback,
		securityHeaders(),
		requestLogger(),
	))

	mux.HandleFunc("GET /auth/poll/{sessionID}", withMiddleware(
		service.handlePoll,
		securityHeaders(),
		corsMiddleware(),
		requestLogger(),
	))

	mux.HandleFunc("POST /auth/refresh", withMiddleware(
		service.handleRefresh,
		securityHeaders(),
		advancedRateLimiter(cfg),
		corsMiddleware(),
		requestLogger(),
	))

	// Create secure server with enhanced configuration
	server := createSecureServer(cfg, mux)

	// Graceful shutdown could be added here in the future
	slog.Info("OAuth relay service ready", "addr", server.Addr)

	if err := server.ListenAndServe(); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func createSecureServer(cfg *Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: handler,

		// Timeouts to prevent slowloris and similar attacks
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       120 * time.Second,

		// Limit request sizes
		MaxHeaderBytes: 1 << 20, // 1 MB

		// TLS configuration for HTTPS (when using TLS termination)
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,

			// Secure cipher suites (Go 1.24+ automatically includes secure defaults)
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},

			// Prefer server cipher order for better security
			PreferServerCipherSuites: true,

			// Modern curve preferences
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},

			// Disable session tickets for better forward secrecy
			SessionTicketsDisabled: cfg.Environment == "production",
		},

		// Enable HTTP/2
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func performHealthCheck() error {
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	port := getEnvOrDefault("PORT", "8080")
	resp, err := client.Get(fmt.Sprintf("http://localhost:%s/health", port))
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Warn("failed to close health check response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	return nil
}
