package security

import (
	"context"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

// SecureLogger provides structured logging with automatic redaction of sensitive data

// silentHandler discards all log messages when verbose mode is disabled
type silentHandler struct{}

func (h *silentHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return false
}

func (h *silentHandler) Handle(_ context.Context, _ slog.Record) error {
	return nil
}

func (h *silentHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

func (h *silentHandler) WithGroup(_ string) slog.Handler {
	return h
}

type SecureLogger struct {
	logger  *slog.Logger
	verbose bool
}

// Sensitive data patterns that should be redacted from logs
var sensitivePatterns = []*regexp.Regexp{
	// OAuth tokens and authorization headers
	regexp.MustCompile(`(?i)(access_token|refresh_token|authorization)["':\s]*["']?([A-Za-z0-9\-._~+/]+=*)`),
	regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`),

	// API keys and secrets
	regexp.MustCompile(`(?i)(api_key|client_secret|client_id)["':\s]*["']?([A-Za-z0-9\-._~+/]{16,})`),

	// Session IDs and CSRF tokens
	regexp.MustCompile(`(?i)(session_id|csrf_token|nonce)["':\s]*["']?([A-Za-z0-9\-._~+/]{16,})`),

	// URLs with embedded tokens
	regexp.MustCompile(`(https?://[^\s]*[?&](?:token|key|secret)=)([A-Za-z0-9\-._~+/]+=*)`),

	// Email addresses (privacy)
	regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),

	// Potential passwords or passphrases
	regexp.MustCompile(`(?i)(password|passphrase|pwd)["':\s]*["']?([^\s"',]{8,})`),
}

// NewSecureLogger creates a new secure logger with redaction capabilities
func NewSecureLogger(verbose bool) *SecureLogger {
	var handler slog.Handler

	if verbose {
		opts := &slog.HandlerOptions{
			Level: slog.LevelInfo,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Apply redaction to string values
				if a.Value.Kind() == slog.KindString {
					a.Value = slog.StringValue(redactSensitiveData(a.Value.String()))
				}
				return a
			},
		}
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		// Silent handler for non-verbose mode
		handler = &silentHandler{}
	}

	return &SecureLogger{
		logger:  slog.New(handler),
		verbose: verbose,
	}
}

// NewSecureLoggerWithLevel creates a secure logger with specified log level
func NewSecureLoggerWithLevel(level slog.Level, verbose bool) *SecureLogger {
	var handler slog.Handler

	if verbose {
		opts := &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Value.Kind() == slog.KindString {
					a.Value = slog.StringValue(redactSensitiveData(a.Value.String()))
				}
				return a
			},
		}
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		// Silent handler for non-verbose mode
		handler = &silentHandler{}
	}

	return &SecureLogger{
		logger:  slog.New(handler),
		verbose: verbose,
	}
}

// Info logs an info level message with automatic redaction
func (sl *SecureLogger) Info(msg string, args ...any) {
	sl.logger.Info(msg, args...)
}

// Warn logs a warning level message with automatic redaction
func (sl *SecureLogger) Warn(msg string, args ...any) {
	sl.logger.Warn(msg, args...)
}

// Error logs an error level message with automatic redaction
func (sl *SecureLogger) Error(msg string, args ...any) {
	sl.logger.Error(msg, args...)
}

// Debug logs a debug level message with automatic redaction
func (sl *SecureLogger) Debug(msg string, args ...any) {
	sl.logger.Debug(msg, args...)
}

// LogSecurityEvent logs a security-related event with standard fields
func (sl *SecureLogger) LogSecurityEvent(event string, severity ErrorSeverity, details map[string]any) {
	attrs := []any{
		slog.String("event_type", "security"),
		slog.String("event", event),
		slog.String("severity", severity.String()),
	}

	// Add details as additional attributes
	for k, v := range details {
		attrs = append(attrs, slog.Any(k, v))
	}

	switch severity {
	case SeverityCritical:
		sl.logger.Error("Security event", attrs...)
	case SeverityWarning:
		sl.logger.Warn("Security event", attrs...)
	default:
		sl.logger.Info("Security event", attrs...)
	}
}

// LogAuthEvent logs authentication-related events
func (sl *SecureLogger) LogAuthEvent(operation string, success bool, details map[string]any) {
	attrs := []any{
		slog.String("event_type", "authentication"),
		slog.String("operation", operation),
		slog.Bool("success", success),
	}

	for k, v := range details {
		attrs = append(attrs, slog.Any(k, v))
	}

	if success {
		sl.logger.Info("Authentication event", attrs...)
	} else {
		sl.logger.Warn("Authentication event", attrs...)
	}
}

// LogNetworkEvent logs network-related events (requests, responses)
func (sl *SecureLogger) LogNetworkEvent(method, url string, statusCode int, duration string) {
	sl.logger.Info("Network event",
		slog.String("event_type", "network"),
		slog.String("method", method),
		slog.String("url", redactURLSecrets(url)),
		slog.Int("status_code", statusCode),
		slog.String("duration", duration),
	)
}

// LogCryptoEvent logs cryptographic operations
func (sl *SecureLogger) LogCryptoEvent(operation string, success bool, error string) {
	attrs := []any{
		slog.String("event_type", "crypto"),
		slog.String("operation", operation),
		slog.Bool("success", success),
	}

	if error != "" {
		attrs = append(attrs, slog.String("error", redactSensitiveData(error)))
	}

	if success {
		sl.logger.Info("Crypto event", attrs...)
	} else {
		sl.logger.Error("Crypto event", attrs...)
	}
}

// WithContext returns a logger with additional context fields
func (sl *SecureLogger) WithContext(attrs ...any) *SecureLogger {
	return &SecureLogger{
		logger: sl.logger.With(attrs...),
	}
}

// redactSensitiveData applies redaction patterns to remove sensitive information
func redactSensitiveData(input string) string {
	result := input

	for _, pattern := range sensitivePatterns {
		result = pattern.ReplaceAllStringFunc(result, func(match string) string {
			// For patterns with groups, preserve the first group and redact the second
			submatches := pattern.FindStringSubmatch(match)
			if len(submatches) >= 3 {
				return submatches[1] + "[REDACTED]"
			}
			// For patterns without groups, redact the entire match
			return "[REDACTED]"
		})
	}

	return result
}

// redactURLSecrets specifically handles URL parameter redaction
func redactURLSecrets(url string) string {
	// Split URL into base and query parts
	parts := strings.SplitN(url, "?", 2)
	if len(parts) < 2 {
		return url // No query parameters
	}

	baseURL := parts[0]
	queryString := parts[1]

	// Redact sensitive query parameters
	queryString = regexp.MustCompile(`([?&](?:token|key|secret|code|state)=)[^&]*`).
		ReplaceAllString(queryString, "${1}[REDACTED]")

	return baseURL + "?" + queryString
}

// RedactString is a utility function to redact sensitive data from any string
func RedactString(input string) string {
	return redactSensitiveData(input)
}

// IsLoggingEnabled checks if logging is enabled at the specified level
func (sl *SecureLogger) IsLoggingEnabled(level slog.Level) bool {
	return sl.logger.Enabled(context.Background(), level)
}
