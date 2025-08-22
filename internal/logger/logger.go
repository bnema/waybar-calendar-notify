package logger

import (
	"context"
	"log/slog"
	"os"
)

var (
	globalLogger *slog.Logger
	verboseMode  bool
)

// Init initializes the global logger with verbose mode setting
func Init(verbose bool) {
	verboseMode = verbose

	if verbose {
		opts := &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}
		globalLogger = slog.New(slog.NewTextHandler(os.Stderr, opts))
	} else {
		// Silent logger for non-verbose mode
		globalLogger = slog.New(&silentHandler{})
	}
	slog.SetDefault(globalLogger)
}

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

// Debug logs debug messages only in verbose mode
func Debug(msg string, args ...any) {
	if verboseMode {
		globalLogger.Debug(msg, args...)
	}
}

// Info logs info messages only in verbose mode
func Info(msg string, args ...any) {
	if verboseMode {
		globalLogger.Info(msg, args...)
	}
}

// Warn logs warning messages only in verbose mode
func Warn(msg string, args ...any) {
	if verboseMode {
		globalLogger.Warn(msg, args...)
	}
}

// Error always logs error messages regardless of verbose mode
func Error(msg string, args ...any) {
	// Create a separate error logger that always outputs
	if !verboseMode {
		errorLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelError,
		}))
		errorLogger.Error(msg, args...)
	} else {
		globalLogger.Error(msg, args...)
	}
}

// IsVerbose returns whether verbose mode is enabled
func IsVerbose() bool {
	return verboseMode
}