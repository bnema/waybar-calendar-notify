package security

import (
	"fmt"
)

// ErrorSeverity represents the severity level of security errors
type ErrorSeverity int

const (
	SeverityInfo ErrorSeverity = iota
	SeverityWarning
	SeverityCritical
)

func (s ErrorSeverity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// TokenError represents errors related to token operations
type TokenError struct {
	Operation string
	Message   string
	Err       error
}

func NewTokenError(operation, message string) *TokenError {
	return &TokenError{
		Operation: operation,
		Message:   message,
	}
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("token %s failed: %s", e.Operation, e.Message)
}

func (e *TokenError) Unwrap() error {
	return e.Err
}

func (e *TokenError) WithCause(err error) *TokenError {
	e.Err = err
	return e
}

// CryptoError represents errors from cryptographic operations
type CryptoError struct {
	Operation string
	Message   string
	Err       error
}

func NewCryptoError(operation, message string) *CryptoError {
	return &CryptoError{
		Operation: operation,
		Message:   message,
	}
}

func (e *CryptoError) Error() string {
	return fmt.Sprintf("crypto %s failed: %s", e.Operation, e.Message)
}

func (e *CryptoError) Unwrap() error {
	return e.Err
}

func (e *CryptoError) WithCause(err error) *CryptoError {
	e.Err = err
	return e
}

// TLSError represents TLS and certificate related errors
type TLSError struct {
	Operation string
	Host      string
	Message   string
	Err       error
}

func NewTLSError(operation, host, message string) *TLSError {
	return &TLSError{
		Operation: operation,
		Host:      host,
		Message:   message,
	}
}

func (e *TLSError) Error() string {
	if e.Host != "" {
		return fmt.Sprintf("TLS %s failed for %s: %s", e.Operation, e.Host, e.Message)
	}
	return fmt.Sprintf("TLS %s failed: %s", e.Operation, e.Message)
}

func (e *TLSError) Unwrap() error {
	return e.Err
}

func (e *TLSError) WithCause(err error) *TLSError {
	e.Err = err
	return e
}

// ConfigError represents configuration validation errors
type ConfigError struct {
	Field   string
	Value   string
	Message string
	Err     error
}

func NewConfigError(field, value, message string) *ConfigError {
	return &ConfigError{
		Field:   field,
		Value:   value,
		Message: message,
	}
}

func (e *ConfigError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("config validation failed for %s=%s: %s", e.Field, e.Value, e.Message)
	}
	return fmt.Sprintf("config validation failed for %s: %s", e.Field, e.Message)
}

func (e *ConfigError) Unwrap() error {
	return e.Err
}

func (e *ConfigError) WithCause(err error) *ConfigError {
	e.Err = err
	return e
}

// ValidationError represents input validation errors
type ValidationError struct {
	Field   string
	Value   string
	Message string
}

func NewValidationError(field, value, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	}
}

func (e *ValidationError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("validation failed for %s=%s: %s", e.Field, e.Value, e.Message)
	}
	return fmt.Sprintf("validation failed for %s: %s", e.Field, e.Message)
}

// IsRetryableError determines if an error is retryable
func IsRetryableError(err error) bool {
	switch err.(type) {
	case *TLSError:
		// Don't retry TLS errors as they indicate configuration issues
		return false
	case *CryptoError:
		// Don't retry crypto errors as they indicate data corruption
		return false
	default:
		return false
	}
}

// IsCriticalError determines if an error requires immediate attention
func IsCriticalError(err error) bool {
	switch err.(type) {
	case *TLSError:
		// TLS errors are always critical
		return true
	case *CryptoError:
		// Crypto errors are always critical
		return true
	default:
		return false
	}
}
