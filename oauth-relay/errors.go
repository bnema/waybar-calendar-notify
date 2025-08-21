package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

type ErrorCode string

const (
	ErrInternal           ErrorCode = "INTERNAL_ERROR"
	ErrInvalidRequest     ErrorCode = "INVALID_REQUEST"
	ErrSessionExpired     ErrorCode = "SESSION_EXPIRED"
	ErrSessionNotFound    ErrorCode = "SESSION_NOT_FOUND"
	ErrRateLimit          ErrorCode = "RATE_LIMITED"
	ErrUnauthorized       ErrorCode = "UNAUTHORIZED"
	ErrTooManySessions    ErrorCode = "TOO_MANY_SESSIONS"
	ErrTooManySessionsIP  ErrorCode = "TOO_MANY_SESSIONS_PER_IP"
	ErrTokenExchangeFailed ErrorCode = "TOKEN_EXCHANGE_FAILED"
	ErrTokenRefreshFailed  ErrorCode = "TOKEN_REFRESH_FAILED"
	ErrInvalidState       ErrorCode = "INVALID_STATE"
)

var (
	ErrMaxSessionsReached    = errors.New("maximum sessions reached")
	ErrMaxSessionsPerIP      = errors.New("maximum sessions per IP reached")
	ErrInvalidSessionState   = errors.New("invalid session state")
	ErrSessionTimeout        = errors.New("session timeout")
	ErrInvalidOAuthResponse  = errors.New("invalid OAuth response")
	ErrMissingCredentials    = errors.New("missing OAuth credentials")
)

type ErrorResponse struct {
	Error   ErrorCode `json:"error"`
	Message string    `json:"message"`
	Code    int       `json:"code,omitempty"`
}

func handleError(w http.ResponseWriter, r *http.Request, code ErrorCode, status int, logMsg string, args ...any) {
	// Create request context for logging
	logArgs := []any{
		"error_code", code,
		"status", status,
		"method", r.Method,
		"path", r.URL.Path,
		"user_agent", r.Header.Get("User-Agent"),
		"remote_addr", extractRealIP(r),
	}
	logArgs = append(logArgs, args...)

	// Log detailed error internally
	slog.Error(logMsg, logArgs...)

	// Return sanitized error to client
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	response := ErrorResponse{
		Error:   code,
		Message: getPublicMessage(code),
		Code:    status,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("failed to encode error response", "error", err)
		// Fallback to plain text if JSON encoding fails
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func getPublicMessage(code ErrorCode) string {
	messages := map[ErrorCode]string{
		ErrInternal:           "An internal error occurred. Please try again later.",
		ErrInvalidRequest:     "The request is invalid or malformed.",
		ErrSessionExpired:     "Your session has expired. Please start a new authentication flow.",
		ErrSessionNotFound:    "Session not found or has expired.",
		ErrRateLimit:          "Too many requests. Please wait before trying again.",
		ErrUnauthorized:       "Unauthorized access.",
		ErrTooManySessions:    "Too many active sessions. Please wait and try again.",
		ErrTooManySessionsIP:  "Too many sessions from your IP address. Please wait and try again.",
		ErrTokenExchangeFailed: "Failed to exchange authorization code for tokens.",
		ErrTokenRefreshFailed:  "Failed to refresh access token.",
		ErrInvalidState:       "Invalid state parameter. Please start a new authentication flow.",
	}

	if msg, exists := messages[code]; exists {
		return msg
	}
	return "An error occurred."
}


func handleInternalError(w http.ResponseWriter, r *http.Request, err error, context string) {
	handleError(w, r, ErrInternal, http.StatusInternalServerError,
		"internal error in "+context, "error", err)
}

func handleValidationError(w http.ResponseWriter, r *http.Request, err error, field string) {
	handleError(w, r, ErrInvalidRequest, http.StatusBadRequest,
		"validation failed", "field", field, "error", err)
}

func handleRateLimitError(w http.ResponseWriter, r *http.Request, ip string, retryAfter int) {
	w.Header().Set("Retry-After", string(rune(retryAfter)))
	handleError(w, r, ErrRateLimit, http.StatusTooManyRequests,
		"rate limit exceeded", "client_ip", ip, "retry_after", retryAfter)
}

func handleSessionError(w http.ResponseWriter, r *http.Request, sessionID string, reason string) {
	code := ErrSessionNotFound
	if reason == "expired" {
		code = ErrSessionExpired
	}

	handleError(w, r, code, http.StatusNotFound,
		"session error", "session_id", sessionID, "reason", reason)
}

func sanitizeOAuthError(err error) ErrorCode {
	if err == nil {
		return ErrInternal
	}

	errStr := err.Error()
	
	// Map common OAuth errors to our error codes
	switch {
	case containsAny(errStr, []string{"invalid_grant", "invalid_code", "code_expired"}):
		return ErrInvalidState
	case containsAny(errStr, []string{"invalid_client", "unauthorized_client"}):
		return ErrUnauthorized
	case containsAny(errStr, []string{"invalid_request", "unsupported_grant_type"}):
		return ErrInvalidRequest
	case containsAny(errStr, []string{"temporarily_unavailable", "server_error"}):
		return ErrInternal
	default:
		return ErrTokenExchangeFailed
	}
}

func containsAny(str string, substrings []string) bool {
	for _, substr := range substrings {
		if contains(str, substr) {
			return true
		}
	}
	return false
}

func contains(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || 
		(len(str) > len(substr) && indexString(str, substr) >= 0))
}

func indexString(s, substr string) int {
	n := len(substr)
	if n == 0 {
		return 0
	}
	if n > len(s) {
		return -1
	}
	
	for i := 0; i <= len(s)-n; i++ {
		if s[i:i+n] == substr {
			return i
		}
	}
	return -1
}