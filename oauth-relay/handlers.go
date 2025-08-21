package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

type RelayService struct {
	clientID     string
	clientSecret string
	redirectURI  string
	sessions     *SessionStore
	config       *Config
	templates    *template.Template
}

func (s *RelayService) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		slog.Error("failed to write health response", "error", err)
	}
}

func (s *RelayService) handleRoot(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"service": "waybar-calendar-notify OAuth2 Relay",
		"status":  "healthy",
		"docs":    "https://github.com/bnema/waybar-calendar-notify",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		slog.Error("failed to encode root response", "error", err)
	}
}

func (s *RelayService) handleAuthInit(w http.ResponseWriter, r *http.Request) {
	clientIP := extractRealIP(r)
	session, err := s.sessions.CreateWithIP(clientIP)
	if err != nil {
		if err == ErrMaxSessionsReached {
			handleError(w, r, ErrTooManySessions, http.StatusServiceUnavailable,
				"session limit reached", "client_ip", clientIP)
			return
		}
		if err == ErrMaxSessionsPerIP {
			handleError(w, r, ErrTooManySessionsIP, http.StatusTooManyRequests,
				"IP session limit reached", "client_ip", clientIP)
			return
		}
		handleInternalError(w, r, err, "session creation")
		return
	}

	// Generate PKCE code challenge
	h := sha256.New()
	h.Write([]byte(session.CodeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Build Google OAuth2 URL
	authURL := fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?"+
			"client_id=%s&"+
			"redirect_uri=%s&"+
			"response_type=code&"+
			"scope=%s&"+
			"state=%s&"+
			"code_challenge=%s&"+
			"code_challenge_method=S256&"+
			"access_type=offline&"+
			"prompt=consent",
		url.QueryEscape(s.clientID),
		url.QueryEscape(s.redirectURI),
		url.QueryEscape("https://www.googleapis.com/auth/calendar.readonly"),
		session.State,
		codeChallenge,
	)

	response := map[string]string{
		"auth_url":   authURL,
		"session_id": session.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("failed to encode auth init response", "error", err)
	}

	slog.Info("auth initiated", "session_id", session.ID)
}

func (s *RelayService) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		slog.Warn("invalid callback", "has_code", code != "", "has_state", state != "")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Find session by state using constant-time lookup
	targetSession, found := s.sessions.GetByState(state)
	if !found {
		handleError(w, r, ErrInvalidState, http.StatusBadRequest,
			"invalid state parameter", "state_length", len(state))
		return
	}

	// Exchange code for tokens
	tokens, err := s.exchangeCodeForTokens(code, targetSession.CodeVerifier)
	if err != nil {
		errorCode := sanitizeOAuthError(err)
		handleError(w, r, errorCode, http.StatusBadRequest,
			"OAuth token exchange failed", "session_id", targetSession.ID)
		return
	}

	targetSession.Tokens = tokens

	// Return success page using template
	w.Header().Set("Content-Type", "text/html")
	if err := s.templates.ExecuteTemplate(w, "success.html", nil); err != nil {
		slog.Error("failed to execute success template", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	slog.Info("auth callback successful", "session_id", targetSession.ID)
}

func (s *RelayService) handlePoll(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("sessionID")

	// Validate session ID format to prevent enumeration
	if len(sessionID) != 64 { // 32 bytes hex encoded
		handleError(w, r, ErrInvalidRequest, http.StatusBadRequest,
			"invalid session ID format", "id_length", len(sessionID))
		return
	}

	session, exists := s.sessions.Get(sessionID)
	if !exists {
		handleSessionError(w, r, sessionID, "not found")
		return
	}

	if session.Tokens == nil {
		// Still waiting for auth
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(map[string]string{
			"status": "pending",
		}); err != nil {
			slog.Error("failed to encode poll response", "error", err)
		}
		return
	}

	// Return tokens and delete session (one-time use)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(session.Tokens); err != nil {
		slog.Error("failed to encode tokens response", "error", err)
	}

	s.sessions.Delete(sessionID)

	slog.Info("tokens delivered", "session_id", sessionID)
}

func (s *RelayService) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, 1024) // 1KB max

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handleValidationError(w, r, err, "refresh_token")
		return
	}

	// Validate refresh token format
	if len(req.RefreshToken) < 10 {
		handleError(w, r, ErrInvalidRequest, http.StatusBadRequest,
			"invalid refresh token format", "token_length", len(req.RefreshToken))
		return
	}

	tokens, err := s.refreshAccessToken(req.RefreshToken)
	if err != nil {
		errorCode := sanitizeOAuthError(err)
		if errorCode == ErrUnauthorized {
			handleError(w, r, ErrTokenRefreshFailed, http.StatusUnauthorized,
				"refresh token invalid or expired")
		} else {
			handleError(w, r, errorCode, http.StatusBadRequest,
				"token refresh failed")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokens); err != nil {
		slog.Error("failed to encode refresh tokens response", "error", err)
	}

	slog.Info("token refreshed successfully")
}

func (s *RelayService) exchangeCodeForTokens(code, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {s.redirectURI},
	}

	resp, err := http.Post(
		"https://oauth2.googleapis.com/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Warn("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) // Limit error response size
		slog.Warn("OAuth token exchange failed", "status", resp.StatusCode, "body", string(body))
		return nil, ErrInvalidOAuthResponse
	}

	var tokens TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

func (s *RelayService) refreshAccessToken(refreshToken string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
		"refresh_token": {refreshToken},
		"grant_type":    {"refresh_token"},
	}

	resp, err := http.Post(
		"https://oauth2.googleapis.com/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Warn("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) // Limit error response size
		slog.Warn("OAuth token refresh failed", "status", resp.StatusCode, "body", string(body))
		return nil, ErrInvalidOAuthResponse
	}

	var tokens TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}
