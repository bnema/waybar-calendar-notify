package calendar

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/bnema/waybar-calendar-notify/internal/config"
	"github.com/bnema/waybar-calendar-notify/internal/security"
)

type AuthOptions struct {
	UseRelay bool   // Always true now
	RelayURL string // Optional override, defaults to production URL
}

type AuthManager struct {
	tokenPath    string
	cacheDir     string
	relayURL     string
	httpClient   *security.SecureHTTPClient
	encryptor    *security.TokenEncryptor
	logger       *security.SecureLogger
	config       *config.SecureConfig
	csrfToken    string
	sessionID    string
}

// Build-time injected relay URL
var RelayURL = "https://gcal-oauth-relay.bnema.dev" // Default, can be overridden with -ldflags

func NewAuthManager(cacheDir string, opts *AuthOptions) (*AuthManager, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Load secure configuration
	secureConfig, err := config.LoadSecureConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load secure config: %w", err)
	}

	// Override relay URL if provided in options
	relayURL := RelayURL
	if opts != nil && opts.RelayURL != "" {
		relayURL = opts.RelayURL
		secureConfig.RelayURL = relayURL
		
		// Revalidate config with new URL
		if err := secureConfig.Validate(); err != nil {
			return nil, fmt.Errorf("invalid relay URL: %w", err)
		}
	}

	// Initialize secure HTTP client
	httpClient, err := security.NewSecureHTTPClient(relayURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure HTTP client: %w", err)
	}

	// Initialize token encryptor
	encryptor, err := security.NewTokenEncryptor(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token encryption: %w", err)
	}

	// Initialize secure logger
	logger := security.NewSecureLogger()

	authManager := &AuthManager{
		tokenPath:  filepath.Join(cacheDir, "token.enc"), // .enc extension for encrypted tokens
		cacheDir:   cacheDir,
		relayURL:   relayURL,
		httpClient: httpClient,
		encryptor:  encryptor,
		logger:     logger,
		config:     secureConfig,
	}

	// Log initialization
	logger.LogSecurityEvent("auth_manager_initialized", security.SeverityInfo, map[string]any{
		"cache_dir":         cacheDir,
		"relay_url":         security.RedactString(relayURL),
		"token_encryption":  secureConfig.TokenEncryption,
		"cert_pinning":      secureConfig.EnableCertPinning,
	})

	return authManager, nil
}

func (a *AuthManager) GetClient(ctx context.Context) (*http.Client, error) {
	startTime := time.Now()
	
	token, err := a.loadToken()
	if err != nil {
		a.logger.LogAuthEvent("token_load", false, map[string]any{
			"error": err.Error(),
		})
		
		// No token, need full auth
		token, err = a.authenticateViaRelay(ctx)
		if err != nil {
			return nil, err
		}
		
		if err := a.saveToken(token); err != nil {
			a.logger.Error("Failed to save token after authentication", "error", err)
		}
	} else if !token.Valid() && token.RefreshToken != "" {
		a.logger.LogAuthEvent("token_refresh_attempt", true, map[string]any{
			"token_expired": true,
		})
		
		// Token expired, try refresh
		if err := a.RefreshToken(ctx); err != nil {
			a.logger.LogAuthEvent("token_refresh", false, map[string]any{
				"error": err.Error(),
			})
			
			// Refresh failed, need full re-auth
			token, err = a.authenticateViaRelay(ctx)
			if err != nil {
				return nil, err
			}
		} else {
			// Refresh succeeded, reload token
			token, _ = a.loadToken()
			a.logger.LogAuthEvent("token_refresh", true, nil)
		}
		
		if err := a.saveToken(token); err != nil {
			a.logger.Error("Failed to save token after refresh", "error", err)
		}
	} else if token.Valid() {
		a.logger.LogAuthEvent("token_load", true, map[string]any{
			"token_valid": true,
		})
	}

	// Create OAuth2 client with token
	config := &oauth2.Config{
		Endpoint: google.Endpoint,
	}
	
	duration := time.Since(startTime)
	a.logger.LogAuthEvent("client_created", true, map[string]any{
		"duration": duration.String(),
	})

	return config.Client(ctx, token), nil
}

func (a *AuthManager) authenticateViaRelay(ctx context.Context) (*oauth2.Token, error) {
	a.logger.LogAuthEvent("relay_auth_start", true, map[string]any{
		"relay_url": security.RedactString(a.relayURL),
	})

	// Generate CSRF token for this session
	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(csrfBytes); err != nil {
		return nil, security.NewCryptoError("csrf_generation", "failed to generate CSRF token").WithCause(err)
	}
	a.csrfToken = base64.URLEncoding.EncodeToString(csrfBytes)

	// Step 1: Initialize session with CSRF protection
	initURL := fmt.Sprintf("%s/auth/init", a.relayURL)
	req, err := http.NewRequestWithContext(ctx, "GET", initURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create init request: %w", err)
	}

	// Add security headers
	for key, value := range a.config.GetSecurityHeaders() {
		req.Header.Set(key, value)
	}
	req.Header.Set("X-CSRF-Token", a.csrfToken)

	startTime := time.Now()
	resp, err := a.httpClient.Do(req)
	duration := time.Since(startTime)

	a.logger.LogNetworkEvent("GET", initURL, 0, duration.String())

	if err != nil {
		relayErr := security.NewRelayError("init", "failed to connect to relay service", 0, security.SeverityCritical).WithCause(err)
		a.logger.LogSecurityEvent("relay_connection_failed", security.SeverityCritical, map[string]any{
			"error": err.Error(),
			"url":   security.RedactString(initURL),
		})
		return nil, relayErr
	}
	defer resp.Body.Close()

	a.logger.LogNetworkEvent("GET", initURL, resp.StatusCode, duration.String())

	if resp.StatusCode != http.StatusOK {
		relayErr := security.NewRelayError("init", "relay service unavailable", resp.StatusCode, security.SeverityWarning)
		a.logger.LogSecurityEvent("relay_init_failed", security.SeverityWarning, map[string]any{
			"status_code": resp.StatusCode,
		})
		return nil, relayErr
	}

	// Validate and parse response
	var initResp struct {
		SessionID string `json:"session_id"`
		AuthURL   string `json:"auth_url"`
		CSRFToken string `json:"csrf_token"`
	}

	body := io.LimitReader(resp.Body, 1024*1024) // 1MB limit
	if err := json.NewDecoder(body).Decode(&initResp); err != nil {
		return nil, fmt.Errorf("invalid relay response: %w", err)
	}

	// Validate response fields
	if len(initResp.SessionID) < 16 || len(initResp.CSRFToken) < 16 {
		return nil, security.NewValidationError("session_data", "", "invalid security tokens from relay")
	}

	// Verify CSRF token matches (optional - some relays may not echo it back)
	if initResp.CSRFToken != "" && initResp.CSRFToken != a.csrfToken {
		return nil, security.NewValidationError("csrf_token", "", "CSRF token mismatch")
	}

	a.sessionID = initResp.SessionID

	// Step 2: Open browser
	fmt.Printf("Opening browser for authentication...\n")
	fmt.Printf("If browser doesn't open, visit: %s\n\n", initResp.AuthURL)

	// Try to open browser (ignore errors)
	exec.Command("xdg-open", initResp.AuthURL).Run()

	a.logger.LogAuthEvent("browser_opened", true, map[string]any{
		"session_id": initResp.SessionID[:8] + "...", // Log partial session ID
	})

	// Step 3: Poll for completion with secure implementation
	return a.pollForToken(ctx)
}

func (a *AuthManager) pollForToken(ctx context.Context) (*oauth2.Token, error) {
	pollCtx, cancel := context.WithTimeout(ctx, a.config.RequestTimeout*10) // Extended timeout for user interaction
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	pollURL := fmt.Sprintf("%s/auth/poll/%s", a.relayURL, a.sessionID)
	pollCount := 0
	maxPolls := 150 // 5 minutes at 2-second intervals

	a.logger.LogAuthEvent("polling_start", true, map[string]any{
		"poll_url": security.RedactString(pollURL),
		"timeout":  func() string {
			if deadline, ok := pollCtx.Deadline(); ok {
				return deadline.Format(time.RFC3339)
			}
			return "no deadline"
		}(),
	})

	for {
		select {
		case <-pollCtx.Done():
			a.logger.LogAuthEvent("polling_timeout", false, map[string]any{
				"poll_count": pollCount,
			})
			return nil, fmt.Errorf("authentication timeout: %w", pollCtx.Err())

		case <-ticker.C:
			pollCount++
			if pollCount > maxPolls {
				return nil, fmt.Errorf("maximum polling attempts exceeded")
			}

			req, err := http.NewRequestWithContext(pollCtx, "GET", pollURL, nil)
			if err != nil {
				continue // Retry on request creation errors
			}

			// Add security headers
			for key, value := range a.config.GetSecurityHeaders() {
				req.Header.Set(key, value)
			}
			req.Header.Set("X-CSRF-Token", a.csrfToken)

			startTime := time.Now()
			resp, err := a.httpClient.Do(req)
			duration := time.Since(startTime)

			if err != nil {
				a.logger.LogNetworkEvent("GET", pollURL, 0, duration.String())
				continue // Retry on network errors
			}

			token, done, pollErr := a.processPollResponse(resp, duration)
			resp.Body.Close()

			if pollErr != nil {
				a.logger.LogAuthEvent("poll_error", false, map[string]any{
					"error":      pollErr.Error(),
					"poll_count": pollCount,
				})
				continue // Retry on processing errors
			}

			if done {
				if token != nil {
					a.logger.LogAuthEvent("polling_success", true, map[string]any{
						"poll_count": pollCount,
						"duration":   time.Since(time.Now().Add(-time.Duration(pollCount)*2*time.Second)).String(),
					})
					return token, nil
				}
				a.logger.LogAuthEvent("polling_failed", false, map[string]any{
					"poll_count": pollCount,
				})
				return nil, fmt.Errorf("authentication failed")
			}
		}
	}
}

func (a *AuthManager) processPollResponse(resp *http.Response, duration time.Duration) (*oauth2.Token, bool, error) {
	a.logger.LogNetworkEvent("GET", "poll", resp.StatusCode, duration.String())

	switch resp.StatusCode {
	case http.StatusAccepted:
		return nil, false, nil // Still pending, continue polling

	case http.StatusOK:
		var tokens struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
		}

		body := io.LimitReader(resp.Body, 1024*1024) // 1MB limit
		if err := json.NewDecoder(body).Decode(&tokens); err != nil {
			return nil, true, fmt.Errorf("invalid token response: %w", err)
		}

		// Validate token format
		if len(tokens.AccessToken) < 10 || tokens.ExpiresIn <= 0 {
			return nil, true, security.NewValidationError("token_data", "", "invalid token format")
		}

		token := &oauth2.Token{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			TokenType:    "Bearer",
			Expiry:       time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
		}

		return token, true, nil

	default:
		return nil, true, security.NewRelayError("poll", "authentication failed", resp.StatusCode, security.SeverityWarning)
	}
}

func (a *AuthManager) loadToken() (*oauth2.Token, error) {
	encrypted, err := os.ReadFile(a.tokenPath)
	if err != nil {
		return nil, err
	}

	a.logger.LogCryptoEvent("token_decrypt", false, "")

	// Decrypt token
	decrypted, err := a.encryptor.Decrypt(string(encrypted))
	if err != nil {
		cryptoErr := security.NewCryptoError("token_decrypt", "failed to decrypt token").WithCause(err)
		a.logger.LogCryptoEvent("token_decrypt", false, cryptoErr.Error())
		return nil, cryptoErr
	}

	var token oauth2.Token
	if err := json.Unmarshal(decrypted, &token); err != nil {
		return nil, security.NewTokenError("unmarshal", "invalid token data").WithCause(err)
	}

	a.logger.LogCryptoEvent("token_decrypt", true, "")

	// Validate token age
	if time.Since(token.Expiry) > a.config.MaxTokenAge {
		return nil, security.NewTokenError("validation", "token too old")
	}

	return &token, nil
}

func (a *AuthManager) saveToken(token *oauth2.Token) error {
	tokenData, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	a.logger.LogCryptoEvent("token_encrypt", false, "")

	// Encrypt token before saving
	encrypted, err := a.encryptor.Encrypt(tokenData)
	if err != nil {
		cryptoErr := security.NewCryptoError("token_encrypt", "failed to encrypt token").WithCause(err)
		a.logger.LogCryptoEvent("token_encrypt", false, cryptoErr.Error())
		return cryptoErr
	}

	// Save with restrictive permissions
	if err := os.WriteFile(a.tokenPath, []byte(encrypted), 0600); err != nil {
		return security.NewTokenError("save", "failed to write token file").WithCause(err)
	}

	a.logger.LogCryptoEvent("token_encrypt", true, "")
	a.logger.LogAuthEvent("token_saved", true, map[string]any{
		"token_path": a.tokenPath,
	})

	return nil
}

func (a *AuthManager) RefreshToken(ctx context.Context) error {
	token, err := a.loadToken()
	if err != nil {
		return security.NewTokenError("refresh", "no token to refresh").WithCause(err)
	}

	// Prepare refresh request
	reqBody, _ := json.Marshal(map[string]string{
		"refresh_token": token.RefreshToken,
	})

	refreshURL := fmt.Sprintf("%s/auth/refresh", a.relayURL)
	req, err := http.NewRequestWithContext(ctx, "POST", refreshURL, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range a.config.GetSecurityHeaders() {
		req.Header.Set(key, value)
	}

	startTime := time.Now()
	resp, err := a.httpClient.Do(req)
	duration := time.Since(startTime)

	a.logger.LogNetworkEvent("POST", refreshURL, 0, duration.String())

	if err != nil {
		return security.NewRelayError("refresh", "refresh request failed", 0, security.SeverityWarning).WithCause(err)
	}
	defer resp.Body.Close()

	a.logger.LogNetworkEvent("POST", refreshURL, resp.StatusCode, duration.String())

	if resp.StatusCode != http.StatusOK {
		return security.NewRelayError("refresh", "refresh failed", resp.StatusCode, security.SeverityWarning)
	}

	var newTokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}

	body := io.LimitReader(resp.Body, 1024*1024) // 1MB limit
	if err := json.NewDecoder(body).Decode(&newTokens); err != nil {
		return fmt.Errorf("invalid refresh response: %w", err)
	}

	// Update stored token
	token.AccessToken = newTokens.AccessToken
	if newTokens.RefreshToken != "" {
		token.RefreshToken = newTokens.RefreshToken
	}
	token.Expiry = time.Now().Add(time.Duration(newTokens.ExpiresIn) * time.Second)

	return a.saveToken(token)
}

func (a *AuthManager) ClearLocalToken() error {
	if err := os.Remove(a.tokenPath); err != nil && !os.IsNotExist(err) {
		return security.NewTokenError("clear", "failed to remove token file").WithCause(err)
	}

	a.logger.LogAuthEvent("token_cleared", true, map[string]any{
		"token_path": a.tokenPath,
	})

	return nil
}

func (a *AuthManager) HasValidToken() bool {
	token, err := a.loadToken()
	isValid := err == nil && token.Valid()
	
	a.logger.LogAuthEvent("token_validation", isValid, map[string]any{
		"has_token": err == nil,
		"is_valid":  isValid,
	})
	
	return isValid
}