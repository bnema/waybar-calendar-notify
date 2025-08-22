package calendar

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/bnema/waybar-calendar-notify/internal/security"
)

// AuthManager handles OAuth authentication using device flow
type AuthManager struct {
	tokenPath  string
	cacheDir   string
	httpClient *security.SecureHTTPClient
	encryptor  *security.TokenEncryptor
	logger     *security.SecureLogger
	verbose    bool
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(cacheDir string, verbose bool) (*AuthManager, error) {
	if err := os.MkdirAll(cacheDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Initialize token encryptor
	encryptor, err := security.NewTokenEncryptor(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token encryption: %w", err)
	}

	// Initialize secure logger
	logger := security.NewSecureLogger(verbose)

	// Create a basic secure HTTP client for device flow (used for token refresh)
	httpClient, err := security.NewSecureHTTPClient("https://oauth2.googleapis.com")
	if err != nil {
		return nil, fmt.Errorf("failed to create secure HTTP client for device flow: %w", err)
	}

	authManager := &AuthManager{
		tokenPath:  filepath.Join(cacheDir, "token.enc"),
		cacheDir:   cacheDir,
		httpClient: httpClient,
		encryptor:  encryptor,
		logger:     logger,
		verbose:    verbose,
	}

	// Log initialization for device flow
	logger.LogSecurityEvent("auth_manager_initialized", security.SeverityInfo, map[string]any{
		"cache_dir":   cacheDir,
		"auth_method": "device_flow",
	})

	return authManager, nil
}

// GetClient returns an authenticated HTTP client
func (a *AuthManager) GetClient(ctx context.Context) (*http.Client, error) {
	startTime := time.Now()

	token, err := a.loadToken()
	if err != nil {
		a.logger.LogAuthEvent("token_load", false, map[string]any{
			"error": err.Error(),
		})

		// No token, need full auth via device flow
		token, err = a.authenticateViaDevice(ctx)
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

			// Refresh failed, need full re-auth via device flow
			token, err = a.authenticateViaDevice(ctx)
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
		ClientID: GoogleOAuthClientID,
		Endpoint: google.Endpoint,
		Scopes:   CalendarScopes,
	}

	duration := time.Since(startTime)
	a.logger.LogAuthEvent("client_created", true, map[string]any{
		"duration": duration.String(),
	})

	return config.Client(ctx, token), nil
}

// authenticateViaDevice performs device flow authentication
func (a *AuthManager) authenticateViaDevice(ctx context.Context) (*oauth2.Token, error) {
	a.logger.LogAuthEvent("device_auth_start", true, map[string]any{
		"client_id": security.RedactString(GoogleOAuthClientID),
	})

	// Initialize device auth manager (no client secrets needed)
	deviceAuth, err := NewDeviceAuthManager(a.cacheDir, a.verbose)
	if err != nil {
		a.logger.LogAuthEvent("device_auth_init", false, map[string]any{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to initialize device auth: %w", err)
	}

	// Perform device authentication
	token, err := deviceAuth.AuthenticateDevice(ctx)
	if err != nil {
		a.logger.LogAuthEvent("device_auth_failed", false, map[string]any{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("device authentication failed: %w", err)
	}

	a.logger.LogAuthEvent("device_auth_success", true, map[string]any{
		"has_refresh_token": token.RefreshToken != "",
	})

	return token, nil
}

// loadToken loads and decrypts the stored token
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

	return &token, nil
}

// saveToken encrypts and saves the token
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

// RefreshToken refreshes the OAuth token using the refresh token
func (a *AuthManager) RefreshToken(ctx context.Context) error {
	token, err := a.loadToken()
	if err != nil {
		return security.NewTokenError("refresh", "no token to refresh").WithCause(err)
	}

	if token.RefreshToken == "" {
		return security.NewTokenError("refresh", "no refresh token available")
	}

	// Use device flow refresh (no client_secret needed)
	return a.refreshTokenForDeviceFlow(ctx, token)
}

// refreshTokenForDeviceFlow refreshes tokens using device flow (no client_secret)
func (a *AuthManager) refreshTokenForDeviceFlow(ctx context.Context, token *oauth2.Token) error {
	a.logger.LogAuthEvent("device_token_refresh_start", true, map[string]any{
		"has_refresh_token": token.RefreshToken != "",
	})

	// Create refresh request to Google's token endpoint
	// For device flow, only client_id is needed, not client_secret
	params := url.Values{
		"client_id":     {GoogleOAuthClientID},
		"refresh_token": {token.RefreshToken},
		"grant_type":    {"refresh_token"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", TokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	startTime := time.Now()
	resp, err := a.httpClient.Do(req)
	duration := time.Since(startTime)

	a.logger.LogNetworkEvent("POST", TokenURL, 0, duration.String())

	if err != nil {
		a.logger.LogAuthEvent("device_token_refresh_failed", false, map[string]any{
			"error": err.Error(),
		})
		return fmt.Errorf("token refresh request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			a.logger.Warn("Failed to close response body", "error", closeErr)
		}
	}()

	a.logger.LogNetworkEvent("POST", TokenURL, resp.StatusCode, duration.String())

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}

		if decodeErr := json.NewDecoder(resp.Body).Decode(&errResp); decodeErr == nil {
			a.logger.LogAuthEvent("device_token_refresh_failed", false, map[string]any{
				"error":             errResp.Error,
				"error_description": errResp.ErrorDescription,
			})
			return fmt.Errorf("token refresh failed: %s - %s", errResp.Error, errResp.ErrorDescription)
		}
		return fmt.Errorf("token refresh failed with status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode refresh token response: %w", err)
	}

	// Validate response
	if tokenResp.AccessToken == "" || tokenResp.ExpiresIn <= 0 {
		return fmt.Errorf("invalid token refresh response: missing required fields")
	}

	// Update token
	token.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		token.RefreshToken = tokenResp.RefreshToken
	}
	token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	token.TokenType = tokenResp.TokenType

	a.logger.LogAuthEvent("device_token_refresh_success", true, map[string]any{
		"new_expiry": token.Expiry.Format(time.RFC3339),
	})

	return a.saveToken(token)
}

// ClearLocalToken removes the stored authentication token
func (a *AuthManager) ClearLocalToken() error {
	if err := os.Remove(a.tokenPath); err != nil && !os.IsNotExist(err) {
		return security.NewTokenError("clear", "failed to remove token file").WithCause(err)
	}

	a.logger.LogAuthEvent("token_cleared", true, map[string]any{
		"token_path": a.tokenPath,
	})

	return nil
}

// HasValidToken checks if a valid token exists
func (a *AuthManager) HasValidToken() bool {
	token, err := a.loadToken()
	isValid := err == nil && token.Valid()

	a.logger.LogAuthEvent("token_validation", isValid, map[string]any{
		"has_token": err == nil,
		"is_valid":  isValid,
	})

	return isValid
}

// Close cleans up resources and clears sensitive data from memory
func (a *AuthManager) Close() error {
	var errs []error

	// Close HTTP client connections if available
	if a.httpClient != nil {
		a.httpClient.Close()
	}

	// Clear encryptor (which may contain sensitive keys)
	a.encryptor = nil

	// Log cleanup completion
	if a.logger != nil {
		a.logger.LogSecurityEvent("auth_manager_closed", security.SeverityInfo, map[string]any{
			"cache_dir": a.cacheDir,
		})
	}

	// Clear logger reference
	a.logger = nil

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}
	return nil
}
