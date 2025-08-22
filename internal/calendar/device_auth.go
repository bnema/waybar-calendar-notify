package calendar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/bnema/waybar-calendar-notify/internal/nerdfonts"
	"github.com/bnema/waybar-calendar-notify/internal/security"
)

// CalendarScopes defines all necessary scopes for calendar access including shared calendars
var CalendarScopes = []string{
	"https://www.googleapis.com/auth/calendar.readonly", // Read access to all calendars and events including shared ones
}

// DeviceAuthManager handles OAuth 2.0 device flow authentication
type DeviceAuthManager struct {
	clientID     string
	clientSecret string
	tokenPath    string
	cacheDir     string
	httpClient   *http.Client
	encryptor    *security.TokenEncryptor
	logger       *security.SecureLogger
}

// DeviceCodeResponse represents the response from the device authorization endpoint
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// TokenResponse represents the response from the token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

// PollError represents an error during token polling
type PollError struct {
	ErrorCode   string
	Description string
}

func (e *PollError) Error() string {
	return fmt.Sprintf("poll error: %s - %s", e.ErrorCode, e.Description)
}

// ClientSecrets represents the structure of the OAuth client secrets JSON file
type ClientSecrets struct {
	Installed struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		AuthURI      string `json:"auth_uri"`
		TokenURI     string `json:"token_uri"`
	} `json:"installed"`
}

// NewDeviceAuthManager creates a new device authentication manager
func NewDeviceAuthManager(cacheDir, clientSecretsPath string, verbose bool) (*DeviceAuthManager, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Load client secrets
	secrets, err := LoadClientSecrets(clientSecretsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client secrets: %w", err)
	}

	// Initialize token encryptor
	encryptor, err := security.NewTokenEncryptor(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token encryption: %w", err)
	}

	// Initialize secure logger
	logger := security.NewSecureLogger(verbose)

	return &DeviceAuthManager{
		clientID:     secrets.Installed.ClientID,
		clientSecret: secrets.Installed.ClientSecret,
		tokenPath:    fmt.Sprintf("%s/token.enc", cacheDir),
		cacheDir:     cacheDir,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		encryptor:    encryptor,
		logger:       logger,
	}, nil
}

// AuthenticateDevice performs the complete OAuth 2.0 device flow
func (d *DeviceAuthManager) AuthenticateDevice(ctx context.Context) (*oauth2.Token, error) {
	d.logger.LogAuthEvent("device_auth_start", true, map[string]any{
		"client_id": security.RedactString(d.clientID),
	})

	// Step 1: Request device and user codes
	deviceResp, err := d.requestDeviceCode(ctx)
	if err != nil {
		d.logger.LogAuthEvent("device_code_request", false, map[string]any{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to request device code: %w", err)
	}

	d.logger.LogAuthEvent("device_code_received", true, map[string]any{
		"user_code":        deviceResp.UserCode,
		"expires_in":       deviceResp.ExpiresIn,
		"interval":         deviceResp.Interval,
		"verification_url": security.RedactString(deviceResp.VerificationURL),
	})

	// Step 2: Display user code and URL to user
	d.displayAuthInstructions(deviceResp)

	// Step 3: Poll for token
	token, err := d.pollForToken(ctx, deviceResp)
	if err != nil {
		d.logger.LogAuthEvent("device_auth_failed", false, map[string]any{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	d.logger.LogAuthEvent("device_auth_success", true, map[string]any{
		"has_refresh_token": token.RefreshToken != "",
	})

	return token, nil
}

// requestDeviceCode requests device and user codes from Google's device authorization endpoint
func (d *DeviceAuthManager) requestDeviceCode(ctx context.Context) (*DeviceCodeResponse, error) {
	params := url.Values{
		"client_id": {d.clientID},
		"scope":     {strings.Join(CalendarScopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/device/code", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			d.logger.Warn("Failed to close response body", "error", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			if errResp.Error == "rate_limit_exceeded" {
				return nil, fmt.Errorf("rate limit exceeded, please try again later")
			}
			return nil, fmt.Errorf("server error: %s - %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var deviceResp DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Validate response
	if deviceResp.DeviceCode == "" || deviceResp.UserCode == "" || deviceResp.VerificationURL == "" {
		return nil, fmt.Errorf("invalid device code response: missing required fields")
	}

	return &deviceResp, nil
}

// displayAuthInstructions shows the user what they need to do to complete authentication
func (d *DeviceAuthManager) displayAuthInstructions(deviceResp *DeviceCodeResponse) {
	fmt.Printf("\n%s Device Authentication Required\n", nerdfonts.InfoCircle)
	fmt.Printf("════════════════════════════════\n\n")
	fmt.Printf("%s Please visit: %s\n", nerdfonts.Globe, deviceResp.VerificationURL)
	fmt.Printf("%s Enter code: %s\n\n", nerdfonts.InfoCircle, deviceResp.UserCode)
	
	if deviceResp.ExpiresIn > 0 {
		minutes := deviceResp.ExpiresIn / 60
		fmt.Printf("This code expires in %d minutes\n", minutes)
	}
	
	fmt.Printf("%s Waiting for authorization...\n\n", nerdfonts.Timer)
}

// pollForToken polls Google's token endpoint until the user completes authentication
func (d *DeviceAuthManager) pollForToken(ctx context.Context, deviceResp *DeviceCodeResponse) (*oauth2.Token, error) {
	ticker := time.NewTicker(time.Duration(deviceResp.Interval) * time.Second)
	defer ticker.Stop()

	deadline := time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)
	pollCount := 0

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		case <-ticker.C:
			pollCount++
			
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("device code expired after %d polls", pollCount)
			}

			token, err := d.exchangeDeviceCode(ctx, deviceResp.DeviceCode)
			if err != nil {
				var pollErr *PollError
				if errors.As(err, &pollErr) {
					switch pollErr.ErrorCode {
					case "authorization_pending":
						// User hasn't authorized yet, continue polling
						continue
					case "slow_down":
						// Google wants us to slow down, increase interval by 5 seconds
						ticker.Reset(time.Duration(deviceResp.Interval+5) * time.Second)
						d.logger.LogAuthEvent("poll_slow_down", true, map[string]any{
							"new_interval": deviceResp.Interval + 5,
							"poll_count":   pollCount,
						})
						continue
					case "access_denied":
						return nil, fmt.Errorf("user denied access")
					case "expired_token":
						return nil, fmt.Errorf("device code expired")
					default:
						return nil, fmt.Errorf("authentication error: %s", pollErr.Description)
					}
				}
				return nil, err
			}

			d.logger.LogAuthEvent("poll_success", true, map[string]any{
				"poll_count": pollCount,
			})

			return token, nil
		}
	}
}

// exchangeDeviceCode exchanges the device code for an access token
func (d *DeviceAuthManager) exchangeDeviceCode(ctx context.Context, deviceCode string) (*oauth2.Token, error) {
	params := url.Values{
		"client_id":     {d.clientID},
		"client_secret": {d.clientSecret},
		"device_code":   {deviceCode},
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/token", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			d.logger.Warn("Failed to close response body", "error", closeErr)
		}
	}()

	if resp.StatusCode == http.StatusOK {
		var tokenResp TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			return nil, fmt.Errorf("failed to decode token response: %w", err)
		}

		// Validate token response
		if tokenResp.AccessToken == "" || tokenResp.ExpiresIn <= 0 {
			return nil, fmt.Errorf("invalid token response: missing required fields")
		}

		return &oauth2.Token{
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			TokenType:    tokenResp.TokenType,
			Expiry:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		}, nil
	}

	// Handle error responses
	var errResp struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		return nil, fmt.Errorf("unexpected status code %d and failed to decode error", resp.StatusCode)
	}

	return nil, &PollError{
		ErrorCode:   errResp.Error,
		Description: errResp.ErrorDescription,
	}
}

// SaveToken saves the token using the same encryption as the relay flow
func (d *DeviceAuthManager) SaveToken(token *oauth2.Token) error {
	tokenData, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	d.logger.LogCryptoEvent("token_encrypt", false, "")

	// Encrypt token before saving
	encrypted, err := d.encryptor.Encrypt(tokenData)
	if err != nil {
		cryptoErr := security.NewCryptoError("token_encrypt", "failed to encrypt token").WithCause(err)
		d.logger.LogCryptoEvent("token_encrypt", false, cryptoErr.Error())
		return cryptoErr
	}

	// Save with restrictive permissions
	if err := os.WriteFile(d.tokenPath, []byte(encrypted), 0600); err != nil {
		return security.NewTokenError("save", "failed to write token file").WithCause(err)
	}

	d.logger.LogCryptoEvent("token_encrypt", true, "")
	d.logger.LogAuthEvent("token_saved", true, map[string]any{
		"token_path": d.tokenPath,
	})

	return nil
}

// GetOAuth2Client creates an OAuth2 client with the provided token
func (d *DeviceAuthManager) GetOAuth2Client(ctx context.Context, token *oauth2.Token) *http.Client {
	config := &oauth2.Config{
		ClientID:     d.clientID,
		ClientSecret: d.clientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       CalendarScopes,
	}

	return config.Client(ctx, token)
}

//garble:controlflow flatten_passes=1 junk_jumps=3
func LoadClientSecrets(path string) (*ClientSecrets, error) {
	// Try embedded secrets first if no path provided or path is "embedded"
	if path == "" || path == "embedded" {
		embeddedSecrets, err := LoadEmbeddedSecrets()
		if err == nil {
			return embeddedSecrets, nil
		}
		// If embedded fails and no path, return error
		if path == "" {
			return nil, fmt.Errorf("embedded secrets unavailable and no file path provided: %w", err)
		}
	}
	
	// Try file-based loading
	data, err := os.ReadFile(path)
	if err != nil {
		// Try embedded as final fallback if file doesn't exist
		if os.IsNotExist(err) {
			embeddedSecrets, embeddedErr := LoadEmbeddedSecrets()
			if embeddedErr == nil {
				return embeddedSecrets, nil
			}
		}
		return nil, fmt.Errorf("failed to read client secrets file '%s': %w", path, err)
	}

	var secrets ClientSecrets
	if err := json.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("failed to parse client secrets JSON: %w", err)
	}

	// Validate required fields
	if secrets.Installed.ClientID == "" {
		return nil, fmt.Errorf("client_id is missing from client secrets")
	}
	if secrets.Installed.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is missing from client secrets")
	}

	return &secrets, nil
}