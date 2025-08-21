package calendar

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gcal "google.golang.org/api/calendar/v3"
)

// Built-in OAuth2 client configuration for device flow
// According to Google's OAuth2 documentation for installed applications,
// client secrets cannot be kept truly secret and are embedded in the application.
// This is the standard approach for device flow applications.
const (
	// This is a placeholder - in a real application, the maintainer would provide
	// valid OAuth2 client credentials obtained from Google Cloud Console
	// For now, we'll use environment variables or require user-provided credentials
	defaultClientID     = ""  // To be set by environment variable or maintainer
	defaultClientSecret = ""  // To be set by environment variable or maintainer
)

type AuthFlow int

const (
	AuthFlowAuto AuthFlow = iota // Try device flow first, fallback to local server
	AuthFlowDeviceCode           // Force device flow
	AuthFlowLocalServer          // Force local server (current behavior)
	AuthFlowRelay                // Use relay service
)

type AuthOptions struct {
	Flow     AuthFlow
	CredPath string // Optional: custom credentials file path
	UseRelay bool   // New: Use relay service
	RelayURL string // New: Optional custom relay URL
}

type AuthManager struct {
	config     *oauth2.Config
	tokenPath  string
	credPath   string
	cacheDir   string
	flow       AuthFlow
	useBuiltIn bool
	useRelay   bool   // New: Use relay service
	relayURL   string // New: Relay service URL
}

// Device Flow response structures
type DeviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type DeviceTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

func NewAuthManager(cacheDir string, opts *AuthOptions) (*AuthManager, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	if opts == nil {
		opts = &AuthOptions{Flow: AuthFlowAuto}
	}

	tokenPath := filepath.Join(cacheDir, "token.json")
	
	am := &AuthManager{
		tokenPath: tokenPath,
		cacheDir:  cacheDir,
		flow:      opts.Flow,
		useRelay:  opts.UseRelay,
		relayURL:  opts.RelayURL,
	}

	// Set default relay URL if using relay but no URL provided
	if am.useRelay && am.relayURL == "" {
		am.relayURL = "https://waybar-calendar-relay.osc-fr1.scalingo.io"
	}

	// Skip credential loading when using relay service
	if !am.useRelay {
		// Determine credential path
		if opts.CredPath != "" {
			am.credPath = opts.CredPath
		} else {
			am.credPath = filepath.Join(cacheDir, "credentials.json")
		}

		// Try to load custom credentials first, then fall back to built-in
		if err := am.loadCustomCredentials(); err != nil {
			log.Printf("Custom credentials not available: %v", err)
			if err := am.useBuiltinCredentials(); err != nil {
				return nil, fmt.Errorf("failed to initialize OAuth2 credentials: %w", err)
			}
			log.Printf("Using OAuth2 credentials from environment variables")
		}
	}

	return am, nil
}

func (a *AuthManager) loadCustomCredentials() error {
	if _, err := os.Stat(a.credPath); os.IsNotExist(err) {
		return fmt.Errorf("credentials file not found")
	}

	b, err := os.ReadFile(a.credPath)
	if err != nil {
		return fmt.Errorf("unable to read client secret file: %w", err)
	}

	config, err := google.ConfigFromJSON(b, gcal.CalendarReadonlyScope)
	if err != nil {
		return fmt.Errorf("unable to parse client secret file to config: %w", err)
	}

	a.config = config
	a.useBuiltIn = false
	return nil
}

func (a *AuthManager) useBuiltinCredentials() error {
	// Try environment variables first
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	
	// Try built-in credentials if available (set by maintainer)
	if clientID == "" && defaultClientID != "" {
		clientID = defaultClientID
		clientSecret = defaultClientSecret
	}
	
	if clientID != "" && clientSecret != "" {
		a.config = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       []string{gcal.CalendarReadonlyScope},
			Endpoint:     google.Endpoint,
		}
		a.useBuiltIn = true
		return nil
	}
	
	// Provide helpful error message with instructions
	return fmt.Errorf(`OAuth2 credentials needed for simplified authentication.

To use device flow authentication (no manual setup required):
1. Get OAuth2 credentials from Google Cloud Console:
   - Go to: https://console.cloud.google.com/
   - Create a project or select existing one
   - Enable Google Calendar API
   - Create OAuth 2.0 Client ID for "Desktop application"
   - Download credentials or copy Client ID and Secret

2. Set environment variables:
   export GOOGLE_CLIENT_ID="your-client-id"
   export GOOGLE_CLIENT_SECRET="your-client-secret"

3. Or create credentials.json file at: %s

Alternative: Use '--local-server' flag with credentials.json for traditional flow`, a.credPath)
}

func (a *AuthManager) GetClient(ctx context.Context) (*http.Client, error) {
	// For relay service, we need a basic HTTP client without OAuth2 config
	if a.useRelay {
		// Try to load existing token
		token, err := a.loadToken()
		if err == nil && token.Valid() {
			// Create a basic HTTP client and add the token manually
			client := &http.Client{}
			// We'll handle token injection at request time
			return client, nil
		}

		// Get token from relay service
		newToken, err := a.getTokenFromRelay(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get token from relay: %w", err)
		}

		// Save token for future use
		if err := a.saveToken(newToken); err != nil {
			log.Printf("Warning: failed to save token: %v", err)
		}

		return &http.Client{}, nil
	}

	// Try to load existing token
	token, err := a.loadToken()
	if err == nil && token.Valid() {
		return a.config.Client(ctx, token), nil
	}

	// Determine which auth flow to use
	var newToken *oauth2.Token
	switch a.flow {
	case AuthFlowDeviceCode:
		newToken, err = a.getTokenFromDeviceFlow(ctx)
	case AuthFlowLocalServer:
		newToken, err = a.getTokenFromWeb(ctx)
	case AuthFlowRelay:
		newToken, err = a.getTokenFromRelay(ctx)
	case AuthFlowAuto:
		// Try device flow first if using built-in credentials, fallback to local server
		if a.useBuiltIn {
			newToken, err = a.getTokenFromDeviceFlow(ctx)
			if err != nil {
				log.Printf("Device flow failed, trying local server: %v", err)
				newToken, err = a.getTokenFromWeb(ctx)
			}
		} else {
			// If using custom credentials, prefer local server
			newToken, err = a.getTokenFromWeb(ctx)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("unable to get token: %w", err)
	}

	// Save token for future use
	if err := a.saveToken(newToken); err != nil {
		log.Printf("Warning: failed to save token: %v", err)
	}

	return a.config.Client(ctx, newToken), nil
}

func (a *AuthManager) getTokenFromWeb(ctx context.Context) (*oauth2.Token, error) {
	// Configure callback server
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	// Start local server to receive the callback
	server := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if code := r.URL.Query().Get("code"); code != "" {
				if _, err := fmt.Fprint(w, `
					<html>
					<body>
						<h1>Authorization successful!</h1>
						<p>You can now close this tab and return to the terminal.</p>
					</body>
					</html>
				`); err != nil {
					log.Printf("Warning: failed to write success response: %v", err)
				}
				codeCh <- code
			} else if errorParam := r.URL.Query().Get("error"); errorParam != "" {
				if _, err := fmt.Fprintf(w, `
					<html>
					<body>
						<h1>Authorization failed</h1>
						<p>Error: %s</p>
					</body>
					</html>
				`, errorParam); err != nil {
					log.Printf("Warning: failed to write error response: %v", err)
				}
				errCh <- fmt.Errorf("authorization failed: %s", errorParam)
			}
		}),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("failed to start callback server: %w", err)
		}
	}()

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Warning: failed to shutdown server gracefully: %v", err)
		}
	}()

	// Set redirect URL for local callback
	a.config.RedirectURL = "http://localhost:8080"

	authURL := a.config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Opening browser for authorization. If it doesn't open automatically, visit:\n%v\n", authURL)

	// Try to open browser
	if err := exec.Command("xdg-open", authURL).Run(); err != nil {
		log.Printf("Warning: failed to open browser automatically: %v", err)
		fmt.Println("Please open the URL manually in your browser.")
	}

	// Wait for callback or timeout
	select {
	case code := <-codeCh:
		token, err := a.config.Exchange(ctx, code)
		if err != nil {
			return nil, fmt.Errorf("unable to exchange code for token: %w", err)
		}
		return token, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("authorization timeout - no callback received within 5 minutes")
	}
}

func (a *AuthManager) loadToken() (*oauth2.Token, error) {
	f, err := os.Open(a.tokenPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("Warning: failed to close token file: %v", err)
		}
	}()

	token := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(token)
	return token, err
}

func (a *AuthManager) saveToken(token *oauth2.Token) error {
	f, err := os.OpenFile(a.tokenPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to cache oauth token: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("Warning: failed to close token file: %v", err)
		}
	}()

	return json.NewEncoder(f).Encode(token)
}

// Device Flow Implementation
func (a *AuthManager) getTokenFromDeviceFlow(ctx context.Context) (*oauth2.Token, error) {
	// Step 1: Request device and user codes
	deviceAuth, err := a.requestDeviceAuthorization(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to request device authorization: %w", err)
	}

	// Step 2: Display user instructions
	fmt.Printf("\n🔐 Google Calendar Authentication Required\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("1. Open this URL in your browser:\n")
	fmt.Printf("   %s\n\n", deviceAuth.VerificationURI)
	fmt.Printf("2. Enter this code when prompted:\n")
	fmt.Printf("   %s\n\n", deviceAuth.UserCode)
	fmt.Printf("Waiting for authorization... (expires in %d minutes)\n", deviceAuth.ExpiresIn/60)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// Step 3: Poll for authorization
	return a.pollForToken(ctx, deviceAuth)
}

func (a *AuthManager) requestDeviceAuthorization(ctx context.Context) (*DeviceAuthResponse, error) {
	deviceEndpoint := "https://oauth2.googleapis.com/device/code"
	
	data := fmt.Sprintf("client_id=%s&scope=%s", 
		a.config.ClientID, 
		"https://www.googleapis.com/auth/calendar.readonly")

	req, err := http.NewRequestWithContext(ctx, "POST", deviceEndpoint, 
		strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device authorization request failed: %s", resp.Status)
	}

	var deviceAuth DeviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceAuth); err != nil {
		return nil, err
	}

	return &deviceAuth, nil
}

func (a *AuthManager) pollForToken(ctx context.Context, deviceAuth *DeviceAuthResponse) (*oauth2.Token, error) {
	interval := time.Duration(deviceAuth.Interval) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second // Minimum polling interval
	}

	timeout := time.Duration(deviceAuth.ExpiresIn) * time.Second
	deadline := time.Now().Add(timeout)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("device code expired")
			}

			token, err := a.checkDeviceToken(ctx, deviceAuth.DeviceCode)
			if err != nil {
				// Continue polling on certain errors
				continue
			}

			fmt.Printf("✅ Authorization successful!\n\n")
			return token, nil
		}
	}
}

func (a *AuthManager) checkDeviceToken(ctx context.Context, deviceCode string) (*oauth2.Token, error) {
	tokenEndpoint := "https://oauth2.googleapis.com/token"
	
	data := fmt.Sprintf("client_id=%s&client_secret=%s&device_code=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code",
		a.config.ClientID, a.config.ClientSecret, deviceCode)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint,
		strings.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp DeviceTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.Error != "" {
		if tokenResp.Error == "authorization_pending" {
			return nil, fmt.Errorf("authorization pending")
		}
		if tokenResp.Error == "slow_down" {
			return nil, fmt.Errorf("slow down")
		}
		return nil, fmt.Errorf("token error: %s", tokenResp.Error)
	}

	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	
	return &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		Expiry:       expiry,
	}, nil
}

// Relay Service Implementation
func (a *AuthManager) getTokenFromRelay(ctx context.Context) (*oauth2.Token, error) {
	// 1. Initialize auth flow
	initURL := fmt.Sprintf("%s/auth/init", a.relayURL)
	resp, err := http.Get(initURL)
	if err != nil {
		return nil, fmt.Errorf("failed to init auth: %w", err)
	}
	defer resp.Body.Close()

	var initResp struct {
		AuthURL   string `json:"auth_url"`
		SessionID string `json:"session_id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return nil, err
	}

	// 2. Open browser
	fmt.Printf("🔐 Opening browser for authentication...\n")
	fmt.Printf("If browser doesn't open, visit: %s\n", initResp.AuthURL)

	if err := exec.Command("xdg-open", initResp.AuthURL).Run(); err != nil {
		log.Printf("Warning: failed to open browser: %v", err)
	}

	// 3. Poll for tokens
	pollURL := fmt.Sprintf("%s/auth/poll/%s", a.relayURL, initResp.SessionID)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeout := time.After(5 * time.Minute)

	for {
		select {
		case <-ticker.C:
			resp, err := http.Get(pollURL)
			if err != nil {
				continue
			}

			if resp.StatusCode == http.StatusAccepted {
				resp.Body.Close()
				continue // Still pending
			}

			if resp.StatusCode == http.StatusOK {
				var tokens struct {
					AccessToken  string `json:"access_token"`
					RefreshToken string `json:"refresh_token"`
					TokenType    string `json:"token_type"`
					ExpiresIn    int    `json:"expires_in"`
				}

				if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
					resp.Body.Close()
					return nil, err
				}
				resp.Body.Close()

				return &oauth2.Token{
					AccessToken:  tokens.AccessToken,
					RefreshToken: tokens.RefreshToken,
					TokenType:    "Bearer",
					Expiry:       time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
				}, nil
			}

			resp.Body.Close()

		case <-timeout:
			return nil, fmt.Errorf("authentication timeout")

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (a *AuthManager) RevokeToken(ctx context.Context) error {
	token, err := a.loadToken()
	if err != nil {
		return fmt.Errorf("no token to revoke: %w", err)
	}

	// Revoke the token
	if token.RefreshToken != "" {
		req, err := http.NewRequestWithContext(ctx, "POST", 
			fmt.Sprintf("https://oauth2.googleapis.com/revoke?token=%s", token.RefreshToken), nil)
		if err != nil {
			return fmt.Errorf("failed to create revoke request: %w", err)
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to revoke token: %w", err)
		}
		if err := resp.Body.Close(); err != nil {
			log.Printf("Warning: failed to close response body: %v", err)
		}
	}

	// Remove local token file
	if err := os.Remove(a.tokenPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove token file: %w", err)
	}

	return nil
}

func (a *AuthManager) HasValidToken() bool {
	token, err := a.loadToken()
	return err == nil && token.Valid()
}