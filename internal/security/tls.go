package security

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"

	"net/url"
	"strings"
	"time"

	"github.com/bnema/waybar-calendar-notify/internal/logger"
)

// SecureHTTPClient provides an HTTP client with enhanced security features
type SecureHTTPClient struct {
	client      *http.Client
	pinnedCerts map[string]string // domain -> sha256 fingerprint
	baseURL     string
}

// NewSecureHTTPClient creates a new secure HTTP client with certificate pinning
func NewSecureHTTPClient(baseURL string) (*SecureHTTPClient, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Certificate fingerprints for known services
	// NOTE: These should be updated with actual certificate fingerprints
	pinnedCerts := map[string]string{
		"oauth2.googleapis.com": "", // Google OAuth2 - uses their CA
		"localhost":             "", // Development - no pinning
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   false,
	}

	// Enable certificate pinning for production hosts
	hostname := parsedURL.Hostname()
	if expectedFingerprint, exists := pinnedCerts[hostname]; exists && expectedFingerprint != "" {
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyCertificatePin(rawCerts, expectedFingerprint)
		}
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects to prevent redirect attacks
			return http.ErrUseLastResponse
		},
	}

	return &SecureHTTPClient{
		client:      client,
		pinnedCerts: pinnedCerts,
		baseURL:     baseURL,
	}, nil
}

// Do executes an HTTP request with security headers and validation
func (sc *SecureHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Add security headers
	req.Header.Set("User-Agent", "waybar-calendar-notify/1.0")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")

	// Validate request URL is for our relay
	if !sc.isAllowedURL(req.URL.String()) {
		return nil, fmt.Errorf("request URL not allowed: %s", req.URL.String())
	}

	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	// Validate response headers
	if err := sc.validateResponse(resp); err != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return nil, fmt.Errorf("validation failed: %w (and failed to close response body: %v)", err, closeErr)
		}
		return nil, err
	}

	return resp, nil
}

// Get performs a GET request with security validation
func (sc *SecureHTTPClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	return sc.Do(req)
}

// GetWithContext performs a GET request with context
func (sc *SecureHTTPClient) GetWithContext(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	return sc.Do(req)
}

// PostWithContext performs a POST request with context
func (sc *SecureHTTPClient) PostWithContext(ctx context.Context, url, contentType string, body interface{}) (*http.Response, error) {
	var bodyReader *strings.Reader
	if body != nil {
		if str, ok := body.(string); ok {
			bodyReader = strings.NewReader(str)
		} else {
			return nil, fmt.Errorf("unsupported body type")
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	return sc.Do(req)
}

// Close closes idle connections in the underlying HTTP client
func (sc *SecureHTTPClient) Close() {
	if sc.client != nil {
		if transport, ok := sc.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
}

// isAllowedURL checks if the URL is allowed for requests
func (sc *SecureHTTPClient) isAllowedURL(reqURL string) bool {
	parsedReqURL, err := url.Parse(reqURL)
	if err != nil {
		return false
	}

	parsedBaseURL, err := url.Parse(sc.baseURL)
	if err != nil {
		return false
	}

	// Must be same scheme and host as configured base URL
	return parsedReqURL.Scheme == parsedBaseURL.Scheme &&
		parsedReqURL.Host == parsedBaseURL.Host
}

// validateResponse performs basic security validation on HTTP responses
func (sc *SecureHTTPClient) validateResponse(resp *http.Response) error {
	// Check Content-Type for JSON endpoints
	contentType := resp.Header.Get("Content-Type")
	if resp.StatusCode == http.StatusOK && !strings.HasPrefix(contentType, "application/json") {
		return fmt.Errorf("unexpected content type: %s", contentType)
	}

	// Check Content-Length to prevent excessive memory usage
	if resp.ContentLength > 1024*1024 { // 1MB limit
		return fmt.Errorf("response too large: %d bytes", resp.ContentLength)
	}

	// Note: Some security headers like X-Content-Type-Options are optional
	// and their absence doesn't constitute a security failure for this use case

	return nil
}

// verifyCertificatePin verifies that at least one certificate matches the expected fingerprint
func verifyCertificatePin(rawCerts [][]byte, expectedFingerprint string) error {
	if expectedFingerprint == "" {
		return nil // No pinning configured
	}

	for _, rawCert := range rawCerts {
		hash := sha256.Sum256(rawCert)
		fingerprint := "sha256:" + hex.EncodeToString(hash[:])

		if fingerprint == expectedFingerprint {
			return nil // Match found
		}
	}

	return fmt.Errorf("certificate pinning failed: no matching certificate found")
}

// GetCertificateFingerprint retrieves the SHA256 fingerprint of a server's certificate
// This is a utility function for determining the correct fingerprint for pinning
func GetCertificateFingerprint(hostname string) (string, error) {
	conn, err := tls.Dial("tcp", hostname+":443", &tls.Config{
		InsecureSkipVerify: true, // We're just getting the fingerprint
	})
	if err != nil {
		return "", fmt.Errorf("failed to connect: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			logger.Error("Error closing TLS connection", "error", closeErr)
		}
	}()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("no certificates found")
	}

	hash := sha256.Sum256(certs[0].Raw)
	fingerprint := "sha256:" + hex.EncodeToString(hash[:])

	return fingerprint, nil
}
