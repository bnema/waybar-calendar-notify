package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pbkdf2"
)

// TokenEncryptor provides secure encryption and decryption for OAuth tokens
type TokenEncryptor struct {
	derivedKey []byte
}

// NewTokenEncryptor creates a new token encryptor with machine-specific key derivation
func NewTokenEncryptor(cacheDir string) (*TokenEncryptor, error) {
	salt, err := generateOrLoadSalt(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	machineID, err := getMachineID()
	if err != nil {
		return nil, fmt.Errorf("failed to get machine ID: %w", err)
	}

	userHome := os.Getenv("HOME")
	if userHome == "" {
		return nil, fmt.Errorf("HOME environment variable not set")
	}

	// Combine machine ID, user home, and salt for key material
	keyMaterial := fmt.Sprintf("%s:%s", machineID, userHome)
	derivedKey := pbkdf2.Key([]byte(keyMaterial), salt, 100000, 32, sha256.New)

	return &TokenEncryptor{derivedKey: derivedKey}, nil
}

// Encrypt encrypts plaintext data and returns base64-encoded ciphertext
func (te *TokenEncryptor) Encrypt(plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", fmt.Errorf("plaintext cannot be empty")
	}

	block, err := aes.NewCipher(te.derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext and returns plaintext
func (te *TokenEncryptor) Decrypt(ciphertext string) ([]byte, error) {
	if ciphertext == "" {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding: %w", err)
	}

	block, err := aes.NewCipher(te.derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// generateOrLoadSalt generates a new salt or loads existing one from cache directory
func generateOrLoadSalt(cacheDir string) ([]byte, error) {
	saltPath := filepath.Join(cacheDir, ".salt")

	// Try to load existing salt
	if salt, err := os.ReadFile(saltPath); err == nil && len(salt) == 32 {
		return salt, nil
	}

	// Generate new salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	// Save salt with restrictive permissions
	if err := os.WriteFile(saltPath, salt, 0600); err != nil {
		return nil, fmt.Errorf("failed to save salt: %w", err)
	}

	return salt, nil
}

// getMachineID reads the machine ID from /etc/machine-id or fallback sources
func getMachineID() (string, error) {
	// Try /etc/machine-id first (most Linux systems)
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		return string(data[:min(len(data), 32)]), nil
	}

	// Try /var/lib/dbus/machine-id (alternative location)
	if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		return string(data[:min(len(data), 32)]), nil
	}

	// Fallback: use hostname + user ID
	hostname, _ := os.Hostname()
	uid := os.Getuid()
	fallback := fmt.Sprintf("%s-%d", hostname, uid)
	
	if len(fallback) < 8 {
		return "fallback-machine-id", nil
	}

	return fallback, nil
}

// min returns the minimum of two integers (Go 1.21+ has this built-in)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}