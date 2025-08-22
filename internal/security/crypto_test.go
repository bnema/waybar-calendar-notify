package security

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTokenEncryption(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	encryptor, err := NewTokenEncryptor(tempDir)
	if err != nil {
		t.Fatalf("Failed to create TokenEncryptor: %v", err)
	}

	testToken := []byte(`{"access_token":"ya29.test","refresh_token":"1//test","token_type":"Bearer","expiry":"2024-01-01T00:00:00Z"}`)

	// Test encryption
	encrypted, err := encryptor.Encrypt(testToken)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify encrypted data is not the same as plaintext
	if bytes.Equal([]byte(encrypted), testToken) {
		t.Error("Encryption failed: ciphertext equals plaintext")
	}

	// Verify encrypted data is not empty
	if len(encrypted) == 0 {
		t.Error("Encryption produced empty result")
	}

	// Test decryption
	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify roundtrip works correctly
	if !bytes.Equal(decrypted, testToken) {
		t.Errorf("Decryption failed: expected %s, got %s", string(testToken), string(decrypted))
	}
}

func TestTokenEncryptionEmptyInput(t *testing.T) {
	tempDir := t.TempDir()
	encryptor, err := NewTokenEncryptor(tempDir)
	if err != nil {
		t.Fatalf("Failed to create TokenEncryptor: %v", err)
	}

	// Test encryption with empty input
	_, err = encryptor.Encrypt([]byte{})
	if err == nil {
		t.Error("Expected error for empty input, got nil")
	}

	// Test decryption with empty input
	_, err = encryptor.Decrypt("")
	if err == nil {
		t.Error("Expected error for empty input, got nil")
	}
}

func TestTokenEncryptionInvalidInput(t *testing.T) {
	tempDir := t.TempDir()
	encryptor, err := NewTokenEncryptor(tempDir)
	if err != nil {
		t.Fatalf("Failed to create TokenEncryptor: %v", err)
	}

	// Test decryption with invalid base64
	_, err = encryptor.Decrypt("invalid_base64!")
	if err == nil {
		t.Error("Expected error for invalid base64, got nil")
	}

	// Test decryption with short ciphertext
	_, err = encryptor.Decrypt("dGVzdA==") // "test" in base64, too short for nonce
	if err == nil {
		t.Error("Expected error for short ciphertext, got nil")
	}
}

func TestTokenEncryptionConsistency(t *testing.T) {
	tempDir := t.TempDir()

	// Create two encryptors with the same cache directory
	encryptor1, err := NewTokenEncryptor(tempDir)
	if err != nil {
		t.Fatalf("Failed to create first TokenEncryptor: %v", err)
	}

	encryptor2, err := NewTokenEncryptor(tempDir)
	if err != nil {
		t.Fatalf("Failed to create second TokenEncryptor: %v", err)
	}

	testToken := []byte(`{"access_token":"test_token","refresh_token":"test_refresh"}`)

	// Encrypt with first encryptor
	encrypted, err := encryptor1.Encrypt(testToken)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt with second encryptor (should work since they share the same salt)
	decrypted, err := encryptor2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Cross-encryptor decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, testToken) {
		t.Error("Cross-encryptor decryption produced different result")
	}
}

func TestSaltGeneration(t *testing.T) {
	tempDir := t.TempDir()

	// Generate salt
	salt1, err := generateOrLoadSalt(tempDir)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	if len(salt1) != 32 {
		t.Errorf("Expected salt length 32, got %d", len(salt1))
	}

	// Load existing salt
	salt2, err := generateOrLoadSalt(tempDir)
	if err != nil {
		t.Fatalf("Failed to load salt: %v", err)
	}

	if !bytes.Equal(salt1, salt2) {
		t.Error("Loaded salt differs from generated salt")
	}

	// Verify salt file exists with correct permissions
	saltPath := filepath.Join(tempDir, ".salt")
	info, err := os.Stat(saltPath)
	if err != nil {
		t.Fatalf("Salt file does not exist: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("Expected salt file permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestMachineIDFallback(t *testing.T) {
	// Test that getMachineID returns something even if system files don't exist
	machineID, err := getMachineID()
	if err != nil {
		t.Fatalf("getMachineID failed: %v", err)
	}

	if len(machineID) < 8 {
		t.Errorf("Machine ID too short: %s", machineID)
	}

	// Test consistency
	machineID2, err := getMachineID()
	if err != nil {
		t.Fatalf("getMachineID failed on second call: %v", err)
	}

	if machineID != machineID2 {
		t.Error("Machine ID not consistent between calls")
	}
}

func TestEncryptionUniqueness(t *testing.T) {
	tempDir := t.TempDir()
	encryptor, err := NewTokenEncryptor(tempDir)
	if err != nil {
		t.Fatalf("Failed to create TokenEncryptor: %v", err)
	}

	testToken := []byte(`{"access_token":"test_token"}`)

	// Encrypt the same data multiple times
	encrypted1, err := encryptor.Encrypt(testToken)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := encryptor.Encrypt(testToken)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Ciphertexts should be different due to random nonces
	if encrypted1 == encrypted2 {
		t.Error("Two encryptions of the same plaintext produced identical ciphertext")
	}

	// But both should decrypt to the same plaintext
	decrypted1, err := encryptor.Decrypt(encrypted1)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	decrypted2, err := encryptor.Decrypt(encrypted2)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted1, testToken) || !bytes.Equal(decrypted2, testToken) {
		t.Error("Decrypted data doesn't match original")
	}
}

// Benchmark tests
func BenchmarkEncryption(b *testing.B) {
	tempDir := b.TempDir()
	encryptor, err := NewTokenEncryptor(tempDir)
	if err != nil {
		b.Fatalf("Failed to create TokenEncryptor: %v", err)
	}

	testToken := []byte(`{"access_token":"ya29.a0AfH6SMC...","refresh_token":"1//04...","token_type":"Bearer","expiry":"2024-01-01T00:00:00Z"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.Encrypt(testToken)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkDecryption(b *testing.B) {
	tempDir := b.TempDir()
	encryptor, err := NewTokenEncryptor(tempDir)
	if err != nil {
		b.Fatalf("Failed to create TokenEncryptor: %v", err)
	}

	testToken := []byte(`{"access_token":"ya29.a0AfH6SMC...","refresh_token":"1//04...","token_type":"Bearer","expiry":"2024-01-01T00:00:00Z"}`)
	encrypted, err := encryptor.Encrypt(testToken)
	if err != nil {
		b.Fatalf("Failed to encrypt test data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.Decrypt(encrypted)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}
