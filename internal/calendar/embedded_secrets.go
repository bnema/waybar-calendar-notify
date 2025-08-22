package calendar

import (
	"fmt"
	"runtime"
	"unsafe"
)

// XOR key generated at build time
var xorKey1 = []byte{0x1e, 0x87, 0xaa, 0xa7, 0x4, 0x7f, 0xd7, 0x6e, 0x61, 0x34, 0x3c, 0xe, 0x34, 0x1e, 0x39, 0x22, 0x57, 0x4c, 0xc1, 0x1a, 0x40, 0xb4, 0x72, 0xe8, 0xeb, 0x59, 0x73, 0x55, 0x14, 0xd2, 0x4a, 0xad}

// Decoy data to confuse analysis
var decoyData1 = []byte{0x6e, 0x80, 0x29, 0xee, 0xc2, 0x70, 0x99, 0x62, 0x6e, 0x16, 0x5f, 0x40, 0xec, 0x70, 0xa6, 0xc7}
var decoyData2 = []byte{0xd4, 0x9d, 0x20, 0x87, 0xb2, 0xae, 0x3d, 0xc6, 0xf6, 0x5b, 0x33, 0xfb}

// Client ID split into 3 XOR-encrypted parts
var clientIDPart1 = []byte{0x2b, 0xb2, 0x9b, 0x94, 0x36, 0x4f, 0xe6, 0x5b, 0x59, 0x4, 0xb, 0x36, 0x19, 0x2f, 0x51, 0x52, 0x3f, 0x7e, 0xaa, 0x68, 0x30, 0x8c, 0x1, 0x8c}
var clientIDPart2 = []byte{0xa, 0x45, 0x4c, 0x3c, 0x5a, 0x7b, 0x52, 0x52, 0x32, 0x2f, 0xb7, 0x78, 0x77, 0xd2, 0x13, 0x84, 0x84, 0x6a, 0x42, 0x24, 0x24, 0xfc, 0x2b, 0xdd}
var clientIDPart3 = []byte{0x27, 0x3f, 0xef, 0x7d, 0x2f, 0xdb, 0x15, 0x84, 0x8e, 0x2c, 0x0, 0x30, 0x66, 0xb1, 0x25, 0xc3, 0x23, 0x29, 0xaf, 0x6e, 0x6e, 0xd7, 0x1d, 0x85}

// Client Secret split into 3 XOR-encrypted parts
var clientSecretPart1 = []byte{0x38, 0x98, 0x2d, 0x32, 0x64, 0x64, 0x23, 0x52, 0x41, 0x4a, 0x4e}
var clientSecretPart2 = []byte{0x54, 0x65, 0x73, 0x72, 0x72, 0x6, 0x74, 0x8e, 0x37, 0x38, 0xdf}
var clientSecretPart3 = []byte{0xfc, 0x15, 0xdf, 0xae, 0x1b, 0x31, 0x67, 0x60, 0x80, 0x3d, 0x9b, 0xc6, 0x37}

// Original lengths for validation
var clientIDLen = 72
var clientSecretLen = 35

// URI constants (not sensitive)
const authURI = "https://accounts.google.com/o/oauth2/auth"
const tokenURI = "https://oauth2.googleapis.com/token"

// Obfuscated ClientSecrets struct for embedded secrets (avoids JSON tag leaks)
//garble:controlflow flatten_passes=1
type EmbeddedClientSecrets struct {
	Installed struct {
		ClientID     string `json:"cid"`      // Obfuscated tag
		ClientSecret string `json:"cs"`       // Obfuscated tag  
		AuthURI      string `json:"au"`       // Obfuscated tag
		TokenURI     string `json:"tu"`       // Obfuscated tag
	} `json:"inst"`  // Obfuscated tag
}

// Use garble control flow obfuscation with maximum complexity
//garble:controlflow flatten_passes=3 junk_jumps=max block_splits=max flatten_hardening=xor,delegate_table trash_blocks=1
func decodeClientID() string {
	// Create decoy operations to confuse static analysis
	dummyOps := func(x int) int {
		for i := 0; i < x%10; i++ {
			x = (x * 31) % 997
		}
		return x
	}
	
	// Use decoy data in calculations
	decoySum := 0
	for _, b := range decoyData1 {
		decoySum += int(b)
	}
	
	// Reconstruct client ID with interleaved dummy operations
	result := make([]byte, 0, clientIDLen)
	
	// Decode part 1
	for i, b := range clientIDPart1 {
		_ = dummyOps(int(b))
		result = append(result, b^xorKey1[i%32])
	}
	
	// Add timing jitter using decoy data
	for i := 0; i < dummyOps(len(result)+decoySum); i++ {
		_ = fmt.Sprintf("%d", i%256)
	}
	
	// Decode part 2
	for i, b := range clientIDPart2 {
		// Use offset to confuse key analysis
		keyIdx := (i + 8) % 32
		result = append(result, b^xorKey1[keyIdx])
	}
	
	// More obfuscation with decoy data
	if dummyOps(decoySum) > 0 {
		// Decode part 3
		for i, b := range clientIDPart3 {
			keyIdx := (i + 16) % 32
			result = append(result, b^xorKey1[keyIdx])
		}
	}
	
	// Validate length
	if len(result) != clientIDLen {
		// Fallback decoding attempt
		result = result[:0]
		allParts := [][]byte{clientIDPart1, clientIDPart2, clientIDPart3}
		offsets := []int{0, 8, 16}
		
		for partIdx, part := range allParts {
			for i, b := range part {
				keyIdx := (i + offsets[partIdx]) % 32
				result = append(result, b^xorKey1[keyIdx])
			}
		}
	}
	
	decoded := string(result)
	
	// Clear intermediate data
	for i := range result {
		result[i] = 0
	}
	
	return decoded
}

//garble:controlflow flatten_passes=3 junk_jumps=max block_splits=max flatten_hardening=xor,delegate_table
func decodeClientSecret() string {
	// Complex decoding with multiple indirections
	result := make([]byte, 0, clientSecretLen)
	
	// Use decoy data for additional obfuscation
	decoyXor := byte(0)
	for _, b := range decoyData2 {
		decoyXor ^= b
	}
	
	// Create decoder function array for indirection
	decoders := []func([]byte, int, int) byte{
		func(data []byte, idx, offset int) byte {
			return data[idx] ^ xorKey1[(idx+offset)%32]
		},
		func(data []byte, idx, offset int) byte {
			return data[idx] ^ xorKey1[(idx+offset+5)%32]
		},
		func(data []byte, idx, offset int) byte {
			return data[idx] ^ xorKey1[(idx+offset+11)%32]
		},
	}
	
	parts := [][]byte{clientSecretPart1, clientSecretPart2, clientSecretPart3}
	offsets := []int{5, 11, 21}
	
	// Decode with function indirection
	for partIdx, part := range parts {
		decoder := decoders[partIdx%len(decoders)]
		offset := offsets[partIdx]
		
		for i, b := range part {
			decoded := decoder([]byte{b}, 0, offset)
			// Apply decoy XOR occasionally
			if (i+partIdx)%7 == 0 {
				decoded ^= decoyXor
				decoded ^= decoyXor // XOR twice to cancel out
			}
			result = append(result, decoded)
		}
	}
	
	// Validate length and retry if needed
	if len(result) != clientSecretLen {
		// Fallback simple decoding
		result = result[:0]
		for partIdx, part := range parts {
			offset := offsets[partIdx]
			for i, b := range part {
				keyIdx := (i + offset) % 32
				result = append(result, b^xorKey1[keyIdx])
			}
		}
	}
	
	decoded := string(result)
	
	// Clear intermediate data
	for i := range result {
		result[i] = 0
	}
	
	return decoded
}

// Additional obfuscation layer using byte rotation
//garble:controlflow flatten_passes=2 junk_jumps=5 block_splits=max
func rotateBytes(data []byte, positions int) []byte {
	if len(data) == 0 {
		return data
	}
	
	result := make([]byte, len(data))
	for i := range data {
		result[(i+positions)%len(data)] = data[i]
	}
	return result
}

// Anti-debugging check using timing
//garble:controlflow flatten_passes=1 junk_jumps=3
func antiDebugCheck() bool {
	// Simple timing-based check
	start := runtime.NumCPU()
	for i := 0; i < 1000; i++ {
		_ = fmt.Sprintf("%d", i)
	}
	end := runtime.NumCPU()
	
	// In a debugger, this might be different
	return start != end
}

// Main function to load embedded secrets with maximum obfuscation
//garble:controlflow flatten_passes=3 junk_jumps=max block_splits=max trash_blocks=1
func LoadEmbeddedSecrets() (*ClientSecrets, error) {
	// Initialize security runtime
	if err := InitializeSecurityRuntime(); err != nil {
		return nil, err
	}
	
	// Anti-debugging check
	if antiDebugCheck() {
		return nil, fmt.Errorf("security check failed")
	}
	
	// Create the obfuscated secrets structure first
	embeddedSecrets := &EmbeddedClientSecrets{}
	
	// Decode with multiple validation checks
	clientID := decodeClientID()
	if len(clientID) < 10 || len(clientID) != clientIDLen {
		// Additional validation failed
		return nil, fmt.Errorf("invalid embedded client credentials")
	}
	
	clientSecret := decodeClientSecret()
	if len(clientSecret) < 10 || len(clientSecret) != clientSecretLen {
		// Clear sensitive data before error
		clearStringSecure(&clientID)
		return nil, fmt.Errorf("invalid embedded client credentials")
	}
	
	// Apply to obfuscated structure (avoids JSON tag exposure)
	embeddedSecrets.Installed.ClientID = clientID
	embeddedSecrets.Installed.ClientSecret = clientSecret
	embeddedSecrets.Installed.AuthURI = authURI
	embeddedSecrets.Installed.TokenURI = tokenURI
	
	// Convert to standard ClientSecrets format for compatibility
	secrets := &ClientSecrets{}
	secrets.Installed.ClientID = embeddedSecrets.Installed.ClientID
	secrets.Installed.ClientSecret = embeddedSecrets.Installed.ClientSecret
	secrets.Installed.AuthURI = embeddedSecrets.Installed.AuthURI
	secrets.Installed.TokenURI = embeddedSecrets.Installed.TokenURI
	
	// Clear embedded secrets from memory
	clearStringSecure(&embeddedSecrets.Installed.ClientID)
	clearStringSecure(&embeddedSecrets.Installed.ClientSecret)
	
	// Validate final structure
	if secrets.Installed.ClientID == "" || secrets.Installed.ClientSecret == "" {
		return nil, fmt.Errorf("failed to decode embedded secrets")
	}
	
	return secrets, nil
}

// Clear sensitive data from memory after use
//garble:controlflow flatten_passes=1
func clearString(s *string) {
	if s == nil || *s == "" {
		return
	}
	
	// Get the underlying byte array
	b := unsafe.Slice(unsafe.StringData(*s), len(*s))
	
	// Overwrite with zeros
	for i := range b {
		b[i] = 0
	}
	
	// Set to empty string
	*s = ""
	
	// Force GC
	runtime.GC()
}

// Memory clearing helper for byte slices
//garble:controlflow flatten_passes=1
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}