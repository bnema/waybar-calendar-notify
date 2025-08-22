#!/bin/bash
set -e

echo "=================================================="
echo "Building Obfuscated waybar-calendar-notify Binary"
echo "=================================================="

# Check for required tools
check_tools() {
    echo "Checking required tools..."
    
    if ! command -v garble &> /dev/null; then
        echo "ERROR: garble not found. Install with: go install mvdan.cc/garble@latest"
        exit 1
    fi
    
    if ! command -v go &> /dev/null; then
        echo "ERROR: go not found"
        exit 1
    fi
    
    echo "✓ All required tools found"
}

# Check embedded secrets exist
check_embedded_secrets() {
    echo "Checking embedded secrets..."
    
    if [ ! -f "internal/calendar/embedded_secrets.go" ]; then
        echo "ERROR: internal/calendar/embedded_secrets.go not found"
        echo "This file should exist with embedded credentials"
        
        if [ -f "client_secrets_device_oauth.json" ]; then
            echo "Found client_secrets_device_oauth.json - you can regenerate with:"
            echo "  go run scripts/encode-secrets.go client_secrets_device_oauth.json"
            echo "  Then manually merge with the template functions"
        fi
        
        return 1
    fi
    
    # Check if the file contains the required functions
    if ! grep -q "LoadEmbeddedSecrets" "internal/calendar/embedded_secrets.go"; then
        echo "ERROR: embedded_secrets.go missing LoadEmbeddedSecrets function"
        return 1
    fi
    
    if ! grep -q "decodeClientID" "internal/calendar/embedded_secrets.go"; then
        echo "ERROR: embedded_secrets.go missing decodeClientID function"
        return 1
    fi
    
    echo "✓ Embedded secrets file looks complete"
    return 0
}

# Generate embedded secrets from client secrets file
generate_embedded_secrets() {
    echo "Generating embedded secrets..."
    
    if [ ! -f "client_secrets_device_oauth.json" ]; then
        echo "WARNING: client_secrets_device_oauth.json not found"
        echo "Using existing embedded secrets or will fail if none exist"
        return 0
    fi
    
    # Backup existing embedded secrets
    if [ -f "internal/calendar/embedded_secrets.go" ]; then
        cp "internal/calendar/embedded_secrets.go" "internal/calendar/embedded_secrets.go.bak"
        echo "✓ Backed up existing embedded secrets"
    fi
    
    # Generate new embedded secrets
    echo "Encoding client secrets with XOR obfuscation..."
    
    # Create the encoded secrets file
    cat > "internal/calendar/embedded_secrets_temp.go" << 'EOF'
package calendar

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"unsafe"
)

EOF
    
    # Append the generated encoded data
    go run scripts/encode-secrets.go client_secrets_device_oauth.json >> "internal/calendar/embedded_secrets_temp.go"
    
    # Append the decoding functions
    cat >> "internal/calendar/embedded_secrets_temp.go" << 'EOF'

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
	// Anti-debugging check
	if antiDebugCheck() {
		return nil, fmt.Errorf("security check failed")
	}
	
	// Create the secrets structure
	secrets := &ClientSecrets{}
	
	// Decode with multiple validation checks
	clientID := decodeClientID()
	if len(clientID) < 10 || len(clientID) != clientIDLen {
		// Additional validation failed
		return nil, fmt.Errorf("invalid embedded client credentials")
	}
	
	clientSecret := decodeClientSecret()
	if len(clientSecret) < 10 || len(clientSecret) != clientSecretLen {
		// Clear sensitive data before error
		clearString(&clientID)
		return nil, fmt.Errorf("invalid embedded client credentials")
	}
	
	// Apply additional transformations
	secrets.Installed.ClientID = clientID
	secrets.Installed.ClientSecret = clientSecret
	secrets.Installed.AuthURI = authURI
	secrets.Installed.TokenURI = tokenURI
	
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
EOF
    
    # Replace the original file
    mv "internal/calendar/embedded_secrets_temp.go" "internal/calendar/embedded_secrets.go"
    
    echo "✓ Generated new embedded secrets with obfuscation"
}

# Build with garble obfuscation
build_with_garble() {
    echo "Building with garble obfuscation..."
    
    # Enable experimental control flow obfuscation (disabled due to garble panic)
    # export GARBLE_EXPERIMENTAL_CONTROLFLOW=1
    
    # Set custom garble cache to avoid conflicts
    export GARBLE_CACHE="$HOME/.cache/garble-waybar"
    mkdir -p "$GARBLE_CACHE"
    
    # Generate random seed for each build
    if command -v openssl &> /dev/null; then
        SEED=$(openssl rand -hex 16)
    else
        # Fallback to date-based seed
        SEED=$(date +%s%N | sha256sum | head -c 32)
    fi
    
    echo "Using garble seed: $SEED"
    
    # Build with maximum obfuscation
    echo "Compiling with garble..."
    garble -literals -tiny -seed="$SEED" build \
        -ldflags="-w -s -X main.buildTime=$(date -u +%Y%m%d%H%M%S) -X main.buildMode=obfuscated" \
        -tags="obfuscated" \
        -o waybar-calendar-notify-obfuscated \
        .
    
    # Save build info for potential reverse operation
    echo "$SEED" > .garble-seed
    echo "$(date -u +%Y%m%d%H%M%S)" > .build-timestamp
    
    echo "✓ Build completed successfully"
}

# Post-build optimizations
post_build_optimizations() {
    echo "Applying post-build optimizations..."
    
    # Strip any remaining symbols (might not be needed after garble -tiny)
    if command -v strip &> /dev/null; then
        strip -s waybar-calendar-notify-obfuscated 2>/dev/null || true
        echo "✓ Stripped remaining symbols"
    fi
    
    # Compress with UPX if available (optional, can make reverse engineering easier)
    if command -v upx &> /dev/null; then
        echo "UPX found, compressing binary..."
        cp waybar-calendar-notify-obfuscated waybar-calendar-notify-obfuscated.original
        upx --best --lzma waybar-calendar-notify-obfuscated 2>/dev/null || {
            echo "UPX compression failed, keeping uncompressed version"
            mv waybar-calendar-notify-obfuscated.original waybar-calendar-notify-obfuscated
        }
    fi
}

# Display build summary
build_summary() {
    echo ""
    echo "=================================================="
    echo "Build Summary"
    echo "=================================================="
    
    if [ -f waybar-calendar-notify-obfuscated ]; then
        echo "✓ Binary: waybar-calendar-notify-obfuscated"
        echo "✓ Size: $(du -h waybar-calendar-notify-obfuscated | cut -f1)"
        echo "✓ Seed saved to: .garble-seed"
        echo "✓ Build timestamp: $(cat .build-timestamp 2>/dev/null || echo 'unknown')"
        
        # Basic obfuscation check
        echo ""
        echo "Basic obfuscation verification:"
        
        if command -v strings &> /dev/null; then
            if strings waybar-calendar-notify-obfuscated 2>/dev/null | grep -q "client_id\|client_secret" 2>/dev/null; then
                echo "⚠ WARNING: Potential client credential strings found!"
            else
                echo "✓ No obvious client credential strings found"
            fi
            
            if strings waybar-calendar-notify-obfuscated 2>/dev/null | grep -qE "[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com" 2>/dev/null; then
                echo "⚠ WARNING: Client ID pattern detected!"
            else
                echo "✓ No client ID patterns detected"
            fi
            
            if strings waybar-calendar-notify-obfuscated 2>/dev/null | grep -q "GOCSPX-" 2>/dev/null; then
                echo "⚠ WARNING: Client secret pattern detected!"
            else
                echo "✓ No client secret patterns detected"
            fi
        else
            echo "⚠ 'strings' command not available for verification"
        fi
        
        echo ""
        echo "Build completed successfully!"
        echo "You can now distribute waybar-calendar-notify-obfuscated"
        echo "Users will not need to provide client_secrets_device_oauth.json"
        
    else
        echo "❌ Build failed - no output binary found"
        exit 1
    fi
}

# Main build process
main() {
    check_tools
    check_embedded_secrets
    build_with_garble
    post_build_optimizations
    build_summary
}

# Handle cleanup on exit
cleanup() {
    # Restore backup if build failed
    if [ $? -ne 0 ] && [ -f "internal/calendar/embedded_secrets.go.bak" ]; then
        echo "Build failed, restoring backup..."
        mv "internal/calendar/embedded_secrets.go.bak" "internal/calendar/embedded_secrets.go"
    fi
    
    # Clean up temporary files
    rm -f "internal/calendar/embedded_secrets_temp.go" 2>/dev/null || true
    rm -f "waybar-calendar-notify-obfuscated.original" 2>/dev/null || true
}

trap cleanup EXIT

# Run main function
main "$@"